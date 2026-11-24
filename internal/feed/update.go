package feed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/database"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// ErrOffline 表示离线模式下拒绝任何网络更新。
var ErrOffline = errors.New("feed: 离线模式，不执行网络更新")

// Verifier 校验分离签名。
//
// 只有 A 级源（Red Hat / SUSE）需要实现；B 级源没有签名可验，
// 记录为 not-applicable，不能因为「没有签名」就说「已验证」。
type Verifier interface {
	VerifyDetached(ctx context.Context, src Source, data, sig []byte) (domain.SignatureStatus, string, error)
}

// Updater 编排一次完整的情报更新：
// 条件请求 → 校验 → 不可变落盘 → 解析 → 单事务写库。
//
// 任一步失败都不破坏上一份有效情报（见 docs/phase3.0-design.md §3.2 失败语义）。
type Updater struct {
	Store    *Store
	Fetcher  *Fetcher
	DB       *database.DB
	Verifier Verifier
	Offline  bool
	Now      func() time.Time
	// Logf 为 nil 时静默；CLI 注入后输出进度。
	Logf func(format string, args ...any)
}

func (u *Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Updater) logf(format string, args ...any) {
	if u.Logf != nil {
		u.Logf(format, args...)
	}
}

// UpdateResult 描述一次更新的结果。
type UpdateResult struct {
	SourceID   domain.SourceID
	Release    string
	Skipped    bool
	SkipReason string
	Artifact   Artifact
	SnapshotID string

	Advisories  int
	Fixes       int
	NotAffected int
	BadRecords  int
	Warnings    []string
	Elapsed     time.Duration
}

// UpdateSource 更新单个源。
//
// release 只对按 release 分文件的源有意义（Ubuntu OVAL / Alpine secdb）；
// 其余源传空串。
func (u *Updater) UpdateSource(ctx context.Context, src Source, release string) (*UpdateResult, error) {
	start := u.now()
	if src.Disabled {
		return nil, fmt.Errorf("feed: 情报源 %s 本期未接入: %s", src.ID, src.DisabledReason)
	}
	if u.Offline {
		return nil, fmt.Errorf("%w: %s", ErrOffline, src.ID)
	}
	if err := src.Validate(); err != nil {
		return nil, err
	}
	// A 级源的信任等级建立在密码学签名上。没有验签器就写库，
	// 等于把「HTTPS 拿到了文件」冒充成「官方签发了文件」，必须拒绝。
	// 这条守卫放在解析器检查之前：信任门槛是无论如何都不能被绕过的前提，
	// 而「缺解析器」只是功能尚未完成。
	if src.TrustLevel == domain.TrustLevelA && u.Verifier == nil {
		return nil, fmt.Errorf("feed: %s 是 A 级签名源，但未配置签名校验器，拒绝写入未经签名的数据", src.ID)
	}
	parser, reason := ParserFor(src.ID)
	if parser == nil {
		return nil, fmt.Errorf("feed: 无法更新 %s：%s", src.ID, reason)
	}

	lock, err := u.Store.acquireLock(string(src.ID))
	if err != nil {
		return nil, err
	}
	defer lock.Release()

	prev, hasPrev, err := u.DB.LastArtifact(ctx, src.ID)
	if err != nil {
		return nil, err
	}

	// 按 release 分文件的源，一次更新可能对应多份文件（Alpine 的 main+community）。
	files, err := u.fetchSourceFiles(ctx, src, release, prev, hasPrev)
	if err != nil {
		_ = u.DB.MarkSourceError(ctx, src.ID, err.Error())
		return nil, err
	}
	if files == nil {
		// 条件请求命中 304，或内容与上次完全一致。
		return &UpdateResult{
			SourceID: src.ID, Release: release, Skipped: true,
			SkipReason: "内容未变化（304 或哈希一致）",
			Elapsed:    u.now().Sub(start),
		}, nil
	}

	bodies := make(map[string][]byte, len(files))
	for k, f := range files {
		bodies[k] = f.Body
	}

	// 内容哈希用于判断快照是否重复；多文件源取各文件哈希的联合摘要。
	// 注意：这里算的是「发布物原始字节」的哈希，压缩包和解压后是两回事。
	contentHash := combinedHash(bodies)

	// 压缩源（Ubuntu OVAL）只把解压结果交给解析器；
	// Artifact 仍然存原始压缩字节，那才是发布方发布的文件。
	parseBodies := bodies
	if src.Archive {
		parseBodies = make(map[string][]byte, len(bodies))
		for k, b := range bodies {
			d, derr := Decompress(b, MaxExpandedBytes)
			if derr != nil {
				_ = u.DB.MarkSourceError(ctx, src.ID, derr.Error())
				return nil, fmt.Errorf("feed: 解压 %s 的 %q 失败: %w", src.ID, k, derr)
			}
			parseBodies[k] = d
		}
	}

	// 解析。单文件源用文件自身哈希做溯源；多文件源用联合摘要，
	// 每个文件的真实哈希由解析器按 Files 自行计算。
	body := parseBodies[""]
	artifactSHA := contentHash
	if _, ok := files[""]; ok {
		artifactSHA = HashBytes(files[""].Body)
	}

	pr, err := parser.Parse(ctx, ParseInput{
		Source:      src,
		ArtifactSHA: artifactSHA,
		Body:        body,
		Files:       parseBodies,
		Release:     release,
		FetchedAt:   u.now().UTC(),
	})
	if err != nil {
		_ = u.DB.MarkSourceError(ctx, src.ID, err.Error())
		return nil, fmt.Errorf("feed: 解析 %s 失败: %w", src.ID, err)
	}

	// 落盘（不可变）+ 组装批次
	arts := make([]database.ArtifactRow, 0, len(files))
	for _, f := range files {
		sha := HashBytes(f.Body)
		path, _, perr := u.Store.Put(sha, f.Body)
		if perr != nil {
			_ = u.DB.MarkSourceError(ctx, src.ID, perr.Error())
			return nil, perr
		}
		arts = append(arts, database.ArtifactRow{
			SHA256:          sha,
			SourceID:        src.ID,
			SizeBytes:       int64(len(f.Body)),
			DownloadURL:     f.URL,
			FetchedAt:       u.now().UTC(),
			SignatureStatus: signatureStatusFor(src),
			IntegrityStatus: domain.IntegrityVerified,
			StoredPath:      path,
			// ETag / Last-Modified 必须落库，否则下一次抓取无法发条件请求，
			// 每次都只能靠下载完整内容再比对哈希。
			ETag:         f.ETag,
			LastModified: f.LastModified,
		})
	}
	sort.Slice(arts, func(i, j int) bool { return arts[i].SHA256 < arts[j].SHA256 })

	batch := database.SnapshotBatch{
		Snapshot: database.SnapshotRow{
			ID:            snapshotID(src.ID, release, contentHash),
			SourceID:      src.ID,
			StartedAt:     start.UTC(),
			CompletedAt:   u.now().UTC(),
			ContentHash:   contentHash,
			ParserVersion: src.ParserVersion,
		},
		Artifacts:   arts,
		Advisories:  pr.Advisories,
		Fixes:       pr.Fixes,
		NotAffected: pr.NotAffected,
		Skipped:     pr.Skipped,
	}
	for _, r := range pr.Releases {
		batch.Releases = append(batch.Releases, database.ReleaseKey{
			DistroID: r.DistroID, Release: r.Release, Codename: r.Codename,
		})
	}

	if err := u.DB.CommitSnapshot(ctx, batch); err != nil {
		_ = u.DB.MarkSourceError(ctx, src.ID, err.Error())
		return nil, err
	}

	res := &UpdateResult{
		SourceID:    src.ID,
		Release:     release,
		SnapshotID:  batch.Snapshot.ID,
		Advisories:  len(pr.Advisories),
		Fixes:       len(pr.Fixes),
		NotAffected: len(pr.NotAffected),
		BadRecords:  pr.Skipped,
		Warnings:    pr.Warnings,
		Elapsed:     u.now().Sub(start),
	}
	if src.TrustLevel == domain.TrustLevelA {
		// 明确暴露降级：A 级源的价值全在签名，未验签就是没拿到这个价值。
		res.Warnings = append(res.Warnings, "A 级源本次未完成 GPG 验签，signature_status 记为 unverified")
	}
	// 报告里展示主文件的 Artifact：单文件源就是它本身，
	// 多文件源取「主文件」（Alpine 的 main、其余源的空键）。
	if len(arts) > 0 {
		primary := arts[0]
		for _, a := range arts {
			if a.SHA256 == artifactSHA {
				primary = a
				break
			}
		}
		res.Artifact = Artifact{
			SHA256:          primary.SHA256,
			SourceID:        primary.SourceID,
			SizeBytes:       primary.SizeBytes,
			DownloadURL:     primary.DownloadURL,
			FetchedAt:       primary.FetchedAt,
			SignatureStatus: primary.SignatureStatus,
			IntegrityStatus: primary.IntegrityStatus,
			StoredPath:      primary.StoredPath,
		}
	}
	u.logf("%s: 公告 %d / 修复 %d / 不受影响 %d（%v）",
		src.ID, res.Advisories, res.Fixes, res.NotAffected, res.Elapsed.Round(time.Millisecond))
	return res, nil
}

// fetchedFile 是一份抓取成功的情报文件，连同它的缓存验证信息。
//
// ETag / Last-Modified 必须与内容一起往上带：漏掉它们，下一次抓取
// 就只能重新下载整份文件再比对哈希，条件请求永远不会生效。
type fetchedFile struct {
	// Key 为空串表示单文件源；多文件源用仓库名。
	Key          string
	URL          string
	Body         []byte
	ETag         string
	LastModified string
}

// fetchSourceFiles 按源类型拉取一份或多份文件。
//
// 返回 nil 表示无需更新（304 或哈希未变）。
// 结果键为文件标识：单文件源用空串，多文件源用仓库名。
func (u *Updater) fetchSourceFiles(ctx context.Context, src Source, release string,
	prev database.ArtifactRow, hasPrev bool) (map[string]fetchedFile, error) {

	switch src.ID {
	case domain.SourceAlpineSecDB:
		return u.fetchAlpineFiles(ctx, src, release, prev, hasPrev)
	default:
		url, err := src.URLFor(release)
		if err != nil {
			return nil, err
		}
		f, err := u.fetchOne(ctx, "", url, src, prev, hasPrev)
		if err != nil {
			return nil, err
		}
		if f == nil {
			return nil, nil
		}
		return map[string]fetchedFile{"": *f}, nil
	}
}

// fetchAlpineFiles 抓取 Alpine 的 main 与 community 两份 secdb。
//
// 这里必须处理一个容易写坏库的情形：两份文件中只有一份变化时，
// 未变化的那份会被条件请求判成 304 而拿不到内容。若就此提交，
// replaceNormalized 会删掉该源全部归一化数据、只写回半份，
// 造成「社区仓库的漏洞凭空消失」。因此只要有一份变化，
// 就无条件补齐其余文件，保证写库的永远是完整快照。
func (u *Updater) fetchAlpineFiles(ctx context.Context, src Source, release string,
	prev database.ArtifactRow, hasPrev bool) (map[string]fetchedFile, error) {

	if release == "" {
		return nil, fmt.Errorf("feed: Alpine 更新必须指定 release")
	}
	files := map[string]fetchedFile{}
	urls := map[string]string{}
	var unchanged []string

	for _, repo := range []string{"main", "community"} {
		url, err := src.URLForRepo(release, repo)
		if err != nil {
			return nil, err
		}
		f, err := u.fetchOne(ctx, repo, url, src, prev, hasPrev)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				// community 缺失不算失败：部分 release 只有 main。
				u.logf("%s: %s 不存在，跳过", src.ID, repo)
				continue
			}
			return nil, err
		}
		urls[repo] = url
		if f == nil {
			unchanged = append(unchanged, repo)
			continue
		}
		files[repo] = *f
	}

	if len(files) == 0 {
		// 两份文件都存在且都没变，才是真正的「无需更新」。
		return nil, nil
	}
	for _, repo := range unchanged {
		f, err := u.fetchOne(ctx, repo, urls[repo], src, database.ArtifactRow{}, false)
		if err != nil {
			return nil, fmt.Errorf("feed: 补齐未变化的 %s 失败（拒绝提交半份快照）: %w", repo, err)
		}
		if f == nil {
			return nil, fmt.Errorf("feed: 补齐 %s 时服务端返回 304，无法组装完整快照", repo)
		}
		files[repo] = *f
	}
	return files, nil
}

// fetchOne 抓一个文件；返回 nil 表示内容未变化。
//
// prev 只在「同源同一 URL」时才作为条件请求依据：按 release 分文件的源
// 上一次可能抓的是别的发行版，拿它的 ETag 去问这个 URL 会得到
// 一个语义上不属于本次请求的 304。
func (u *Updater) fetchOne(ctx context.Context, key, url string, src Source,
	prev database.ArtifactRow, hasPrev bool) (*fetchedFile, error) {

	sameURL := hasPrev && prev.DownloadURL == url
	opt := FetchOptions{MaxBytes: src.MaxBytes}
	if sameURL {
		opt.ETag = prev.ETag
		opt.LastModified = prev.LastModified
	}
	res, err := u.Fetcher.Get(ctx, url, opt)
	if err != nil {
		return nil, err
	}
	if res.NotModified {
		return nil, nil
	}
	// 无 ETag 的源（Debian / Arch）靠哈希比对判断是否变化。
	if sameURL && prev.SHA256 == res.SHA256 {
		return nil, nil
	}
	return &fetchedFile{
		Key:          key,
		URL:          url,
		Body:         res.Body,
		ETag:         res.ETag,
		LastModified: res.LastModified,
	}, nil
}

// combinedHash 把多份文件的内容哈希合成一个快照内容哈希。
func combinedHash(files map[string][]byte) string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := make([]byte, 0, len(keys)*64)
	for _, k := range keys {
		h = append(h, []byte(k)...)
		h = append(h, '=')
		h = append(h, []byte(HashBytes(files[k]))...)
		h = append(h, '\n')
	}
	return HashBytes(h)
}

// snapshotID 由源、release 与内容哈希派生，重复更新同一内容得到同一 ID。
func snapshotID(sourceID domain.SourceID, release, contentHash string) string {
	sum := HashBytes([]byte(string(sourceID) + "|" + release + "|" + contentHash))
	return "snap-" + sum[:24]
}

// signatureStatusFor 给出该源应有的签名状态基线。
//
// A 级源必须经过 Verifier 才能声称已验证；在验签链路接通前一律记
// unverified —— 宁可低报可信度，也不能把「HTTPS 拿到了文件」写成
// 「官方签发了文件」。B 级源没有分离签名可验，如实记 not-applicable。
func signatureStatusFor(src Source) domain.SignatureStatus {
	if src.TrustLevel == domain.TrustLevelA {
		return domain.SignatureUnverified
	}
	return domain.SignatureNotApplicable
}

// ErrNoParser 用于明确区分「解析器缺失」与「数据有问题」。
var ErrNoParser = errors.New("feed: 该情报源尚无解析器")
