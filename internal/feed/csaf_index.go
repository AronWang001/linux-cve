package feed

// 按文档集发布的情报源（CSAF）的抓取编排。
//
// 与单文件源的根本区别：Red Hat 有 32,407 份公告、SUSE 有数万份，
// 一份公告就是一个发布物。策略是「索引驱动 + 本地 CAS 复用」：
//
//  1. 先抓 changes.csv（发布方给的变更清单），它本身也是一份不可变 Artifact；
//  2. 逐份处理：清单里的时间戳不比本地 Artifact 新，就直接读本地字节，
//     不重复下载——既不浪费带宽，也不影响可追溯性（字节还是那份字节）；
//  3. 需要更新的文档重新下载，(A 级源)验签通过才落盘；
//  4. 全部文档解析完，合并成一个快照一次性提交。
//
// 快照仍然是「整源替换」语义：旧公告在本次集合里就保留，
// 不在就随快照一起失效，使扫描看到的情报永远是同一时刻的完整切片。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/database"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// DocInput 是「一份公告文档」的解析输入。
//
// Path 是清单里的相对路径，进入 raw_locator，
// 使每条归一化记录都能指回发布集里的具体文件。
type DocInput struct {
	Source      Source
	Path        string
	ArtifactSHA string
	Body        []byte
	FetchedAt   time.Time
}

// DocumentParser 是按份解析的解析器（CSAF）。
type DocumentParser interface {
	SourceID() domain.SourceID
	Version() string
	ParseDocument(in DocInput) (*ParseResult, error)
}

// DocumentParserFor 返回按份解析的解析器；不存在时返回 nil 与原因。
func DocumentParserFor(id domain.SourceID) (DocumentParser, string) {
	switch id {
	case domain.SourceRHELCSAF:
		return RedHatParser{}, ""
	case domain.SourceSUSECSAF:
		return SUSEParser{}, ""
	default:
		return nil, "该情报源不是按文档发布的形式"
	}
}

// docFetchWorkers 是并发抓取的协程数。
//
// 12 是实测折中：再高对厂商 CDN 不礼貌、也容易触发限流，
// 再低则首轮几万份文档要跑太久。
const docFetchWorkers = 12

// csafIndexEntry 是 changes.csv 的一行。
type csafIndexEntry struct {
	// Path 形如 "2026/rhsa-2026_0002.json"。
	Path string
	// Modified 是发布方声明的最后修改时间。
	Modified time.Time
	// Year 是从路径里取出的年份，用于按年限裁剪。
	Year int
}

// docOutcome 是单份文档的处理结果。
type docOutcome struct {
	path   string
	sha    string
	res    *ParseResult
	art    database.ArtifactRow
	err    error
	reused bool
}

// parseIndexCSV 解析 changes.csv。
//
// 格式（实测）：`"2026/rhsa-2026_0002.json","2026-11-24T12:29:13+00:00"`。
// 只接受能解析出相对路径与时间的行：格式漂移时宁可少算，也不猜。
func parseIndexCSV(b []byte) ([]csafIndexEntry, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("feed: 变更清单为空")
	}
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	out := make([]csafIndexEntry, 0, len(lines))
	bad := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			bad++
			continue
		}
		path := strings.Trim(fields[0], `"`)
		ts := strings.Trim(fields[1], `"`)
		if path == "" || !strings.HasSuffix(strings.ToLower(path), ".json") {
			bad++
			continue
		}
		// 只接受站内相对路径：清单来自发布方，但不能让一条记录
		// 把抓取引到别的域名或跳出目录。
		if strings.Contains(path, "://") || strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			bad++
			continue
		}
		mod, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			bad++
			continue
		}
		year := 0
		if i := strings.Index(path, "/"); i > 0 {
			if y, perr := strconv.Atoi(path[:i]); perr == nil {
				year = y
			}
		}
		out = append(out, csafIndexEntry{Path: path, Modified: mod, Year: year})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("feed: 变更清单没有任何可用条目（异常行 %d）", bad)
	}
	if maxErrorRate(bad, len(out)+bad) {
		return nil, fmt.Errorf("%w: 变更清单异常行 %d/%d 超过阈值",
			ErrUnsafeInput, bad, len(out)+bad)
	}
	return out, nil
}

// updateDocumentSet 更新一个按文档发布的源。
func (u *Updater) updateDocumentSet(ctx context.Context, src Source,
	release string, prev database.ArtifactRow, hasPrev bool) (*UpdateResult, error) {

	start := u.now().UTC()
	parser, reason := DocumentParserFor(src.ID)
	if parser == nil {
		return nil, fmt.Errorf("%w: %s：%s", ErrNoParser, src.ID, reason)
	}
	if src.IndexURL == "" {
		return nil, fmt.Errorf("feed: %s 缺少变更清单地址", src.ID)
	}

	// 1. 索引。索引不变说明发布集没变，直接跳过——最省的一次同步。
	idxFile, err := u.fetchOne(ctx, "", src.IndexURL, src, prev, hasPrev)
	if err != nil {
		_ = u.DB.MarkSourceError(ctx, src.ID, err.Error())
		return nil, err
	}
	if idxFile == nil {
		return &UpdateResult{
			SourceID: src.ID, Release: release, Skipped: true,
			SkipReason: "变更清单未变化（304 或哈希一致）",
			Elapsed:    u.now().Sub(start),
		}, nil
	}

	entries, err := parseIndexCSV(idxFile.Body)
	if err != nil {
		_ = u.DB.MarkSourceError(ctx, src.ID, err.Error())
		return nil, err
	}
	total := len(entries)

	// 按年限裁剪：支持矩阵只覆盖近几年的发行版，更早的公告
	// 既不会命中受支持系统，又会把同步时间与磁盘撑爆。
	if src.SinceYear > 0 {
		kept := make([]csafIndexEntry, 0, len(entries))
		for _, e := range entries {
			if e.Year == 0 || e.Year >= src.SinceYear {
				kept = append(kept, e)
			}
		}
		entries = kept
	}

	idxSHA := HashBytes(idxFile.Body)
	idxPath, _, perr := u.Store.Put(idxSHA, idxFile.Body)
	if perr != nil {
		_ = u.DB.MarkSourceError(ctx, src.ID, perr.Error())
		return nil, perr
	}
	arts := []database.ArtifactRow{{
		SHA256:      idxSHA,
		SourceID:    src.ID,
		SizeBytes:   int64(len(idxFile.Body)),
		DownloadURL: idxFile.URL,
		FetchedAt:   u.now().UTC(),
		// 清单不签名，它只是索引；把它标成 verified 会虚增签名覆盖。
		SignatureStatus: domain.SignatureNotApplicable,
		IntegrityStatus: domain.IntegrityVerified,
		StoredPath:      idxPath,
		ETag:            idxFile.ETag,
		LastModified:    idxFile.LastModified,
	}}

	// 2. 并发处理文档。
	jobs := make(chan int)
	results := make(chan docOutcome, docFetchWorkers*2)

	var wg sync.WaitGroup
	for w := 0; w < docFetchWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				results <- u.processOneDocument(ctx, src, parser, entries[i])
			}
		}()
	}
	go func() {
		defer close(jobs)
		for i := range entries {
			select {
			case jobs <- i:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		wg.Wait()
		close(results)
	}()

	agg := &ParseResult{}
	failures, fetched, reused, done := 0, 0, 0, 0
	shaByPath := make(map[string]string, len(entries))
	for out := range results {
		done++
		if out.err != nil {
			failures++
			agg.warn("%s: %v", out.path, out.err)
		} else {
			if out.reused {
				reused++
			} else {
				fetched++
			}
			arts = append(arts, out.art)
			shaByPath[out.path] = out.sha
			agg.Advisories = append(agg.Advisories, out.res.Advisories...)
			agg.Fixes = append(agg.Fixes, out.res.Fixes...)
			agg.NotAffected = append(agg.NotAffected, out.res.NotAffected...)
			agg.Releases = append(agg.Releases, out.res.Releases...)
			agg.Skipped += out.res.Skipped
			agg.BridgeFailed += out.res.BridgeFailed
			for _, w := range out.res.Warnings {
				agg.warn("%s", w)
			}
		}
		if done%500 == 0 {
			u.logf("%s：已处理 %d/%d（新下载 %d，复用 %d，失败 %d）",
				src.ID, done, len(entries), fetched, reused, failures)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// 失败率过高说明上游在故障或格式变了，整批拒绝：
	// 半套情报比没有情报更危险，因为覆盖状态看起来仍是 COVERED。
	if failures > 0 && maxErrorRate(failures, len(entries)) {
		msg := fmt.Sprintf("文档失败 %d/%d 超过阈值，放弃本次快照", failures, len(entries))
		_ = u.DB.MarkSourceError(ctx, src.ID, msg)
		return nil, fmt.Errorf("feed: %s %s", src.ID, msg)
	}

	agg.Releases = dedupeReleases(agg.Releases)
	arts = dedupeArtifacts(arts)

	contentHash := hashDocumentSet(shaByPath)
	batch := database.SnapshotBatch{
		Snapshot: database.SnapshotRow{
			ID:            snapshotID(src.ID, release, contentHash),
			SourceID:      src.ID,
			StartedAt:     start,
			CompletedAt:   u.now().UTC(),
			ContentHash:   contentHash,
			ParserVersion: src.ParserVersion,
		},
		Artifacts:   arts,
		Advisories:  agg.Advisories,
		Fixes:       agg.Fixes,
		NotAffected: agg.NotAffected,
		Skipped:     agg.Skipped,
	}
	for _, r := range agg.Releases {
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
		Advisories:  len(agg.Advisories),
		Fixes:       len(agg.Fixes),
		NotAffected: len(agg.NotAffected),
		BadRecords:  agg.Skipped,
		Warnings:    agg.Warnings,
		Elapsed:     u.now().Sub(start),
	}
	if agg.BridgeFailed > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"%d 条记录引用了产品树中不存在的产品，包级细节缺失（公告本身仍已入库）",
			agg.BridgeFailed))
	}
	if total != len(entries) {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"按起始年份 %d 裁剪：清单 %d 份，本次处理 %d 份", src.SinceYear, total, len(entries)))
	}
	res.Warnings = append(res.Warnings, fmt.Sprintf(
		"文档 %d 份：新下载 %d、复用本地 %d、失败 %d", len(entries), fetched, reused, failures))

	u.logf("%s: 公告 %d / 修复 %d / 不受影响 %d（%v）",
		src.ID, res.Advisories, res.Fixes, res.NotAffected, res.Elapsed.Round(time.Millisecond))
	return res, nil
}

// processOneDocument 处理一份文档：必要时下载并验签，然后解析。
func (u *Updater) processOneDocument(ctx context.Context, src Source,
	parser DocumentParser, e csafIndexEntry) docOutcome {

	url := strings.TrimRight(src.URL, "/") + "/" + e.Path

	// 复用本地：清单时间戳不比本地抓取时间新，说明内容没变。
	if art, ok, err := u.DB.ArtifactByURL(ctx, src.ID, url); err == nil && ok {
		if !e.Modified.After(art.FetchedAt) {
			if body, rerr := os.ReadFile(art.StoredPath); rerr == nil {
				res, perr := parser.ParseDocument(DocInput{
					Source: src, Path: e.Path, ArtifactSHA: art.SHA256,
					Body: body, FetchedAt: art.FetchedAt,
				})
				if perr != nil {
					return docOutcome{path: e.Path, err: perr}
				}
				return docOutcome{path: e.Path, sha: art.SHA256, res: res, art: art, reused: true}
			}
			// 本地字节丢了（磁盘清理、误删）：退回重新下载，不静默跳过。
		}
	}

	body, sig, err := u.fetchDocument(ctx, src, url)
	if err != nil {
		return docOutcome{path: e.Path, err: err}
	}

	sigStatus := signatureStatusFor(src)
	if src.TrustLevel == domain.TrustLevelA {
		if u.Verifier == nil {
			return docOutcome{path: e.Path, err: fmt.Errorf("A 级源未配置签名校验器")}
		}
		st, _, verr := u.Verifier.VerifyDetached(ctx, src, body, sig)
		if verr != nil {
			return docOutcome{path: e.Path, err: fmt.Errorf("验签失败: %w", verr)}
		}
		sigStatus = st
	}

	sha := HashBytes(body)
	stored, _, perr := u.Store.Put(sha, body)
	if perr != nil {
		return docOutcome{path: e.Path, err: perr}
	}
	art := database.ArtifactRow{
		SHA256:          sha,
		SourceID:        src.ID,
		SizeBytes:       int64(len(body)),
		DownloadURL:     url,
		FetchedAt:       u.now().UTC(),
		SignatureStatus: sigStatus,
		IntegrityStatus: domain.IntegrityVerified,
		StoredPath:      stored,
	}
	res, perr := parser.ParseDocument(DocInput{
		Source: src, Path: e.Path, ArtifactSHA: sha, Body: body, FetchedAt: art.FetchedAt,
	})
	if perr != nil {
		return docOutcome{path: e.Path, err: perr}
	}
	return docOutcome{path: e.Path, sha: sha, res: res, art: art}
}

// fetchDocument 取一份文档；(A 级源)同时取它的分离签名。
func (u *Updater) fetchDocument(ctx context.Context, src Source,
	url string) (body, sig []byte, err error) {

	res, err := u.Fetcher.Get(ctx, url, FetchOptions{MaxBytes: src.MaxBytes})
	if err != nil {
		return nil, nil, err
	}
	body = res.Body
	if src.TrustLevel != domain.TrustLevelA {
		return body, nil, nil
	}
	sigRes, err := u.Fetcher.Get(ctx, url+".asc", FetchOptions{MaxBytes: 64 << 10})
	if err != nil {
		return nil, nil, fmt.Errorf("抓取签名失败: %w", err)
	}
	return body, sigRes.Body, nil
}

// hashDocumentSet 计算发布集的联合摘要。
//
// 按路径排序后滚动哈希「路径 + 内容哈希」：清单顺序可能变化，
// 但集合内容不变时摘要必须相同，否则每次同步都会产生一个「新」快照，
// 白白重建几十万条归一化记录。
func hashDocumentSet(shaByPath map[string]string) string {
	paths := make([]string, 0, len(shaByPath))
	for p := range shaByPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write([]byte(shaByPath[p]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// dedupeReleases 去重 release 坐标（文档集里同一坐标会重复上万次）。
func dedupeReleases(in []ReleaseRef) []ReleaseRef {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, r := range in {
		k := string(r.DistroID) + "\x1f" + r.Release
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DistroID != out[j].DistroID {
			return out[i].DistroID < out[j].DistroID
		}
		return out[i].Release < out[j].Release
	})
	return out
}

// dedupeArtifacts 按 sha256 去重（同一份字节可能被多个 URL 发布）。
func dedupeArtifacts(in []database.ArtifactRow) []database.ArtifactRow {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, a := range in {
		if seen[a.SHA256] {
			continue
		}
		seen[a.SHA256] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SHA256 < out[j].SHA256 })
	return out
}
