package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// DebianParser 解析 Debian Security Tracker 的全量 JSON。
//
// 结构（2026-11-24 实测：89MB、4,217 个源码包、83,080 个 CVE、289,749 条
// release 记录）：
//
//	{ "<源码包>": { "<CVE>": {
//	      "description": "...", "scope": "local",
//	      "releases": { "<codename>": {
//	          "status": "resolved|open|undetermined",
//	          "repositories": { "<repo>": "<version>" },
//	          "fixed_version": "6.12.113-1" 或占位 "0",
//	          "urgency": "not yet assigned|unimportant|low|medium|high|end-of-life"
//	      } } } } }
//
// 两处与直觉相反的实测事实，直接决定了实现方式：
//  1. 顶层键是「源码包」而不是 CVE。所以解析按包推进，内存只需容纳一个包。
//  2. fixed_version 有 25,449 条是占位 "0"（resolved 总数 259,254 的 8.8%），
//     真实版本只存在于 repositories。这类记录只能弱判，不能当官方修复版本用。
//
// 另外 sid / forky / experimental 是不稳定的开发版，生产服务器不会运行，
// 直接跳过：它们占全部 release 记录的约四成，且会让 distro_releases 里
// 多出一批永远匹配不到的坐标。
type DebianParser struct{}

// SourceID 实现 Parser。
func (DebianParser) SourceID() domain.SourceID { return domain.SourceDebianTracker }

// Version 实现 Parser。
func (DebianParser) Version() string { return ParserVersionDebian }

// debianCVERecord 是某源码包下的单条 CVE 记录。
type debianCVERecord struct {
	Description string                   `json:"description"`
	Scope       string                   `json:"scope"`
	Releases    map[string]debianRelease `json:"releases"`
}

// debianRelease 是某 CVE 在某个 Debian release 上的状态。
type debianRelease struct {
	Status       string            `json:"status"`
	Repositories map[string]string `json:"repositories"`
	FixedVersion string            `json:"fixed_version"`
	Urgency      string            `json:"urgency"`
}

// debianCodenameRelease 把 codename 映射到 VERSION_ID。
// 未收录的（sid / experimental / hornyx 等）一律跳过，不猜版本号。
var debianCodenameRelease = map[string]string{
	"bullseye": "11",
	"bookworm": "12",
	"trixie":   "13",
	"forky":    "14",
}

// Parse 实现 Parser。
func (p DebianParser) Parse(ctx context.Context, in ParseInput) (*ParseResult, error) {
	if len(in.Body) == 0 {
		return nil, fmt.Errorf("feed: Debian 解析缺少内容")
	}
	depth, err := CheckJSONDepth(in.Body, MaxJSONDepth)
	if err != nil {
		return nil, err
	}

	res := &ParseResult{}
	res.Guard = GuardStats{MaxDepth: depth, InputBytes: int64(len(in.Body)), DecodedBytes: int64(len(in.Body))}

	dec := json.NewDecoder(bytes.NewReader(in.Body))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("feed: Debian JSON 解析失败: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("feed: Debian 数据顶层不是 JSON 对象")
	}

	seenReleases := map[string]ReleaseRef{}
	packets, records := 0, 0

	for dec.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("feed: Debian JSON 读取源码包名失败: %w", err)
		}
		pkg, _ := keyTok.(string)
		if pkg == "" {
			return nil, fmt.Errorf("feed: Debian JSON 出现空的源码包名")
		}

		var cves map[string]debianCVERecord
		// 包级解码失败说明格式变了，整批拒绝：半套数据比没有数据更危险。
		if err := dec.Decode(&cves); err != nil {
			return nil, fmt.Errorf("feed: Debian 源码包 %q 解码失败: %w", pkg, err)
		}
		packets++
		records += p.parsePackage(pkg, cves, in, res, seenReleases)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("feed: Debian JSON 结构未闭合: %w", err)
	}

	// 异常记录比例过高说明是格式漂移而不是个别脏数据，整批拒绝。
	if maxErrorRate(res.Skipped, records+res.Skipped) {
		return nil, fmt.Errorf("%w: Debian 异常记录 %d/%d 超过阈值 %.0f%%",
			ErrUnsafeInput, res.Skipped, records+res.Skipped, DefaultMaxErrorRate*100)
	}

	names := make([]string, 0, len(seenReleases))
	for k := range seenReleases {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		res.Releases = append(res.Releases, seenReleases[k])
	}
	return res, nil
}

// parsePackage 处理一个源码包下的全部 CVE，返回产出的记录数。
func (p DebianParser) parsePackage(pkg string, cves map[string]debianCVERecord,
	in ParseInput, res *ParseResult, seen map[string]ReleaseRef) int {

	// map 迭代顺序随机，必须排序：否则同一份数据两次解析产出顺序不同，
	// 快照内容哈希随之漂移，「内容没变」就永远判不出来。
	cveIDs := make([]string, 0, len(cves))
	for id := range cves {
		cveIDs = append(cveIDs, id)
	}
	sort.Strings(cveIDs)

	produced := 0
	for _, cveID := range cveIDs {
		cve := domain.CVEID(cveID)
		if !cve.Valid() {
			res.Skipped++
			res.warn("源码包 %s 下的非法 CVE 编号: %q", pkg, cveID)
			continue
		}
		rec := cves[cveID]

		codenames := make([]string, 0, len(rec.Releases))
		for cn := range rec.Releases {
			codenames = append(codenames, cn)
		}
		sort.Strings(codenames)

		for _, codename := range codenames {
			release, ok := debianCodenameRelease[codename]
			if !ok {
				// 开发版或不认识的 codename：跳过且不计为异常。
				continue
			}
			rel := rec.Releases[codename]
			if rel.Status == "" {
				res.Skipped++
				res.warn("%s %s %s 缺少 status", pkg, cveID, codename)
				continue
			}

			seen["debian:"+release] = ReleaseRef{DistroID: domain.DistroDebian, Release: release, Codename: codename}

			// advisory_id 编入 release：同一条 CVE 在 bookworm 与 trixie 的
			// 状态和修复版本都不同，合并成一条会让 vendor_status 无处安放。
			advisoryID := fmt.Sprintf("%s/%s/%s", cveID, pkg, release)
			uid := domain.AdvisoryUID(domain.SourceDebianTracker, advisoryID, cve)

			res.Advisories = append(res.Advisories, domain.Advisory{
				UID:        uid,
				SourceID:   domain.SourceDebianTracker,
				AdvisoryID: advisoryID,
				CVEID:      cve,
				// Debian 的 description 是 CVE Program 的描述文本，
				// 不属于 advisory 自身标题，也不宜整份复制入库。
				Title:          "",
				Severity:       debianSeverity(rel.Urgency),
				SeveritySource: "debian-urgency",
				URL:            "https://security-tracker.debian.org/tracker/" + cveID,
				FetchedAt:      in.FetchedAt,
				ArtifactSHA256: in.ArtifactSHA,
				RawLocator:     fmt.Sprintf("%s.%s.releases.%s", pkg, cveID, codename),
				RawRecordHash:  hashDebianRelease(rel),
				ParserVersion:  ParserVersionDebian,
				VendorStatus:   rel.Status,
			})
			produced++

			produced += appendDebianFixes(res, pkg, cve, release, codename, rel, uid, advisoryID, in)
		}
	}
	return produced
}

// appendDebianFixes 依据 release 状态产出修复记录。
//
// 三种状态分别对应三种证据强度：
//   - resolved + 真实 fixed_version → 官方声明，可严格比较
//   - resolved + 占位 "0"            → 只有仓库当前版本，弱判
//   - open / undetermined            → 无修复版本，只留 advisory 表达状态
func appendDebianFixes(res *ParseResult, pkg string, cve domain.CVEID, release, codename string,
	rel debianRelease, uid, advisoryID string, in ParseInput) int {

	base := domain.AdvisoryFix{
		AdvisoryUID: uid,
		SourceID:    domain.SourceDebianTracker,
		AdvisoryID:  advisoryID,
		CVEID:       cve,
		DistroID:    domain.DistroDebian,
		Release:     release,
		Ref: domain.PackageRef{
			Kind: domain.PackageKindSource,
			Name: pkg,
			Arch: domain.ArchAny,
		},
		EvidenceURL: "https://security-tracker.debian.org/tracker/" + string(cve),
	}

	// open：发布方已确认受影响，但没有修复版本。这条必须落库——
	// 它就是「已知有洞、暂时没有补丁」，是扫描最应该报出来的情况。
	// undetermined：发布方尚未判定，不能当作受影响，只留 advisory 表达未知。
	if rel.Status != "resolved" {
		if rel.Status != "open" {
			return 0
		}
		fix := base
		fix.Channel = pickDebianChannel(codename, rel.Repositories)
		fix.FixedVersion = "" // 空版本 = 确认受影响、无修复包
		fix.FixedVersionSource = domain.FixVersionOfficial
		res.Fixes = append(res.Fixes, fix)
		return 1
	}

	if isRealFixedVersion(rel.FixedVersion) {
		fix := base
		fix.Channel = pickDebianChannel(codename, rel.Repositories)
		fix.FixedVersion = rel.FixedVersion
		fix.FixedVersionSource = domain.FixVersionOfficial
		res.Fixes = append(res.Fixes, fix)
		return 1
	}

	// 占位版本：只能用仓库观测值，逐仓库各记一条，让匹配器按渠道分别弱判。
	repos := make([]string, 0, len(rel.Repositories))
	for repo := range rel.Repositories {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	n := 0
	for _, repo := range repos {
		ver := strings.TrimSpace(rel.Repositories[repo])
		if ver == "" {
			continue
		}
		fix := base
		fix.Channel = repo
		fix.FixedVersion = ver
		fix.FixedVersionSource = domain.FixVersionRepositoryObserved
		res.Fixes = append(res.Fixes, fix)
		n++
	}
	if n == 0 {
		res.Skipped++
		res.warn("%s %s 状态为 resolved 但既无修复版本也无仓库版本", pkg, cve)
	}
	return n
}

// pickDebianChannel 选出该 release 的主渠道。
// 优先安全仓库：修复通常先出现在 <codename>-security。
func pickDebianChannel(codename string, repos map[string]string) string {
	if _, ok := repos[codename+"-security"]; ok {
		return codename + "-security"
	}
	if _, ok := repos[codename]; ok {
		return codename
	}
	names := make([]string, 0, len(repos))
	for k := range repos {
		names = append(names, k)
	}
	if len(names) == 0 {
		// 没有任何仓库信息时仍要给出渠道，用 codename 自身作保守选择。
		return codename
	}
	sort.Strings(names)
	return names[0]
}

// isRealFixedVersion 判断 fixed_version 是否为真实版本号。
// Debian 用 "0" 表示「没有单独的修复版本」，空串同理。
func isRealFixedVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v != "" && v != "0"
}

// debianSeverity 把 Debian 的 urgency 映射到统一严重程度。
// 只用于展示与排序，不参与受影响判定。
func debianSeverity(urgency string) domain.Severity {
	switch strings.ToLower(strings.TrimSpace(urgency)) {
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	case "unimportant":
		return domain.SeverityLow
	default:
		// "not yet assigned" / "end-of-life" 等：不猜，如实标 unknown。
		return domain.SeverityUnknown
	}
}

// hashDebianRelease 计算单条 release 记录的内容哈希，用于判断该条是否变化。
func hashDebianRelease(rel debianRelease) string {
	// 结构化后序列化，避免 map 顺序导致的哈希漂移。
	repos := make([]string, 0, len(rel.Repositories))
	for k := range rel.Repositories {
		repos = append(repos, k)
	}
	sort.Strings(repos)
	var sb strings.Builder
	sb.WriteString(rel.Status)
	sb.WriteByte('|')
	sb.WriteString(rel.FixedVersion)
	sb.WriteByte('|')
	sb.WriteString(rel.Urgency)
	for _, k := range repos {
		sb.WriteByte('|')
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(rel.Repositories[k])
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}
