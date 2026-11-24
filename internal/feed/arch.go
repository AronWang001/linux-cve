package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// ArchRelease 是 Arch 的 release 标识。
//
// Arch 是滚动发行，没有版本号，但它也不是「没有发行版」：
// 系统里装的就是 rolling 仓库里的包。用固定标识表达，比留空更诚实，
// 也避免 distro_releases 主键出现空串。
const ArchRelease = "rolling"

// ArchChannel 是 Arch 修复版本的渠道标识。
//
// 追踪器不告诉某个包属于 core 还是 extra，只给出「稳定仓库里的版本」。
// 因此渠道记 stable：不假装知道具体仓库，也不留空。
const ArchChannel = "stable"

// ArchParser 解析 Arch Security Tracker 的全量 JSON。
//
// 结构（2026-11-24 实测 898KB、2,444 条 AVG 记录）：
//
//	[ { "name": "AVG-2843", "packages": ["vim"], "status": "Unknown",
//	    "severity": "Unknown", "type": "unknown",
//	    "affected": "9.0.1224-1", "fixed": "9.0.1225-1",
//	    "ticket": null, "issues": ["CVE-2023-0433", ...],
//	    "advisories": ["ASA-202610-2"] } ]
//
// 四个实测事实决定了字段怎么落库：
//  1. 条目是「平均记录」：一条 AVG 可覆盖多个包与多条 CVE（实测 52 条
//     涉及多包）。因此按「包 × CVE」拆成修复记录，而不是一条 AVG 一条。
//  2. status 有四种取值：Fixed 2,152 / Not affected 193 / Vulnerable 84 /
//     Unknown 15。只有 Fixed 才给出可比较的修复版本。
//  3. Not affected 里有 78 条仍带 fixed 字段。那是「修复版本存在但本包
//     从未受影响」，若照抄成修复记录，会凭空造出「请升级到 X」的错误建议。
//  4. Unknown 里有 13 条带 fixed 字段。状态未定性时不得把版本当结论，
//     只留 advisory 表达原始状态。
type ArchParser struct{}

// SourceID 实现 Parser。
func (ArchParser) SourceID() domain.SourceID { return domain.SourceArchTracker }

// Version 实现 Parser。
func (ArchParser) Version() string { return ParserVersionArch }

// archAVG 是追踪器的一条平均记录。
type archAVG struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      *string  `json:"fixed"`
	Ticket     *string  `json:"ticket"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

// Parse 实现 Parser。
func (p ArchParser) Parse(ctx context.Context, in ParseInput) (*ParseResult, error) {
	body := in.Body
	if len(body) == 0 {
		body = in.Files[""]
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("feed: Arch 解析缺少内容")
	}
	depth, err := CheckJSONDepth(body, MaxJSONDepth)
	if err != nil {
		return nil, err
	}

	res := &ParseResult{}
	res.Guard = GuardStats{MaxDepth: depth, InputBytes: int64(len(body)), DecodedBytes: int64(len(body))}

	var items []archAVG
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("feed: Arch JSON 解码失败: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("feed: Arch 数据为空数组，拒绝用空数据覆盖已有情报")
	}

	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })

	artifactSHA := in.ArtifactSHA
	if artifactSHA == "" {
		artifactSHA = HashBytes(body)
	}

	records := 0
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		records += p.parseIntAVG(it, artifactSHA, in, res)
	}

	if maxErrorRate(res.Skipped, records+res.Skipped) {
		return nil, fmt.Errorf("%w: Arch 异常记录 %d/%d 超过阈值 %.0f%%",
			ErrUnsafeInput, res.Skipped, records+res.Skipped, DefaultMaxErrorRate*100)
	}

	res.Releases = []ReleaseRef{{DistroID: domain.DistroArch, Release: ArchRelease}}
	return res, nil
}

// parseIntAVG 处理一条 AVG，返回产出的记录数。
func (p ArchParser) parseIntAVG(it archAVG, artifactSHA string, in ParseInput, res *ParseResult) int {
	name := strings.TrimSpace(it.Name)
	if name == "" {
		res.Skipped++
		res.warn("Arch 存在缺少 AVG 编号的记录")
		return 0
	}
	pkgs := cleanNames(it.Packages)
	if len(pkgs) == 0 {
		res.Skipped++
		res.warn("%s 没有包名，无法用于匹配", name)
		return 0
	}
	if len(it.Issues) == 0 {
		res.Skipped++
		res.warn("%s 没有关联任何 CVE", name)
		return 0
	}

	status := strings.TrimSpace(it.Status)
	fixed := ""
	if it.Fixed != nil {
		fixed = strings.TrimSpace(*it.Fixed)
	}
	url := "https://security.archlinux.org/" + name

	produced := 0
	for _, rawCVE := range it.Issues {
		cve := domain.CVEID(strings.TrimSpace(rawCVE))
		if !cve.Valid() {
			res.Skipped++
			res.warn("%s 关联了非 CVE 编号: %q", name, rawCVE)
			continue
		}

		// 一条 AVG 覆盖多包，故 advisory 以 (AVG, CVE) 为粒度，
		// 包维度落在修复记录与不受影响声明上。
		advisoryID := fmt.Sprintf("%s/%s", name, cve)
		uid := domain.AdvisoryUID(domain.SourceArchTracker, advisoryID, cve)

		res.Advisories = append(res.Advisories, domain.Advisory{
			UID:            uid,
			SourceID:       domain.SourceArchTracker,
			AdvisoryID:     advisoryID,
			CVEID:          cve,
			Title:          archTitle(it.Type),
			Severity:       archSeverity(it.Severity),
			SeveritySource: "arch-avg",
			URL:            url,
			FetchedAt:      in.FetchedAt,
			ArtifactSHA256: artifactSHA,
			RawLocator:     fmt.Sprintf("[name=%s]", name),
			RawRecordHash:  hashArchAVG(it),
			ParserVersion:  ParserVersionArch,
			VendorStatus:   status,
		})
		produced++

		for _, pkg := range pkgs {
			ref := domain.PackageRef{Kind: domain.PackageKindBinary, Name: pkg, Arch: domain.ArchAny}
			switch status {
			case "Fixed":
				if fixed == "" {
					// 状态声称已修复却没有版本，无法参与版本比较。
					res.Skipped++
					res.warn("%s 状态为 Fixed 但缺少 fixed 版本", name)
					continue
				}
				res.Fixes = append(res.Fixes, domain.AdvisoryFix{
					AdvisoryUID:        uid,
					SourceID:           domain.SourceArchTracker,
					AdvisoryID:         advisoryID,
					CVEID:              cve,
					DistroID:           domain.DistroArch,
					Release:            ArchRelease,
					Channel:            ArchChannel,
					Ref:                ref,
					FixedVersion:       fixed,
					FixedVersionSource: domain.FixVersionOfficial,
					EvidenceURL:        url,
				})
				produced++
			case "Not affected":
				// 即使带 fixed 版本也不能产出修复记录：本包从未受影响，
				// 「升级到该版本」是无意义的建议。
				res.NotAffected = append(res.NotAffected, domain.NotAffected{
					SourceID:    domain.SourceArchTracker,
					AdvisoryID:  advisoryID,
					CVEID:       cve,
					DistroID:    domain.DistroArch,
					Release:     ArchRelease,
					Ref:         ref,
					Reason:      domain.NotAffectedDeclared,
					EvidenceURL: url,
				})
				produced++
			case "Vulnerable", "Unknown":
				// 状态本身是证据，已记在 advisory 的 vendor_status 上。
			default:
				// 出现未知状态说明格式变了，不得默认成任何结论。
				res.Skipped++
				res.warn("%s 出现未知状态: %q", name, status)
			}
		}
	}
	return produced
}

// cleanNames 去空白、去重并排序，保证同一份数据两次解析结果一致。
func cleanNames(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		v := strings.TrimSpace(s)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// archSeverity 把追踪器的严重程度映射到统一取值。
// 只用于展示与排序，不参与受影响判定。
func archSeverity(s string) domain.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

// archTitle 把漏洞类型作为标题。
//
// 追踪器的 type 是漏洞类别（如 denial of service），不是公告标题，
// 但它是该记录唯一的人类可读描述，比空标题更有信息量；
// 原始值可随时从 artifact 取回。
func archTitle(t string) string {
	v := strings.TrimSpace(t)
	if v == "unknown" || v == "" {
		return ""
	}
	return v
}

// hashArchAVG 计算单条 AVG 的内容哈希，用于判断该条是否变化。
func hashArchAVG(it archAVG) string {
	fixed := ""
	if it.Fixed != nil {
		fixed = *it.Fixed
	}
	parts := []string{
		it.Name, it.Status, it.Severity, it.Type, it.Affected, fixed,
		strings.Join(cleanNames(it.Packages), ","),
		strings.Join(sortedCopy(it.Issues), ","),
		strings.Join(sortedCopy(it.Advisories), ","),
	}
	return HashBytes([]byte(strings.Join(parts, "\x1f")))
}

// sortedCopy 返回排序后的副本，避免就地改动调用方的切片。
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
