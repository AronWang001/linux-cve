package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// AlpineParser 解析 Alpine secdb（每个 release、每个仓库一份 JSON）。
//
// 结构（2026-11-24 实测 v3.20 main 81KB / 266 包 / 2,966 条 CVE，
// community 132KB / 410 包 / 5,409 条 CVE）：
//
//	{ "distroversion": "v3.20", "reponame": "main", "archs": [...],
//	  "packages": [ { "pkg": { "name": "aom",
//	      "secfixes": { "3.1.1-r0": ["CVE-2021-30473", ...] } } } ] }
//
// 三处必须如实处理的细节：
//  1. secfixes 的键是「修复版本」，值是「该版本修掉的 CVE」。空串键表示
//     该包存在未修复的 CVE（本期三个 release 实测均为 0 条，但格式允许）。
//  2. 值里混有非 CVE 编号，实测 v3.20 共 366 条，分两类：341 条形如
//     "CVE-2021-27219 GHSL-2021-045"（CVE 后跟厂商通报号，首段可用），
//     25 条形如 "ALPINE-13661" / "GHSA-..."（无 CVE，只能跳过并计数）。
//     后者不得改写成 CVE 编号。
//  3. 同一 CVE 可能在多个版本下重复出现（实测 34 条），每个版本各记一条
//     修复记录：那是不同分支的修复点，合并会丢掉版本比较的依据。
type AlpineParser struct{}

// SourceID 实现 Parser。
func (AlpineParser) SourceID() domain.SourceID { return domain.SourceAlpineSecDB }

// Version 实现 Parser。
func (AlpineParser) Version() string { return ParserVersionAlpine }

// alpineSecDB 是一份 secdb 文件的顶层结构。
type alpineSecDB struct {
	DistroVersion string          `json:"distroversion"`
	RepoName      string          `json:"reponame"`
	Archs         []string        `json:"archs"`
	Packages      []alpinePkgItem `json:"packages"`
}

type alpinePkgItem struct {
	Pkg alpinePkg `json:"pkg"`
}

type alpinePkg struct {
	Name     string              `json:"name"`
	SecFixes map[string][]string `json:"secfixes"`
}

// Parse 实现 Parser。
//
// 必须同时收到 main 与 community 两份文件：只解析其中一份会把另一半
// 包的漏洞当成不存在。缺文件由调用方负责（Updater 会先补齐）。
func (p AlpineParser) Parse(ctx context.Context, in ParseInput) (*ParseResult, error) {
	if len(in.Files) == 0 {
		return nil, fmt.Errorf("feed: Alpine 解析缺少输入文件")
	}
	release := strings.TrimSpace(in.Release)
	if release == "" {
		return nil, fmt.Errorf("feed: Alpine 解析缺少 release")
	}

	res := &ParseResult{}
	repos := make([]string, 0, len(in.Files))
	for repo := range in.Files {
		repos = append(repos, repo)
	}
	sort.Strings(repos)

	records := 0
	for _, repo := range repos {
		body := in.Files[repo]
		if len(body) == 0 {
			return nil, fmt.Errorf("feed: Alpine %s/%s 内容为空", release, repo)
		}
		depth, err := CheckJSONDepth(body, MaxJSONDepth)
		if err != nil {
			return nil, fmt.Errorf("feed: Alpine %s/%s: %w", release, repo, err)
		}
		if depth > res.Guard.MaxDepth {
			res.Guard.MaxDepth = depth
		}
		res.Guard.InputBytes += int64(len(body))
		res.Guard.DecodedBytes += int64(len(body))

		var db alpineSecDB
		if err := json.Unmarshal(body, &db); err != nil {
			return nil, fmt.Errorf("feed: Alpine %s/%s JSON 解码失败: %w", release, repo, err)
		}
		// 版本不符说明拿到的是别的 release 的数据（镜像错位或 URL 拼错），
		// 写进库会污染整份情报。
		if want := "v" + release; db.DistroVersion != want {
			return nil, fmt.Errorf("feed: Alpine %s/%s 声明版本为 %q，与请求的 %q 不符",
				release, repo, db.DistroVersion, want)
		}
		if db.RepoName != repo {
			return nil, fmt.Errorf("feed: Alpine %s/%s 声明仓库为 %q，与文件名不符",
				release, repo, db.RepoName)
		}
		records += p.parseRepo(repo, release, db, in, res)
	}

	if maxErrorRate(res.Skipped, records+res.Skipped) {
		return nil, fmt.Errorf("%w: Alpine %s 异常记录 %d/%d 超过阈值 %.0f%%",
			ErrUnsafeInput, release, res.Skipped, records+res.Skipped, DefaultMaxErrorRate*100)
	}

	// 每个 release 只有一个坐标：Alpine 的仓库不是发行版版本，
	// 不构成额外的 distro_releases 行。
	res.Releases = []ReleaseRef{{DistroID: domain.DistroAlpine, Release: release}}
	return res, nil
}

// parseRepo 处理一份 secdb 的全部包，返回产出的记录数。
func (p AlpineParser) parseRepo(repo, release string, db alpineSecDB, in ParseInput, res *ParseResult) int {
	items := make([]alpinePkgItem, len(db.Packages))
	copy(items, db.Packages)
	sort.Slice(items, func(i, j int) bool { return items[i].Pkg.Name < items[j].Pkg.Name })

	produced := 0
	for _, item := range items {
		pkg := item.Pkg
		name := strings.TrimSpace(pkg.Name)
		if name == "" {
			res.Skipped++
			res.warn("Alpine %s/%s 存在空包名条目", release, repo)
			continue
		}
		if len(pkg.SecFixes) == 0 {
			continue
		}

		// 先按 CVE 归并版本：同一 CVE 可能在多个版本下出现。
		versions := make([]string, 0, len(pkg.SecFixes))
		for v := range pkg.SecFixes {
			versions = append(versions, v)
		}
		sort.Strings(versions)

		cveVersions := map[string][]string{}
		unfixed := map[string]bool{}
		cveOrder := make([]string, 0, 8)

		for _, ver := range versions {
			ids := pkg.SecFixes[ver]
			for _, raw := range ids {
				cve, ok := alpineCVE(raw)
				if !ok {
					res.Skipped++
					res.warn("Alpine %s/%s 包 %s 的非 CVE 编号: %q", release, repo, name, raw)
					continue
				}
				if _, ok := cveVersions[string(cve)]; !ok {
					cveOrder = append(cveOrder, string(cve))
				}
				if strings.TrimSpace(ver) == "" {
					unfixed[string(cve)] = true
					continue
				}
				// 同一个版本里可能重复列出同一 CVE（实测存在），
				// 不去重会产出两条内容相同的修复记录。
				if !containsStr(cveVersions[string(cve)], ver) {
					cveVersions[string(cve)] = append(cveVersions[string(cve)], ver)
				}
			}
		}
		sort.Strings(cveOrder)

		for _, cveStr := range cveOrder {
			cve := domain.CVEID(cveStr)
			// advisory_id 编入 release 与仓库：同一条 CVE 在不同 release、
			// 不同仓库的修复点不同，合并成一条会让 vendor_status 与
			// 修复版本无处安放，也可能让 main 与 community 互相覆盖。
			advisoryID := fmt.Sprintf("%s/%s/%s/%s", cveStr, name, release, repo)
			uid := domain.AdvisoryUID(domain.SourceAlpineSecDB, advisoryID, cve)

			vendorStatus := "fixed"
			if unfixed[cveStr] && len(cveVersions[cveStr]) == 0 {
				vendorStatus = "affected-unfixed"
			}

			res.Advisories = append(res.Advisories, domain.Advisory{
				UID:        uid,
				SourceID:   domain.SourceAlpineSecDB,
				AdvisoryID: advisoryID,
				CVEID:      cve,
				// secdb 不提供标题、严重程度与发布时间，如实留空。
				Severity:       domain.SeverityUnknown,
				SeveritySource: "none",
				URL:            "https://security.alpinelinux.org/vuln/" + cveStr,
				FetchedAt:      in.FetchedAt,
				ArtifactSHA256: artifactSHAFor(in, repo),
				RawLocator:     fmt.Sprintf("%s.packages[pkg=%s].secfixes", repo, name),
				RawRecordHash:  hashAlpineSecFixes(name, pkg.SecFixes),
				ParserVersion:  ParserVersionAlpine,
				VendorStatus:   vendorStatus,
			})
			produced++

			for _, ver := range cveVersions[cveStr] {
				res.Fixes = append(res.Fixes, domain.AdvisoryFix{
					AdvisoryUID: uid,
					SourceID:    domain.SourceAlpineSecDB,
					AdvisoryID:  advisoryID,
					CVEID:       cve,
					DistroID:    domain.DistroAlpine,
					Release:     release,
					Channel:     repo,
					Ref: domain.PackageRef{
						// secdb 记录的是仓库里的二进制包名（apache2、aom），
						// 不是源码包名。
						Kind: domain.PackageKindBinary,
						Name: name,
						// 同一版本对所有架构生效，secdb 的 archs 列的是
						// 全部支持架构而非「限定架构」。
						Arch: domain.ArchAny,
					},
					FixedVersion:       ver,
					FixedVersionSource: domain.FixVersionOfficial,
					EvidenceURL:        alpineSecDBURLOrEmpty(release, repo),
				})
				produced++
			}
		}
	}
	return produced
}

// alpineCVE 从 secdb 的条目标识里取出 CVE 编号。
//
// 实测 v3.20 有两类非纯 CVE 的写法，必须区别对待：
//   - "CVE-2021-27219 GHSL-2021-045"（341 条）：CVE 编号后面跟着厂商通报号。
//     首段就是标准 CVE，整条丢弃会白白损失三百多条真实记录。
//   - "ALPINE-13661" / "GHSA-..." / "RUSTSEC-..." / "DW202402-001"（25 条）：
//     根本没有 CVE，只能跳过并计数，不得改写成 CVE 编号。
func alpineCVE(raw string) (domain.CVEID, bool) {
	s := strings.TrimSpace(raw)
	if cve := domain.CVEID(s); cve.Valid() {
		return cve, true
	}
	if fields := strings.Fields(s); len(fields) > 1 {
		if cve := domain.CVEID(fields[0]); cve.Valid() {
			return cve, true
		}
	}
	return "", false
}

// artifactSHAFor 返回某仓库文件的内容哈希。
//
// 多文件源的 ParseInput.ArtifactSHA 是联合摘要，不能用来指认单份文件；
// 这里按文件内容现算，保证每条记录都能回到确切的字节。
func artifactSHAFor(in ParseInput, repo string) string {
	if body, ok := in.Files[repo]; ok {
		return HashBytes(body)
	}
	return in.ArtifactSHA
}

// alpineSecDBURLOrEmpty 返回 secdb 的下载地址，拼接失败时留空。
func alpineSecDBURLOrEmpty(release, repo string) string {
	u, err := AlpineSecDBURL(release, repo)
	if err != nil {
		return ""
	}
	return u
}

// hashAlpineSecFixes 计算单个包 secfixes 的内容哈希，用于判断该包是否变化。
func hashAlpineSecFixes(name string, secfixes map[string][]string) string {
	versions := make([]string, 0, len(secfixes))
	for v := range secfixes {
		versions = append(versions, v)
	}
	sort.Strings(versions)

	var sb strings.Builder
	sb.WriteString(name)
	for _, v := range versions {
		ids := append([]string(nil), secfixes[v]...)
		sort.Strings(ids)
		sb.WriteByte('|')
		sb.WriteString(v)
		sb.WriteByte('=')
		sb.WriteString(strings.Join(ids, ","))
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// AlpineReleaseKey 把 /etc/os-release 的 VERSION_ID（如 3.20.3）归一为
// secdb 使用的 release 键（3.20）。
//
// 两者粒度不同：系统版本是补丁级，secdb 只按 minor 发布。
// 归一失败的输入原样返回，由调用方决定是否报错，不静默猜一个版本。
func AlpineReleaseKey(versionID string) string {
	v := strings.TrimSpace(versionID)
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return v
	}
	if !isDigits(parts[0]) || !isDigits(parts[1]) {
		return v
	}
	return parts[0] + "." + parts[1]
}

// isDigits 判断字符串是否全为数字且非空。
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// containsStr 判断切片是否已含该值。切片很小（单包单 CVE 的版本数），
// 线性查找比额外维护集合更简单。
func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
