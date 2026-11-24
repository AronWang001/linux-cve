package feed

// CSAF 2.0 安全公告的共享解析层。
//
// Red Hat 与 SUSE 都按 CSAF 2.0 发布公告，文档结构一致、字段语义有差异
// （Red Hat 用 product_status.fixed，SUSE 用 recommended；发行版坐标
// 一个藏在 CPE 里，另一个藏在产品名字符串里）。差异用 csafProfile 收敛，
// 文档遍历、产品解析、归一化落库共用一套代码。
//
// 与 Debian/Alpine 解析器的根本区别：CSAF 是「按公告逐份」发布，
// 一个源是几万份文档而不是一个文件，因此这里只负责单份文档，
// 多文档编排在 csaf_index.go。

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// csafDoc 是 CSAF 2.0 文档中我们使用的部分。
//
// 只声明需要的字段：CSAF 完整模型很大（remediations、threats、scores…），
// 未使用的字段不声明就不会被解析，也不会因为上游加字段而崩。
type csafDoc struct {
	Document struct {
		Category          string `json:"category"`
		Title             string `json:"title"`
		AggregateSeverity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		Tracking struct {
			ID                 string `json:"id"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches      []csafBranch   `json:"branches"`
		Relationships []csafRelation `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []csafVuln `json:"vulnerabilities"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Product  *csafProduct `json:"product"`
	Branches []csafBranch `json:"branches"`
}

type csafProduct struct {
	Name                        string `json:"name"`
	ProductID                   string `json:"product_id"`
	ProductIdentificationHelper struct {
		CPE  string `json:"cpe"`
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafRelation struct {
	Category         string       `json:"category"`
	FullProductName  *csafProduct `json:"full_product_name"`
	ProductReference string       `json:"product_reference"`
	RelatesToProduct string       `json:"relates_to_product_reference"`
}

type csafVuln struct {
	CVE           string `json:"cve"`
	Title         string `json:"title"`
	ProductStatus struct {
		Fixed              []string `json:"fixed"`
		Recommended        []string `json:"recommended"`
		FirstFixed         []string `json:"first_fixed"`
		KnownAffected      []string `json:"known_affected"`
		KnownNotAffected   []string `json:"known_not_affected"`
		UnderInvestigation []string `json:"under_investigation"`
	} `json:"product_status"`
}

// csafComponent 是一个已解析出包坐标的产品条目。
type csafComponent struct {
	// ProductID 是 CSAF 里的产品标识（product_status 引用的就是它）。
	ProductID string
	// Name/Version/Arch 来自 purl，可能为空。
	Name    string
	Version string
	Arch    string
	// ProductName 是「这个组件属于哪个产品」，即发行版坐标的来源：
	// Red Hat 是 "Red Hat Enterprise Linux BaseOS (v. 10)"，
	// SUSE 是 "openSUSE Leap 16.0"。
	ProductName string
	// CPE 是产品级 CPE（Red Hat 有，SUSE 多数没有）。
	CPE string
}

// csafProfile 收敛厂商之间的语义差异。
type csafProfile interface {
	SourceID() domain.SourceID
	ParserVersion() string
	// MapProduct 把产品名/CPE 映射成发行版坐标。
	// ok=false 表示该产品不在支持范围内（例如 RHEL 6 ELS、SUSE HPC），
	// 这类记录应跳过而不是猜一个版本号塞进去。
	MapProduct(c csafComponent) (distro domain.DistroID, release, channel string, ok bool)
	// Severity 把厂商的严重度文本映射成统一枚举。
	Severity(text string) domain.Severity
	// AdvisoryURL 返回公告的人工查看地址。
	AdvisoryURL(advisoryID string) string
}

// parseCSAFDoc 解析单份 CSAF 文档。
func parseCSAFDoc(body []byte) (*csafDoc, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("feed: CSAF 文档为空")
	}
	// 深度防护必须在解码前做：深层嵌套的 JSON 会先把栈打穿再报错。
	if _, err := CheckJSONDepth(body, MaxJSONDepth); err != nil {
		return nil, err
	}
	var d csafDoc
	dec := json.NewDecoder(strings.NewReader(string(body)))
	// 上游存在非 UTF-8 字节（SUSE 文档里实测有 Latin-1 的乘号），
	// 用字符串转换走一遍能把非法字节替换为 U+FFFD 而不是整份拒绝。
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("feed: CSAF 文档解析失败: %w", err)
	}
	if d.Document.Tracking.ID == "" {
		return nil, fmt.Errorf("feed: CSAF 文档缺少 tracking.id")
	}
	return &d, nil
}

// components 把产品树展开成 ProductID → 包坐标 的索引。
//
// 两层映射都要建：
//   - 包级 product_version（Red Hat 与 SUSE 都有）
//   - relationship 的完整产品 ID（Red Hat 的 product_status 引用的是它，
//     形如 "BaseOS-10.1.Z:tar-2:1.35-9.el10_1.x86_64"）
//
// 漏掉后者会让 Red Hat 的 fixed 列表全部解析不出包，统计上表现为
// 「公告有、修复记录为零」，正好是最容易误读成「没漏洞」的形态。
func (d *csafDoc) components() map[string]csafComponent {
	byID := make(map[string]csafComponent, 256)
	var walk func(bs []csafBranch, productName, cpe string)
	walk = func(bs []csafBranch, productName, cpe string) {
		for _, b := range bs {
			name, curCPE := productName, cpe
			if b.Product != nil {
				if b.Product.ProductIdentificationHelper.CPE != "" {
					curCPE = b.Product.ProductIdentificationHelper.CPE
				}
				if b.Category == "product_name" || b.Category == "product_family" {
					name = b.Product.Name
					if name == "" {
						name = b.Name
					}
				}
				// 每个带 product_id 的产品都要登记，即使它没有 purl。
				//
				// 实测 Red Hat 的产品树是「兄弟」结构：product_name（带 CPE，
				// 是发行版坐标的唯一来源）与 architecture→product_version（带 purl，
				// 是包坐标）并列挂在 vendor 下，包并不是产品名的子节点。
				// 只登记带 purl 的叶子，relationship 就找不到产品，
				// 结果是「公告有、修复记录为零」——最容易被误读成没漏洞的形态。
				if b.Product.ProductID != "" {
					comp := csafComponent{
						ProductID:   b.Product.ProductID,
						ProductName: name,
						CPE:         curCPE,
					}
					applyPURL(&comp, b.Product.ProductIdentificationHelper.PURL)
					byID[comp.ProductID] = comp
				}
			}
			if len(b.Branches) > 0 {
				walk(b.Branches, name, curCPE)
			}
		}
	}
	walk(d.ProductTree.Branches, "", "")

	// 关系：component_of 把包级产品挂到产品线上。
	for _, r := range d.ProductTree.Relationships {
		comp, ok := byID[r.ProductReference]
		if !ok {
			// 关系引用了不存在的产品说明文档结构异常，跳过该关系即可：
			// 其余关系仍然可用，不能因此整份拒收。
			continue
		}
		if r.FullProductName != nil && r.FullProductName.ProductID != "" {
			rel := comp
			rel.ProductID = r.FullProductName.ProductID
			// relates_to 有两种写法：Red Hat 用品 ID（BaseOS-10.1.Z，
			// 对应带 CPE 的 product_name），SUSE 直接写产品名字符串
			// （"openSUSE Leap 16.0"，产品树里根本没有对应条目）。
			// 能查到就用查到的产品名与 CPE，查不到就原样保留字符串，
			// 由 profile 自己按名称解析。
			if r.RelatesToProduct != "" {
				rel.ProductName = r.RelatesToProduct
				if owner, ok := byID[r.RelatesToProduct]; ok {
					if owner.CPE != "" {
						rel.CPE = owner.CPE
					}
					if owner.ProductName != "" {
						rel.ProductName = owner.ProductName
					}
				}
			}
			byID[rel.ProductID] = rel
		}
	}
	return byID
}

// applyPURL 从 purl 中取出包名、版本与架构。
//
// 形如 pkg:rpm/redhat/tar@1.35-9.el10_1?arch=x86_64&epoch=2。
// 只处理 rpm 类型：CSAF 里出现的其他 type（oci、github）不是系统包，
// 解析出来也没有意义，宁可留空让上层跳过。
func applyPURL(c *csafComponent, purl string) {
	p := strings.TrimPrefix(purl, "pkg:")
	slash := strings.Index(p, "/")
	if slash < 0 {
		return
	}
	typ := p[:slash]
	rest := p[slash+1:]
	if typ != "rpm" && typ != "deb" && typ != "apk" {
		return
	}
	// 去掉 namespace（redhat/suse），包名在最后一个 / 之后。
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	query := ""
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	ver := ""
	if i := strings.Index(rest, "@"); i >= 0 {
		rest, ver = rest[:i], rest[i+1:]
	}
	c.Name = rest
	c.Version = ver
	for _, kv := range strings.Split(query, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch k {
		case "arch":
			c.Arch = v
		case "epoch":
			// epoch 独立给出时必须拼回版本号：rpm 的比较规则里
			// epoch 优先级最高，丢了它会把 1:1.0 与 1.0 判成相同。
			if v != "" && v != "0" && c.Version != "" && !strings.Contains(c.Version, ":") {
				c.Version = v + ":" + c.Version
			}
		}
	}
}

// parseCSAFDocument 把一份 CSAF 文档归一化为公告、修复与不受影响声明。
//
// 归类规则（与阶段 3.0 设计的证据分层一致）：
//
//	fixed / recommended / first_fixed → 修复记录（可严格比较，官方声明）
//	known_affected                    → 修复记录 + 空版本（确认受影响、无补丁）
//	known_not_affected                → 不受影响声明（只有它能推出 NOT_AFFECTED）
//	under_investigation               → 只留公告（厂商尚未判定，不得当结论）
func parseCSAFDocument(d *csafDoc, p csafProfile, in DocInput, res *ParseResult) int {
	comps := d.components()
	advisoryID := d.Document.Tracking.ID
	sev := p.Severity(d.Document.AggregateSeverity.Text)
	url := p.AdvisoryURL(advisoryID)
	produced := 0

	// CVE 顺序必须稳定：JSON 数组顺序是上游给的，但同一份文档被解析两次
	// 可能顺序不同（不同版本），排序后快照内容哈希才可比。
	vulns := append([]csafVuln(nil), d.Vulnerabilities...)
	sort.SliceStable(vulns, func(i, j int) bool { return vulns[i].CVE < vulns[j].CVE })

	for _, v := range vulns {
		cve := domain.CVEID(v.CVE)
		if !cve.Valid() {
			res.Skipped++
			res.warn("%s 下的非法 CVE 编号: %q", advisoryID, v.CVE)
			continue
		}

		status := csafVendorStatus(v)
		uid := domain.AdvisoryUID(p.SourceID(), advisoryID, cve)
		res.Advisories = append(res.Advisories, domain.Advisory{
			UID:            uid,
			SourceID:       p.SourceID(),
			AdvisoryID:     advisoryID,
			CVEID:          cve,
			Title:          strings.TrimSpace(v.Title),
			Severity:       sev,
			SeveritySource: csafSeveritySource(p.SourceID()),
			URL:            url,
			FetchedAt:      in.FetchedAt,
			ArtifactSHA256: in.ArtifactSHA,
			RawLocator:     fmt.Sprintf("vulnerabilities[cve=%s]", v.CVE),
			RawRecordHash:  HashBytes([]byte(v.CVE + "\x1f" + status)),
			ParserVersion:  p.ParserVersion(),
			VendorStatus:   status,
		})
		produced++

		seen := map[string]bool{}
		var cands []csafFixCandidate
		addFix := func(ids []string, fixed bool) {
			for _, id := range ids {
				comp, ok := comps[id]
				if !ok {
					res.BridgeFailed++
					continue
				}
				distro, release, channel, ok := p.MapProduct(comp)
				if !ok {
					// 不在支持范围（RHEL 6 ELS、SUSE HPC 等）：
					// 记事实但不猜坐标，也不算异常。
					continue
				}
				if comp.Name == "" {
					res.BridgeFailed++
					continue
				}
				key := string(distro) + "\x1f" + release + "\x1f" + channel + "\x1f" +
					comp.Name + "\x1f" + comp.Arch + "\x1f" + comp.Version
				if seen[key] {
					continue
				}
				seen[key] = true

				arch := comp.Arch
				if arch == "" || arch == "src" {
					arch = domain.ArchAny
				}
				// fixed 但 purl 没给版本：这是数据缺口，不是「无补丁」，
				// 版本留空，报告里以覆盖不足呈现。
				cands = append(cands, csafFixCandidate{
					distro: distro, release: release, channel: channel,
					name: comp.Name, version: comp.Version, arch: arch,
				})
			}
		}

		addFix(v.ProductStatus.Fixed, true)
		addFix(v.ProductStatus.Recommended, true)
		addFix(v.ProductStatus.FirstFixed, true)
		addFix(v.ProductStatus.KnownAffected, false)

		collapsed := csafCollapseFixes(cands)
		for _, c := range collapsed {
			res.Fixes = append(res.Fixes, domain.AdvisoryFix{
				AdvisoryUID: uid,
				SourceID:    p.SourceID(),
				AdvisoryID:  advisoryID,
				CVEID:       cve,
				DistroID:    c.distro,
				Release:     c.release,
				Channel:     c.channel,
				Ref: domain.PackageRef{
					Kind: domain.PackageKindBinary,
					Name: c.name,
					Arch: c.arch,
				},
				FixedVersion:       c.version,
				FixedVersionSource: domain.FixVersionOfficial,
				EvidenceURL:        url,
			})
			produced++
		}

		for _, id := range v.ProductStatus.KnownNotAffected {
			comp, ok := comps[id]
			if !ok {
				res.BridgeFailed++
				continue
			}
			distro, release, _, ok := p.MapProduct(comp)
			if !ok || comp.Name == "" {
				continue
			}
			arch := comp.Arch
			if arch == "" || arch == "src" || arch == "noarch" {
				arch = domain.ArchAny
			}
			res.NotAffected = append(res.NotAffected, domain.NotAffected{
				SourceID:    p.SourceID(),
				AdvisoryID:  advisoryID,
				CVEID:       cve,
				DistroID:    distro,
				Release:     release,
				Ref:         domain.PackageRef{Kind: domain.PackageKindBinary, Name: comp.Name, Arch: arch},
				Reason:      domain.NotAffectedDeclared,
				EvidenceURL: url,
			})
			produced++
		}

		// 记录涉及到的 release 坐标，供 distro_releases 登记。
		for _, id := range append(append(append([]string{},
			v.ProductStatus.Fixed...), v.ProductStatus.Recommended...),
			v.ProductStatus.KnownAffected...) {
			comp, ok := comps[id]
			if !ok {
				continue
			}
			if distro, release, _, ok := p.MapProduct(comp); ok {
				res.mergeRelease(distro, release)
			}
		}
	}
	return produced
}

// csafVendorStatus 把产品状态压缩成一个字符串，逐字保留厂商给出的语义。
func csafVendorStatus(v csafVuln) string {
	switch {
	case len(v.ProductStatus.Fixed) > 0:
		return "fixed"
	case len(v.ProductStatus.Recommended) > 0:
		return "recommended"
	case len(v.ProductStatus.FirstFixed) > 0:
		return "first_fixed"
	case len(v.ProductStatus.KnownAffected) > 0:
		return "known_affected"
	case len(v.ProductStatus.KnownNotAffected) > 0:
		return "known_not_affected"
	case len(v.ProductStatus.UnderInvestigation) > 0:
		return "under_investigation"
	default:
		return ""
	}
}

// mergeRelease 去重登记 release 坐标。
func (r *ParseResult) mergeRelease(distro domain.DistroID, release string) {
	for _, x := range r.Releases {
		if x.DistroID == distro && x.Release == release {
			return
		}
	}
	r.Releases = append(r.Releases, ReleaseRef{DistroID: distro, Release: release})
}

func csafSeveritySource(id domain.SourceID) string {
	switch id {
	case domain.SourceRHELCSAF:
		return "redhat-csaf"
	case domain.SourceSUSECSAF:
		return "suse-csaf"
	default:
		return "csaf"
	}
}

// csafFixCandidate 是一条尚未合并架构的修复候选。
type csafFixCandidate struct {
	distro  domain.DistroID
	release string
	channel string
	name    string
	version string
	arch    string
}

// csafCollapseFixes 把「同包同版本的多架构条目」合并成一条 any 记录。
//
// 为什么必须合并：一份 RHSA 会把同一个包在 aarch64/ppc64le/s390x/x86_64
// 各列一遍，实测一份 10,409 份文档（仅 2026 年）就产出 175 万条修复记录，
// 其中四分之三是同一个事实的架构副本。合并后行数降到约四分之一，
// 查询与磁盘都可控；而架构语义没有丢失——
//
//   - 同一包在支持架构上版本一致 → 记 any（对所有架构生效）
//   - 版本随架构不同 → 保留各自的架构，不做 any 通配
//
// 这条规则只在「版本完全一致」时合并，因此不会把某架构的修复
// 错误地套到另一个架构上。
func csafCollapseFixes(in []csafFixCandidate) []csafFixCandidate {
	if len(in) <= 1 {
		return in
	}
	type groupKey struct {
		distro  domain.DistroID
		release string
		channel string
		name    string
	}
	// 先按「包」分组，看同一包有几个不同版本。
	versions := map[groupKey]map[string]bool{}
	for _, c := range in {
		k := groupKey{c.distro, c.release, c.channel, c.name}
		if versions[k] == nil {
			versions[k] = map[string]bool{}
		}
		versions[k][c.version] = true
	}

	out := make([]csafFixCandidate, 0, len(in))
	emitted := map[string]bool{}
	for _, c := range in {
		k := groupKey{c.distro, c.release, c.channel, c.name}
		arch := c.arch
		if len(versions[k]) == 1 {
			arch = domain.ArchAny
		}
		key := string(c.distro) + "\x1f" + c.release + "\x1f" + c.channel + "\x1f" +
			c.name + "\x1f" + c.version + "\x1f" + arch
		if emitted[key] {
			continue
		}
		emitted[key] = true
		c.arch = arch
		out = append(out, c)
	}
	return out
}
