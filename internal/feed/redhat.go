package feed

// Red Hat CSAF 的厂商侧映射。
//
// 实测（2026-11-24）：advisories/changes.csv 列出 32,407 份公告，
// 目录 csaf/v2/advisories/<year>/rhsa-<year>_<n>.json，每份 20~100KB，
// 同目录下有对应的 .asc 分离签名，签名者指纹
// 77E79ABE93673533ED09EBE2DCE3823597F5EAC4（provider-metadata.json 声明）。
//
// 为什么用 advisories 而不是 vex：VEX 文档按单个 CVE 发布，实测一份
// 16.8MB（把全部产品线都塞进 product_tree），78,041 份既下载不动也存不下；
// 而扫描需要的「修复版本」事实恰好来自 RHSA。VEX 的
// known_not_affected 语义由 RHSA 的同类字段覆盖，不额外抓取。

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// RedHatParser 解析 Red Hat CSAF 安全公告（csaf_security_advisory）。
type RedHatParser struct{}

// SourceID 实现 DocumentParser。
func (RedHatParser) SourceID() domain.SourceID { return domain.SourceRHELCSAF }

// Version 实现 DocumentParser。
func (RedHatParser) Version() string { return ParserVersionRedHat }

// ParserVersion 实现 csafProfile。
func (RedHatParser) ParserVersion() string { return ParserVersionRedHat }

// ParseDocument 实现 DocumentParser。
func (p RedHatParser) ParseDocument(in DocInput) (*ParseResult, error) {
	d, err := parseCSAFDoc(in.Body)
	if err != nil {
		return nil, err
	}
	res := &ParseResult{}
	parseCSAFDocument(d, p, in, res)
	return res, nil
}

// MapProduct 实现 csafProfile。
//
// 优先级：CPE（最可靠）→ 产品名里的 "(v. N)" → 产品名中的发行版字样。
// 解析不出来就返回 ok=false：RHEL 6/7 ELS 与 HPC 等不在支持矩阵内，
// 猜一个版本号塞进去会让「旧系统」看起来被新版情报覆盖。
func (RedHatParser) MapProduct(c csafComponent) (domain.DistroID, string, string, bool) {
	channel := redHatChannel(c.ProductName)
	if rel, ok := redHatReleaseFromCPE(c.CPE); ok {
		return domain.DistroRHEL, rel, channel, true
	}
	if rel, ok := redHatReleaseFromName(c.ProductName); ok {
		return domain.DistroRHEL, rel, channel, true
	}
	return "", "", "", false
}

// Severity 实现 csafProfile。
// Red Hat 的四档：Critical / Important / Moderate / Low。
func (RedHatParser) Severity(text string) domain.Severity {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "critical":
		return domain.SeverityCritical
	case "important", "high":
		return domain.SeverityHigh
	case "moderate", "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	case "none":
		return domain.SeverityNone
	default:
		return domain.SeverityUnknown
	}
}

// AdvisoryURL 实现 csafProfile。
func (RedHatParser) AdvisoryURL(id string) string {
	return "https://access.redhat.com/errata/" + id
}

// redHatReleaseFromCPE 从 cpe:/o:redhat:enterprise_linux:9.4 取主版本。
//
// 只取主版本：RHEL 的补丁流（9.4、9.5…）共用同一套软件源，
// 而支持矩阵按主版本登记生命周期；按次版本登记会让 9.4 的机器
// 在 9.5 发布后立刻掉进「未登记 release」的 UNKNOWN 分支。
func redHatReleaseFromCPE(cpe string) (string, bool) {
	if !strings.Contains(cpe, ":redhat:enterprise_linux:") {
		return "", false
	}
	parts := strings.Split(cpe, ":")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "enterprise_linux" {
			if major := majorOfVersion(parts[i+1]); major != "" {
				return major, true
			}
		}
	}
	return "", false
}

var rhelNameVer = regexp.MustCompile(`\(v\.?\s*(\d+)`)

// redHatReleaseFromName 从 "Red Hat Enterprise Linux BaseOS (v. 10)" 取主版本。
func redHatReleaseFromName(name string) (string, bool) {
	m := rhelNameVer.FindStringSubmatch(name)
	if len(m) < 2 {
		return "", false
	}
	if _, err := strconv.Atoi(m[1]); err != nil {
		return "", false
	}
	return m[1], true
}

// redHatChannel 从产品名推断渠道。
//
// BaseOS 与 AppStream 的修复节奏不同：同一个包可能只在 AppStream 更新。
// 渠道不可知时用 rhel 兜底，而不是留空——空渠道会让修复记录校验失败。
func redHatChannel(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "baseos"):
		return "baseos"
	case strings.Contains(n, "appstream"):
		return "appstream"
	case strings.Contains(n, "codeready"), strings.Contains(n, "crb"):
		return "crb"
	case strings.Contains(n, "supplementary"):
		return "supplementary"
	default:
		return "rhel"
	}
}

// majorOfVersion 取版本号的主数字段，"10.1" → "10"，非数字返回空。
func majorOfVersion(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, ".-+~"); i > 0 {
		v = v[:i]
	}
	if v == "" {
		return ""
	}
	for _, r := range v {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return v
}

// 编译期断言：RedHatParser 必须同时满足两个接口。
var _ DocumentParser = RedHatParser{}
var _ csafProfile = RedHatParser{}

// debugRedHat 便于排查产品映射问题时不引入额外依赖。
func debugRedHat(c csafComponent) string {
	return fmt.Sprintf("product=%q cpe=%q purl-name=%q purl-ver=%q",
		c.ProductName, c.CPE, c.Name, c.Version)
}
