package feed

// SUSE CSAF 的厂商侧映射。
//
// 实测（2026-11-24）：
//   - 目录 https://ftp.suse.com/pub/projects/security/csaf/ 下只有 changes.csv、
//     deletions.csv、index.txt 与按年份分目录，**没有 provider-metadata.json**，
//     所以指纹不能像 Red Hat 那样自动声明，只能从官方公钥文件
//     keys/security-automation.asc 现场算出并固化。
//   - 文档带 .asc 与 .sha256；签名者指纹
//     6B62473BD771517D41E684DFD4439E7EC133994D（2026-11-24 校验通过）。
//   - 关键字段与 Red Hat 不同：修复状态用 product_status.**recommended**，
//     发行版坐标既不在 CPE 里也不在 purl 里，而在 relationship 的
//     relates_to_product_reference 字符串中（如 "openSUSE Leap 16.0"）。
//   - 文档里存在非 UTF-8 字节（Latin-1 的乘号 "×"），直接按 UTF-8 解码会失败。

import (
	"regexp"
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// SUSEParser 解析 SUSE/openSUSE CSAF 安全公告。
type SUSEParser struct{}

// SourceID 实现 DocumentParser。
func (SUSEParser) SourceID() domain.SourceID { return domain.SourceSUSECSAF }

// Version 实现 DocumentParser。
func (SUSEParser) Version() string { return ParserVersionSUSE }

// ParserVersion 实现 csafProfile。
func (SUSEParser) ParserVersion() string { return ParserVersionSUSE }

// ParseDocument 实现 DocumentParser。
func (p SUSEParser) ParseDocument(in DocInput) (*ParseResult, error) {
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
// SUSE 的产品标识是自由文本，没有可依赖的 CPE，因此按名称匹配。
// 只认支持矩阵里登记过的产品线；其余（HPC、Real Time、Manager 等）
// 一律 ok=false，不猜坐标。
func (SUSEParser) MapProduct(c csafComponent) (domain.DistroID, string, string, bool) {
	name := c.ProductName
	if name == "" {
		name = c.Name
	}
	lower := strings.ToLower(name)

	switch {
	case strings.Contains(lower, "opensuse leap"):
		if v := leapVersion(name); v != "" {
			return domain.DistroOpenSUSE, v, "oss", true
		}
		return "", "", "", false
	case strings.Contains(lower, "suse linux enterprise server"),
		strings.Contains(lower, "sles"):
		if v := slesVersion(name); v != "" {
			return domain.DistroSLES, v, "sle", true
		}
		return "", "", "", false
	default:
		return "", "", "", false
	}
}

// Severity 实现 csafProfile。SUSE 用 aggregate_severity.text：critical/important/moderate/low。
func (SUSEParser) Severity(text string) domain.Severity {
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
func (SUSEParser) AdvisoryURL(id string) string {
	// openSUSE-SU-2026:21889-1 → /update/announcement/21889/
	if i := strings.LastIndex(id, ":"); i >= 0 {
		rest := id[i+1:]
		if j := strings.Index(rest, "-"); j > 0 {
			rest = rest[:j]
		}
		return "https://www.suse.com/support/update/announcement/" + rest + "/"
	}
	return "https://www.suse.com/security/cve/"
}

var leapVer = regexp.MustCompile(`(?i)leap\s+(\d+(?:\.\d+)?)`)

// leapVersion 从 "openSUSE Leap 16.0" 取 "16.0"。
func leapVersion(name string) string {
	if m := leapVer.FindStringSubmatch(name); len(m) > 1 {
		return m[1]
	}
	return ""
}

var slesSP = regexp.MustCompile(`(?i)\b(\d{2})\s*(?:sp|service pack)\s*(\d+)`)
var slesPlain = regexp.MustCompile(`(?i)server\s+(\d{2})(?:\.(\d+))?`)

// slesVersion 把 SLES 的产品名映射成 "15.6" 形式。
//
// SLES 同时用两套写法："SUSE Linux Enterprise Server 15 SP6" 与
// "SUSE Linux Enterprise Server 15.6"，两者是同一个版本，
// 必须归一，否则同一台机器会同时命中两个 release 坐标。
func slesVersion(name string) string {
	if m := slesSP.FindStringSubmatch(name); len(m) > 2 {
		return m[1] + "." + m[2]
	}
	if m := slesPlain.FindStringSubmatch(name); len(m) > 1 {
		if len(m) > 2 && m[2] != "" {
			return m[1] + "." + m[2]
		}
		return m[1]
	}
	return ""
}

var _ DocumentParser = SUSEParser{}
var _ csafProfile = SUSEParser{}
