package feed

import (
	"fmt"
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// 各源端点，2026-11-24 逐个实测确认（HTTP 206/200，字节可读）。
// 记录在此而不是散落在解析器里，便于一次性核对与轮换影响面。
const (
	// URLDebianTracker 是 Debian Security Tracker 全量 JSON（约 90MB，无 ETag）。
	URLDebianTracker = "https://security-tracker.debian.org/tracker/data/json"

	// URLUbuntuOVALTemplate 按 codename 分文件，不是版本号：
	// com.ubuntu.noble.cve.oval.xml.bz2，不是 com.ubuntu.24.04.*。
	URLUbuntuOVALTemplate = "https://security-metadata.canonical.com/oval/com.ubuntu.%s.cve.oval.xml.bz2"

	// URLRedHatCSAFBase 是 CSAF 根，其下 advisories/<year>/ 与 vex/<year>/。
	URLRedHatCSAFBase = "https://security.access.redhat.com/data/csaf/v2"

	// URLRedHatProviderMetadata 是 CSAF 2.0 标准信任锚，声明 PGP 指纹。
	URLRedHatProviderMetadata = URLRedHatCSAFBase + "/provider-metadata.json"

	// FingerprintRedHat 是 provider-metadata.json 声明的公钥指纹，固化在此。
	// 指纹不符必须拒绝并告警，不得静默换钥。
	FingerprintRedHat = "77E79ABE93673533ED09EBE2DCE3823597F5EAC4"

	// URLSUSECSAFBase 是 SUSE CSAF 根，其下有 <year>/ 与 csaf-vex/<year>/。
	URLSUSECSAFBase = "https://ftp.suse.com/pub/projects/security/csaf"

	// URLSUSEPublicKey 是 SUSE 官方目录内声明的公钥文件（无 provider-metadata.json）。
	URLSUSEPublicKey = "https://ftp.suse.com/pub/projects/security/keys/security-automation.asc"

	// FingerprintSUSE 是 security-automation.asc 的主密钥指纹。
	// 2026-11-24 用该公钥实际校验 opensuse-su-2026_21889-1.json.asc 通过后固化。
	// SUSE 不提供 provider-metadata.json，指纹只能如此确定；
	// 换钥时必须同步修改这里，否则所有文档会以「指纹不符」失败——这是预期行为。
	FingerprintSUSE = "6B62473BD771517D41E684DFD4439E7EC133994D"

	// URLRedHatCSAFFeed 按文档发布的公告目录（每份 RHSA 一个 JSON + .asc）。
	//
	// 为什么不用 vex：实测单份 VEX 文档 16.8MB（把全部产品线塞进 product_tree），
	// 共 78,041 份，既下载不动也存不下；而扫描需要的「修复版本」事实
	// 恰好来自 RHSA，VEX 的价值（known_not_affected）在 RHSA 里同样有。
	URLRedHatCSAFFeed  = URLRedHatCSAFBase + "/advisories"
	URLRedHatCSAFIndex = URLRedHatCSAFFeed + "/changes.csv"
	URLRedHatCSAFKey   = "https://security.access.redhat.com/data/97f5eac4.txt"

	// URLSUSECSAFIndex 是 SUSE 的变更清单。
	URLSUSECSAFIndex = URLSUSECSAFBase + "/changes.csv"

	// URLAlpineSecDBTemplate 按 release 与仓库分文件：v3.20/main.json。
	//
	// 模板含两个占位符，顺序固定为 release、仓库，由 Source.URLForRepo 展开。
	URLAlpineSecDBTemplate = "https://secdb.alpinelinux.org/v%s/%s.json"

	// URLArchTracker 是 Arch 全量追踪数据（单个 JSON，无 ETag）。
	//
	// 2026-11-24 实测：/all.json 返回 308 永久重定向到 /issues/all.json。
	// 直接固化最终地址，避免每次抓取都多一跳，也避免重定向目标再次变化时
	// 静默把 HTML 错误页当数据（旧地址目前返回的是 279 字节的重定向页）。
	URLArchTracker = "https://security.archlinux.org/issues/all.json"
)

// 解析器版本：格式或字段映射变化时递增，便于判断是否需要重建归一化数据。
const (
	ParserVersionDebian = "debian-tracker/1"
	ParserVersionUbuntu = "ubuntu-oval/1"
	ParserVersionRedHat = "rhel-csaf/1"
	ParserVersionSUSE   = "suse-csaf/1"
	ParserVersionAlpine = "alpine-secdb/1"
	ParserVersionArch   = "arch-tracker/1"
)

// Sources 返回六个官方数据源的静态配置。
//
// 顺序即设计确定的实施顺序：先易后难（Alpine → Arch → Debian → Ubuntu →
// Red Hat → SUSE），便于逐个落地真实样本验证。
func Sources() []Source {
	return []Source{
		{
			ID:            domain.SourceAlpineSecDB,
			Name:          "Alpine secdb",
			Kind:          "secdb",
			URL:           URLAlpineSecDBTemplate,
			TrustLevel:    domain.TrustLevelB,
			SignatureKind: "none",
			ParserVersion: ParserVersionAlpine,
			MaxBytes:      DefaultMaxBytes,
			NeedRelease:   true,
		},
		{
			ID:            domain.SourceArchTracker,
			Name:          "Arch Security Tracker",
			Kind:          "tracker",
			URL:           URLArchTracker,
			TrustLevel:    domain.TrustLevelB,
			SignatureKind: "none",
			ParserVersion: ParserVersionArch,
			MaxBytes:      DefaultMaxBytes,
		},
		{
			ID:            domain.SourceDebianTracker,
			Name:          "Debian Security Tracker",
			Kind:          "tracker",
			URL:           URLDebianTracker,
			TrustLevel:    domain.TrustLevelB,
			SignatureKind: "none",
			ParserVersion: ParserVersionDebian,
			MaxBytes:      DebianMaxBytes,
		},
		{
			ID:            domain.SourceUbuntuOVAL,
			Name:          "Ubuntu OVAL",
			Kind:          "oval",
			URL:           URLUbuntuOVALTemplate,
			TrustLevel:    domain.TrustLevelB,
			SignatureKind: "none",
			ParserVersion: ParserVersionUbuntu,
			MaxBytes:      DefaultMaxBytes,
			NeedRelease:   true,
			Archive:       true,
		},
		{
			ID:            domain.SourceRHELCSAF,
			Name:          "Red Hat CSAF",
			Kind:          "csaf",
			URL:           URLRedHatCSAFFeed,
			IndexURL:      URLRedHatCSAFIndex,
			KeyURL:        URLRedHatCSAFKey,
			DocumentSet:   true,
			TrustLevel:    domain.TrustLevelA,
			SignatureKind: "gpg",
			PublicKeyFP:   FingerprintRedHat,
			ParserVersion: ParserVersionRedHat,
			MaxBytes:      DefaultMaxBytes,
		},
		{
			ID:            domain.SourceSUSECSAF,
			Name:          "SUSE CSAF",
			Kind:          "csaf",
			URL:           URLSUSECSAFBase,
			IndexURL:      URLSUSECSAFIndex,
			KeyURL:        URLSUSEPublicKey,
			DocumentSet:   true,
			TrustLevel:    domain.TrustLevelA,
			SignatureKind: "gpg",
			PublicKeyFP:   FingerprintSUSE,
			ParserVersion: ParserVersionSUSE,
			MaxBytes:      DefaultMaxBytes,
		},
	}
}

// ParserReason 按源 ID 判断解析器是否就绪，返回为空表示就绪。
//
// feed status 只需要「能不能解析」，不需要解析器实例；
// 单独提供这个入口，避免调用方为了一个判断去关心两种解析器接口。
func ParserReason(id domain.SourceID) (Source, string) {
	src, ok := SourceByID(id)
	if !ok {
		return Source{}, "未知情报源"
	}
	_, reason := ParserReady(src)
	return src, reason
}

// SourceByID 按 ID 查找源配置。
func SourceByID(id domain.SourceID) (Source, bool) {
	for _, s := range Sources() {
		if s.ID == id {
			return s, true
		}
	}
	return Source{}, false
}

// RedHatAdvisoryURL 返回某个 RHSA 公告的 JSON 地址。
func RedHatAdvisoryURL(year int, seq string) string {
	return fmt.Sprintf("%s/advisories/%d/%s.json", URLRedHatCSAFBase, year, strings.ToLower(seq))
}

// RedHatVEXURL 返回某条 CVE 的 VEX 地址。
// 文件名是 cve-YYYY-NNNN.json，年份取自 CVE 编号本身，不取当前年份。
func RedHatVEXURL(cve domain.CVEID) (string, error) {
	year, ok := cve.Year()
	if !ok {
		return "", fmt.Errorf("feed: CVE 编号无法解析年份: %q", cve)
	}
	return fmt.Sprintf("%s/vex/%d/cve-%s.json", URLRedHatCSAFBase, year, cve.String()[4:]), nil
}

// SUSEAdvisoryURL 返回 SUSE 公告 JSON 地址。
func SUSEAdvisoryURL(year int, name string) string {
	return fmt.Sprintf("%s/%d/%s.json", URLSUSECSAFBase, year, strings.ToLower(name))
}

// SUSEVEXURL 返回 SUSE CSAF VEX 地址。
func SUSEVEXURL(year int, name string) string {
	return fmt.Sprintf("%s/csaf-vex/%d/%s.json", URLSUSECSAFBase, year, strings.ToLower(name))
}

// AlpineSecDBURL 返回 Alpine 某 release 某仓库的 secdb 地址。
// repo 取 main 或 community。
func AlpineSecDBURL(release, repo string) (string, error) {
	switch repo {
	case "main", "community":
	default:
		return "", fmt.Errorf("feed: Alpine 仓库只能是 main 或 community，收到 %q", repo)
	}
	return fmt.Sprintf(URLAlpineSecDBTemplate, release, repo), nil
}
