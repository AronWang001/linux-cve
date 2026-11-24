package feed

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// ---------------- purl 解析 ----------------

func TestApplyPURL(t *testing.T) {
	cases := []struct {
		name, purl, wantName, wantVer, wantArch string
	}{
		{
			name:     "redhat 带 arch 与 epoch",
			purl:     "pkg:rpm/redhat/tar@1.35-9.el10_1?arch=x86_64&epoch=2",
			wantName: "tar", wantVer: "2:1.35-9.el10_1", wantArch: "x86_64",
		},
		{
			name:     "suse 无 epoch",
			purl:     "pkg:rpm/suse/libheif-aom@1.23.4-160000.1.1?arch=aarch64",
			wantName: "libheif-aom", wantVer: "1.23.4-160000.1.1", wantArch: "aarch64",
		},
		{
			// epoch=0 不应写进版本号：rpm 里 0:1.0 与 1.0 等价，
			// 拼上去只会让字符串比对变复杂。
			name:     "epoch 为 0 不拼",
			purl:     "pkg:rpm/redhat/bash@5.1.8-6.el9?arch=src&epoch=0",
			wantName: "bash", wantVer: "5.1.8-6.el9", wantArch: "src",
		},
		{
			// 非 rpm/deb/apk 的 purl（oci、github）不是系统包，
			// 解析出来会污染包名前缀，宁可留空。
			name:     "oci 忽略",
			purl:     "pkg:oci/ubi9@sha256:abc?arch=amd64",
			wantName: "", wantVer: "", wantArch: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var comp csafComponent
			applyPURL(&comp, c.purl)
			if comp.Name != c.wantName || comp.Version != c.wantVer || comp.Arch != c.wantArch {
				t.Errorf("applyPURL(%q) = (%q,%q,%q)，期望 (%q,%q,%q)",
					c.purl, comp.Name, comp.Version, comp.Arch,
					c.wantName, c.wantVer, c.wantArch)
			}
		})
	}
}

// ---------------- Red Hat 文档 ----------------

// redHatFixture 复刻实测的 RHSA 结构，两个关键点必须与真实文档一致：
//
//  1. product_name（带 CPE，发行版坐标的唯一来源）与
//     architecture→product_version（带 purl，包坐标）是 **兄弟** 分支，
//     包并不是产品名的子节点；
//  2. product_status.fixed 引用的是 relationship 的完整产品 ID，
//     而不是包级 product_id。
//
// 把这两点写错（例如让 product_name 当父节点），单测会全绿而真实数据
// 一条修复记录也产不出来——这正是第一版实现的真实故障。
const redHatFixture = `{
  "document": {
    "category": "csaf_security_advisory",
    "aggregate_severity": {"text": "Important"},
    "tracking": {"id": "RHSA-2026:0002", "current_release_date": "2026-01-02T00:00:00Z"}
  },
  "product_tree": {
    "branches": [
      {"category": "vendor", "name": "Red Hat", "branches": [
        {"category": "product_family", "name": "Red Hat Enterprise Linux", "branches": [
          {"category": "product_name", "name": "Red Hat Enterprise Linux BaseOS (v. 9)",
           "product": {"name": "Red Hat Enterprise Linux BaseOS (v. 9)", "product_id": "BaseOS-9.6.Z",
                       "product_identification_helper": {"cpe": "cpe:/o:redhat:enterprise_linux:9.6"}}}
        ]},
        {"category": "architecture", "name": "x86_64", "branches": [
          {"category": "product_version", "name": "tar-2:1.35-1.el9_6.x86_64",
           "product": {"name": "tar-2:1.35-1.el9_6.x86_64", "product_id": "tar-2:1.35-1.el9_6.x86_64",
                       "product_identification_helper": {"purl": "pkg:rpm/redhat/tar@1.35-1.el9_6?arch=x86_64&epoch=2"}}}
        ]}
      ]}
    ],
    "relationships": [
      {"category": "default_component_of",
       "full_product_name": {"name": "tar as a component of RHEL 9", "product_id": "BaseOS-9.6.Z:tar-2:1.35-1.el9_6.x86_64"},
       "product_reference": "tar-2:1.35-1.el9_6.x86_64",
       "relates_to_product_reference": "BaseOS-9.6.Z"}
    ]
  },
  "vulnerabilities": [
    {"cve": "CVE-2026-1000", "title": "tar: path traversal",
     "product_status": {"fixed": ["BaseOS-9.6.Z:tar-2:1.35-1.el9_6.x86_64"]}}
  ]
}`

func TestRedHatParseDocument(t *testing.T) {
	in := DocInput{
		Source:      mustSource(t, domain.SourceRHELCSAF),
		Path:        "2026/rhsa-2026_0002.json",
		ArtifactSHA: HashBytes([]byte(redHatFixture)),
		Body:        []byte(redHatFixture),
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	res, err := RedHatParser{}.ParseDocument(in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Advisories) != 1 {
		t.Fatalf("应产出 1 条公告，实际 %d", len(res.Advisories))
	}
	a := res.Advisories[0]
	if a.AdvisoryID != "RHSA-2026:0002" || a.CVEID != "CVE-2026-1000" {
		t.Errorf("公告标识错误: %s / %s", a.AdvisoryID, a.CVEID)
	}
	if a.Severity != domain.SeverityHigh {
		t.Errorf("Important 应映射为 high，实际 %s", a.Severity)
	}
	if a.VendorStatus != "fixed" {
		t.Errorf("vendor_status 应为 fixed，实际 %q", a.VendorStatus)
	}

	// 修复记录必须来自 relationship 引用的完整产品 ID：
	// 只认包级 product_id 的实现会在这里产出零条，
	// 而这正是「公告有、修复为零」这一最危险形态的来源。
	if len(res.Fixes) != 1 {
		t.Fatalf("应产出 1 条修复记录，实际 %d", len(res.Fixes))
	}
	f := res.Fixes[0]
	if f.DistroID != domain.DistroRHEL || f.Release != "9" {
		t.Errorf("发行版坐标应为 rhel/9，实际 %s/%s", f.DistroID, f.Release)
	}
	if f.Ref.Name != "tar" || f.FixedVersion != "2:1.35-1.el9_6" {
		t.Errorf("包名或修复版本错误: %q / %q", f.Ref.Name, f.FixedVersion)
	}
	if f.Channel != "baseos" {
		t.Errorf("BaseOS 产品应映射到 baseos 渠道，实际 %q", f.Channel)
	}
	if f.Ref.Arch != "x86_64" {
		t.Errorf("架构应保留 purl 的 x86_64，实际 %q", f.Ref.Arch)
	}
	if len(res.Releases) != 1 || res.Releases[0].Release != "9" {
		t.Errorf("release 坐标错误: %+v", res.Releases)
	}
}

// ---------------- SUSE 文档 ----------------

// suseFixture 复刻实测结构：修复状态用 recommended，
// 发行版坐标只存在于 relationship 的 relates_to 字符串里。
const suseFixture = `{
  "document": {
    "category": "csaf_security_advisory",
    "aggregate_severity": {"text": "important"},
    "tracking": {"id": "openSUSE-SU-2026:21889-1"}
  },
  "product_tree": {
    "branches": [
      {"category": "vendor", "name": "SUSE", "branches": [
        {"category": "architecture", "name": "x86_64", "branches": [
          {"category": "product_version", "name": "libheif-aom-0:1.23.4-160000.1.1.x86_64",
           "product": {"name": "libheif-aom-0:1.23.4-160000.1.1.x86_64",
                       "product_id": "libheif-aom-0:1.23.4-160000.1.1.x86_64",
                       "product_identification_helper": {"purl": "pkg:rpm/suse/libheif-aom@1.23.4-160000.1.1?arch=x86_64"}}}
        ]}
      ]}
    ],
    "relationships": [
      {"category": "default_component_of",
       "full_product_name": {"name": "libheif-aom as component of openSUSE Leap 16.0",
                             "product_id": "openSUSE Leap 16.0:libheif-aom-0:1.23.4-160000.1.1.x86_64"},
       "product_reference": "libheif-aom-0:1.23.4-160000.1.1.x86_64",
       "relates_to_product_reference": "openSUSE Leap 16.0"}
    ]
  },
  "vulnerabilities": [
    {"cve": "CVE-2026-84383", "title": "Heap buffer overflow",
     "product_status": {"recommended": ["openSUSE Leap 16.0:libheif-aom-0:1.23.4-160000.1.1.x86_64"]}}
  ]
}`

func TestSUSEParseDocument(t *testing.T) {
	in := DocInput{
		Source:      mustSource(t, domain.SourceSUSECSAF),
		Path:        "2026/opensuse-su-2026_21889-1.json",
		ArtifactSHA: HashBytes([]byte(suseFixture)),
		Body:        []byte(suseFixture),
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	res, err := SUSEParser{}.ParseDocument(in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Advisories) != 1 {
		t.Fatalf("应产出 1 条公告，实际 %d", len(res.Advisories))
	}
	if got := res.Advisories[0].VendorStatus; got != "recommended" {
		t.Errorf("SUSE 用 recommended 表达已修复，vendor_status 应逐字保留，实际 %q", got)
	}
	// recommended 必须当成修复记录产出：漏了它，SUSE 的「已修复」全部消失。
	if len(res.Fixes) != 1 {
		t.Fatalf("recommended 应产出 1 条修复记录，实际 %d", len(res.Fixes))
	}
	f := res.Fixes[0]
	if f.DistroID != domain.DistroOpenSUSE || f.Release != "16.0" {
		t.Errorf("发行版坐标应为 opensuse-leap/16.0，实际 %s/%s", f.DistroID, f.Release)
	}
	if f.FixedVersion != "1.23.4-160000.1.1" {
		t.Errorf("修复版本错误: %q", f.FixedVersion)
	}
}

// TestSUSEProductNameMapping 覆盖 SUSE 产品名到发行版坐标的映射。
//
// SUSE 没有可用的 CPE，只能按名称匹配，所以边界必须在测试里钉死：
// 「15 SP6」与「15.6」是同一个版本，而 HPC / Real Time 不是我们的目标系统。
func TestSUSEProductNameMapping(t *testing.T) {
	cases := []struct {
		name     string
		comp     csafComponent
		wantOK   bool
		wantDist domain.DistroID
		wantRel  string
	}{
		{"Leap 16.0", csafComponent{ProductName: "openSUSE Leap 16.0"}, true, domain.DistroOpenSUSE, "16.0"},
		{"Leap 15.6", csafComponent{ProductName: "openSUSE Leap 15.6"}, true, domain.DistroOpenSUSE, "15.6"},
		{"SLES 15 SP6", csafComponent{ProductName: "SUSE Linux Enterprise Server 15 SP6"}, true, domain.DistroSLES, "15.6"},
		{"SLES 15.6", csafComponent{ProductName: "SUSE Linux Enterprise Server 15.6"}, true, domain.DistroSLES, "15.6"},
		{"SLES HPC 不覆盖", csafComponent{ProductName: "SUSE Linux Enterprise High Performance Computing 15 SP6"}, false, "", ""},
		{"未知产品", csafComponent{ProductName: "SUSE Manager 4.3"}, false, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			distro, rel, _, ok := SUSEParser{}.MapProduct(c.comp)
			if ok != c.wantOK {
				t.Fatalf("ok = %v，期望 %v", ok, c.wantOK)
			}
			if !ok {
				return
			}
			if distro != c.wantDist || rel != c.wantRel {
				t.Errorf("坐标 = %s/%s，期望 %s/%s", distro, rel, c.wantDist, c.wantRel)
			}
		})
	}
}

// TestRedHatReleaseFromCPE 覆盖 CPE 到主版本的截断。
func TestRedHatReleaseFromCPE(t *testing.T) {
	cases := map[string]string{
		"cpe:/o:redhat:enterprise_linux:9.6":  "9",
		"cpe:/o:redhat:enterprise_linux:10.1": "10",
		"cpe:/o:redhat:enterprise_linux:8":    "8",
		"cpe:/a:redhat:openshift:4.16":        "",
		"":                                    "",
	}
	for cpe, want := range cases {
		got, ok := redHatReleaseFromCPE(cpe)
		if want == "" {
			if ok {
				t.Errorf("%q 不应解析出 release，实际 %q", cpe, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("%q 应解析为 %q，实际 %q(ok=%v)", cpe, want, got, ok)
		}
	}
}

// ---------------- 变更清单 ----------------

func TestParseIndexCSV(t *testing.T) {
	// 混合 CRLF 与 LF：发布方的清单换行符不保证一致。
	body := "\"2026/rhsa-2026_0002.json\",\"2026-11-24T12:29:13+00:00\"\r\n" +
		"\"2025/rhsa-2025_1000.json\",\"2025-06-01T00:00:00+00:00\"\n" +
		"bad-line-without-comma\n"

	entries, err := parseIndexCSV([]byte(body))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("应保留 2 条合法条目，实际 %d（%+v）", len(entries), entries)
	}
	if entries[0].Path != "2026/rhsa-2026_0002.json" || entries[0].Year != 2026 {
		t.Errorf("首条条目解析错误: %+v", entries[0])
	}
	if !entries[0].Modified.Equal(time.Date(2026, 11, 24, 12, 29, 13, 0, time.UTC)) {
		t.Errorf("时间解析错误: %v", entries[0].Modified)
	}
}

// TestParseIndexCSVDropsUnsafePaths 清单来自发布方，但一条被投毒的记录
// 不能把抓取引到别的域名或跳出目录。
func TestParseIndexCSVDropsUnsafePaths(t *testing.T) {
	body := "\"2026/a.json\",\"2026-01-01T00:00:00+00:00\"\n" +
		"\"2026/b.json\",\"2026-01-01T00:00:00+00:00\"\n" +
		"\"../../etc/passwd\",\"2026-01-01T00:00:00+00:00\"\n" +
		"\"https://evil.example/x.json\",\"2026-01-01T00:00:00+00:00\"\n"

	entries, err := parseIndexCSV([]byte(body))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("越权路径必须被剔除，仅剩 2 条，实际 %d（%+v）", len(entries), entries)
	}
	for _, e := range entries {
		if strings.Contains(e.Path, "..") || strings.Contains(e.Path, "://") {
			t.Errorf("不安全路径未被剔除: %q", e.Path)
		}
	}
}

// TestParseIndexCSVRejectsBadRate 异常行超阈值必须整批拒绝：
// 格式漂移时只解析出一小部分文档，比完全没有数据更危险。
func TestParseIndexCSVRejectsBadRate(t *testing.T) {
	var b strings.Builder
	b.WriteString("\"2026/a.json\",\"2026-01-01T00:00:00+00:00\"\n")
	for i := 0; i < 50; i++ {
		b.WriteString("garbage\n")
	}
	if _, err := parseIndexCSV([]byte(b.String())); err == nil {
		t.Fatal("异常行超阈值应拒绝整份清单")
	}
}

// ---------------- 签名校验 ----------------

// TestPGPVerifierRoundTrip 用临时生成的密钥验证「通过 / 篡改 / 换钥」三条路径。
func TestPGPVerifierRoundTrip(t *testing.T) {
	cfg := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Time: time.Now}
	entity, err := openpgp.NewEntity("test", "linux-cve test key", "test@example.com", cfg)
	if err != nil {
		t.Fatalf("生成测试密钥失败: %v", err)
	}
	var pub bytes.Buffer
	if err := entity.Serialize(&pub); err != nil {
		t.Fatalf("序列化公钥失败: %v", err)
	}
	fp := normalizeFingerprint(strings.ToUpper(hexString(entity.PrimaryKey.Fingerprint[:])))

	data := []byte(`{"document":{"tracking":{"id":"RHSA-TEST:1"}}}`)
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, entity, bytes.NewReader(data), cfg); err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	v, err := NewPGPVerifier(pub.Bytes(), fp)
	if err != nil {
		t.Fatalf("构造校验器失败: %v", err)
	}
	if st, _, err := v.VerifyDetached(context.Background(), Source{}, data, sig.Bytes()); err != nil {
		t.Fatalf("正确签名应通过: %v", err)
	} else if st != domain.SignatureVerified {
		t.Errorf("签名状态应为 verified，实际 %s", st)
	}

	// 内容改一个字节必须失败：否则「验签通过」就毫无意义。
	tampered := append([]byte(nil), data...)
	tampered[0] = 'x'
	if _, _, err := v.VerifyDetached(context.Background(), Source{}, tampered, sig.Bytes()); err == nil {
		t.Error("内容被篡改时必须验签失败")
	}

	// 指纹不符必须失败：这是「换钥」与「伪造」的共同防线。
	if _, err := NewPGPVerifier(pub.Bytes(), strings.Repeat("AB", 20)); err == nil {
		t.Error("固化指纹不在公钥环中时应拒绝构造校验器")
	}
}

// hexString 把字节切片转成大写十六进制，避免额外引入 encoding/hex 的命名冲突。
func hexString(b []byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
