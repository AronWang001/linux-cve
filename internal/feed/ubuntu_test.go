package feed

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// ubuntuFixture 覆盖四种关键形态：
// 有 evr 状态的修复、无状态的无修复、多值变量（一包名对应多个二进制包）、
// 以及必须被排除的 inventory 类定义与 applicability_check 前置条件。
const ubuntuFixture = `<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"
  xmlns:linux-def="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">
  <generator><oval:product_name xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">Canonical OVAL Generator</oval:product_name></generator>
  <definitions>
    <definition id="oval:com.ubuntu.noble:def:100" class="inventory" version="1">
      <metadata><title>Check that Ubuntu 24.04 LTS (noble) is installed.</title><description /></metadata>
      <criteria><criterion test_ref="oval:com.ubuntu.noble:tst:100" comment="host is unix" /></criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:2001" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2024-0001 on Ubuntu 24.04 LTS (noble) - medium</title>
        <affected family="unix"><platform>Ubuntu 24.04 LTS</platform></affected>
        <reference source="CVE" ref_id="CVE-2024-0001" ref_url="https://www.cve.org/CVERecord?id=CVE-2024-0001" />
        <reference source="USN" ref_id="USN-9001-1" ref_url="https://ubuntu.com/security/notices/USN-9001-1" />
        <description>长描述不应进入归一化记录。</description>
        <advisory from="security@ubuntu.com">
          <severity>Medium</severity>
          <public_date>2024-05-01T10:00:00Z</public_date>
          <cve href="https://ubuntu.com/security/CVE-2024-0001">CVE-2024-0001</cve>
        </advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed" />
        <criterion test_ref="oval:com.ubuntu.noble:tst:2001" comment="openssl source package ... fixed (note: '3.0.13-0ubuntu3.1')." />
      </criteria>
    </definition>
    <definition id="oval:com.ubuntu.noble:def:2002" class="vulnerability" version="1">
      <metadata>
        <title>CVE-2024-0002 on Ubuntu 24.04 LTS (noble) - low</title>
        <affected family="unix"><platform>Ubuntu 24.04 LTS</platform></affected>
        <reference source="CVE" ref_id="CVE-2024-0002" />
        <description>尚无修复版本。</description>
        <advisory from="security@ubuntu.com">
          <severity>Low</severity>
          <public_date>2024-06-01T10:00:00Z</public_date>
          <cve>CVE-2024-0002</cve>
        </advisory>
      </metadata>
      <criteria>
        <extend_definition applicability_check="true" definition_ref="oval:com.ubuntu.noble:def:100" />
        <criteria operator="OR">
          <criterion test_ref="oval:com.ubuntu.noble:tst:2002" comment="might be affected and may need fixing" />
          <criterion test_ref="oval:com.ubuntu.noble:tst:2003" comment="might be affected and may need fixing" />
        </criteria>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:100" version="1" check="at least one">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:100" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2001" version="1" check="at least one">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:2001" />
      <linux-def:state state_ref="oval:com.ubuntu.noble:ste:2001" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2002" version="1" check="at least one">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:2002" />
    </linux-def:dpkginfo_test>
    <linux-def:dpkginfo_test id="oval:com.ubuntu.noble:tst:2003" version="1" check="at least one">
      <linux-def:object object_ref="oval:com.ubuntu.noble:obj:2003" />
    </linux-def:dpkginfo_test>
  </tests>
  <objects>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:100" version="1">
      <linux-def:name var_ref="oval:com.ubuntu.noble:var:100" />
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:2001" version="1">
      <linux-def:name var_ref="oval:com.ubuntu.noble:var:2001" />
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:2002" version="1">
      <linux-def:name var_ref="oval:com.ubuntu.noble:var:2002" />
    </linux-def:dpkginfo_object>
    <linux-def:dpkginfo_object id="oval:com.ubuntu.noble:obj:2003" version="1">
      <linux-def:name var_ref="oval:com.ubuntu.noble:var:2003" />
    </linux-def:dpkginfo_object>
  </objects>
  <states>
    <linux-def:dpkginfo_state id="oval:com.ubuntu.noble:ste:2001" version="1">
      <linux-def:evr datatype="debian_evr_string" operation="less than">3.0.13-0ubuntu3.1</linux-def:evr>
    </linux-def:dpkginfo_state>
  </states>
  <variables>
    <constant_variable id="oval:com.ubuntu.noble:var:100" version="1" datatype="string">
      <value>ubuntu-release</value>
    </constant_variable>
    <constant_variable id="oval:com.ubuntu.noble:var:2001" version="1" datatype="string">
      <value>libssl3t64</value>
      <value>openssl</value>
    </constant_variable>
    <constant_variable id="oval:com.ubuntu.noble:var:2002" version="1" datatype="string">
      <value>libfoo1</value>
    </constant_variable>
    <constant_variable id="oval:com.ubuntu.noble:var:2003" version="1" datatype="string">
      <value>libbar2</value>
    </constant_variable>
  </variables>
</oval_definitions>`

func ubuntuInput(t *testing.T, codename, body string) ParseInput {
	t.Helper()
	return ParseInput{
		Source:      mustSource(t, domain.SourceUbuntuOVAL),
		ArtifactSHA: HashBytes([]byte(body)),
		Body:        []byte(body),
		Release:     codename,
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
}

func TestUbuntuParseBasics(t *testing.T) {
	in := ubuntuInput(t, "noble", ubuntuFixture)
	res, err := UbuntuParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// inventory 类定义不参与漏洞情报，只有两条 vulnerability 定义。
	if len(res.Advisories) != 2 {
		t.Fatalf("公告数应为 2，实际 %d: %v", len(res.Advisories), advisoryIDs(res.Advisories))
	}

	// 修复记录：CVE-2024-0001 的一个 test 展开成两个包名（libssl3t64、openssl）；
	// CVE-2024-0002 的两个 test 都没有 state，不产出修复记录。
	if len(res.Fixes) != 2 {
		t.Fatalf("修复记录数应为 2，实际 %d", len(res.Fixes))
	}
	var pkgs []string
	for _, f := range res.Fixes {
		if f.FixedVersion != "3.0.13-0ubuntu3.1" {
			t.Errorf("修复版本应取 evr 状态值，实际 %q", f.FixedVersion)
		}
		if !f.IsOfficial() {
			t.Error("evr 是官方声明，应标记 official")
		}
		if f.DistroID != domain.DistroUbuntu || f.Release != "24.04" {
			t.Errorf("发行版坐标错误: %s/%s", f.DistroID, f.Release)
		}
		if f.Ref.Kind != domain.PackageKindBinary || f.Ref.Arch != domain.ArchAny {
			t.Errorf("dpkginfo 针对二进制包且不限架构，实际 %s/%s", f.Ref.Kind, f.Ref.Arch)
		}
		pkgs = append(pkgs, f.Ref.Name)
	}
	if !contains(pkgs, "libssl3t64") || !contains(pkgs, "openssl") {
		t.Errorf("多值变量应展开为两个包名，实际 %v", pkgs)
	}

	var fixed, unfixed *domain.Advisory
	for i := range res.Advisories {
		switch res.Advisories[i].CVEID {
		case "CVE-2024-0001":
			fixed = &res.Advisories[i]
		case "CVE-2024-0002":
			unfixed = &res.Advisories[i]
		}
	}
	if fixed == nil || unfixed == nil {
		t.Fatal("两条公告都应存在")
	}
	if fixed.VendorStatus != "fixed" {
		t.Errorf("有 evr 状态的应记为 fixed，实际 %q", fixed.VendorStatus)
	}
	if unfixed.VendorStatus != "affected-no-fix" {
		t.Errorf("无状态 test 应记为 affected-no-fix，实际 %q", unfixed.VendorStatus)
	}
	if fixed.Severity != domain.SeverityMedium {
		t.Errorf("严重程度应映射为 medium，实际 %q", fixed.Severity)
	}
	if fixed.URL != "https://ubuntu.com/security/notices/USN-9001-1" {
		t.Errorf("应优先使用 USN 链接，实际 %q", fixed.URL)
	}
	if fixed.IssuedAt == nil {
		t.Error("应记录 public_date")
	}
	if fixed.Title != "" {
		t.Errorf("definition 的 title 是 CVE 描述拼装，不应作为公告标题: %q", fixed.Title)
	}
	// 前置条件 applicability_check 必须被排除，不能被当成「平台检查定义」。
	for _, a := range res.Advisories {
		if strings.Contains(a.RawLocator, "def:100") {
			t.Error("inventory 定义不应产出公告")
		}
	}
}

func TestUbuntuRequiresCodename(t *testing.T) {
	in := ubuntuInput(t, "", ubuntuFixture)
	if _, err := (UbuntuParser{}).Parse(context.Background(), in); err == nil {
		t.Fatal("缺少 codename 时必须失败")
	}
}

func TestUbuntuRejectsNonOvalRoot(t *testing.T) {
	in := ubuntuInput(t, "noble", `<html><body>not oval</body></html>`)
	if _, err := (UbuntuParser{}).Parse(context.Background(), in); err == nil {
		t.Fatal("根元素不是 oval_definitions 时必须失败")
	}
}

func TestUbuntuSeverityMapping(t *testing.T) {
	cases := map[string]domain.Severity{
		"Critical":   domain.SeverityCritical,
		"High":       domain.SeverityHigh,
		"Medium":     domain.SeverityMedium,
		"Low":        domain.SeverityLow,
		"Negligible": domain.SeverityLow,
		"":           domain.SeverityUnknown,
	}
	for in, want := range cases {
		if got := ubuntuSeverity(in); got != want {
			t.Errorf("ubuntuSeverity(%q) = %q，期望 %q", in, got, want)
		}
	}
}

func TestUbuntuFixedVersionOnlyAcceptsLessThan(t *testing.T) {
	var s ovalStateXML
	s.EVR = append(s.EVR, struct {
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
		Value     string `xml:",chardata"`
	}{Datatype: "debian_evr_string", Operation: "equals", Value: "1.0"})
	if v, ok := ubuntuFixedVersion(s); ok {
		t.Errorf("equals 操作不是「首次修复版本」，不应被接受: %q", v)
	}
}

func TestUbuntuDeterministic(t *testing.T) {
	in := ubuntuInput(t, "noble", ubuntuFixture)
	a, err := UbuntuParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	b, err := UbuntuParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if h1, h2 := digestResult(a), digestResult(b); h1 != h2 {
		t.Fatalf("同一输入两次解析结果不一致: %s vs %s", h1[:12], h2[:12])
	}
}

// TestUbuntuParseRealDataset 用真实 bz2 数据验证解析器。
//
//	curl -o /tmp/noble.oval.xml.bz2 \
//	  https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2
//	UBUNTU_OVAL_BZ2=/tmp/noble.oval.xml.bz2 go test ./internal/feed/ -run UbuntuReal -v
func TestUbuntuParseRealDataset(t *testing.T) {
	path := os.Getenv("UBUNTU_OVAL_BZ2")
	if path == "" {
		t.Skip("未设置 UBUNTU_OVAL_BZ2，跳过真实数据集验证")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取真实数据集失败: %v", err)
	}
	t.Logf("压缩后 %.1f MB", float64(len(raw))/1024/1024)

	start := time.Now()
	body, err := Decompress(raw, MaxExpandedBytes)
	if err != nil {
		t.Fatalf("解压失败: %v", err)
	}
	t.Logf("解压后 %.1f MB，耗时 %v", float64(len(body))/1024/1024, time.Since(start))

	in := ParseInput{
		Source:      mustSource(t, domain.SourceUbuntuOVAL),
		ArtifactSHA: HashBytes(raw),
		Body:        body,
		Release:     "noble",
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	start = time.Now()
	res, err := UbuntuParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析真实数据集失败: %v", err)
	}
	t.Logf("解析耗时 %v；公告 %d，修复 %d，跳过 %d",
		time.Since(start), len(res.Advisories), len(res.Fixes), res.Skipped)

	if len(res.Advisories) < 30000 {
		t.Errorf("公告数量异常偏低: %d", len(res.Advisories))
	}
	if len(res.Fixes) < 1000 {
		t.Errorf("修复记录异常偏低: %d（实测 evr 状态仅约 1.5k 条）", len(res.Fixes))
	}
	if res.Skipped > 2000 {
		t.Errorf("跳过记录过多: %d，疑似桥接或格式漂移", res.Skipped)
	}
	if len(res.Releases) != 1 || res.Releases[0].Release != "24.04" || res.Releases[0].Codename != "noble" {
		t.Errorf("release 坐标错误: %+v", res.Releases)
	}

	// 目标 CVE：libxml-parser-perl 在 noble 的修复版本为 2.47-1ubuntu0.24.04.1
	// （2026-11-24 实测，与 Canonical OVAL 的 evr 状态一致）。
	var hit bool
	for _, f := range res.Fixes {
		if f.CVEID == "CVE-2006-10002" && f.Ref.Name == "libxml-parser-perl" {
			hit = true
			if f.FixedVersion != "2.47-1ubuntu0.24.04.1" {
				t.Errorf("目标 CVE 的修复版本应为 2.47-1ubuntu0.24.04.1，实际 %q", f.FixedVersion)
			}
		}
	}
	if !hit {
		t.Error("未找到 CVE-2006-10002 对 libxml-parser-perl 的修复记录")
	}

	// 溯源完整性：每条公告都要能回到 definition。
	for i, a := range res.Advisories {
		if a.ArtifactSHA256 != in.ArtifactSHA {
			t.Fatalf("第 %d 条公告未携带 Artifact 哈希", i+1)
		}
		if !strings.HasPrefix(a.RawLocator, "oval:com.ubuntu.") || a.RawRecordHash == "" {
			t.Fatalf("第 %d 条公告溯源字段不完整: %+v", i+1, a)
		}
		if i > 2000 {
			break
		}
	}
}
