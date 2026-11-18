package domain

import (
	"strings"
	"testing"
)

func TestParseCVEID(t *testing.T) {
	valid := []string{"CVE-2026-98432", "cve-2026-98432", " CVE-2015-1234 "}
	for _, s := range valid {
		id, err := ParseCVEID(s)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", s, err)
		}
		want := CVEID(strings.ToUpper(strings.TrimSpace(s)))
		if id != want {
			t.Errorf("解析 %q 得到 %q，期望 %q", s, id, want)
		}
	}

	invalid := []string{"", "CVE-26-1", "CVE-2026-123", "CVE-2026-98432x", "2026-98432", "CVE-2026-98 432"}
	for _, s := range invalid {
		if _, err := ParseCVEID(s); err == nil {
			t.Errorf("非法编号 %q 应被拒绝", s)
		}
	}
}

func TestCVEYear(t *testing.T) {
	id, _ := ParseCVEID("CVE-2026-98432")
	if y, ok := id.Year(); !ok || y != 2026 {
		t.Errorf("年份应为 2026，实际 %d (%v)", y, ok)
	}
	if _, ok := CVEID("bad").Year(); ok {
		t.Error("非法编号不应返回年份")
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{-0.1, SeverityUnknown},
		{0, SeverityNone},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10, SeverityCritical},
		{10.1, SeverityUnknown},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("CVSS %.1f 应为 %s，实际 %s", c.score, c.want, got)
		}
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Error("critical 排序权重应大于 high")
	}
	if SeverityUnknown.Rank() != -1 {
		t.Error("unknown 应返回 -1，单独排序")
	}
	if _, err := ParseSeverity("HIGH"); err != nil {
		t.Errorf("解析大写严重程度应成功: %v", err)
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("非法严重程度应报错")
	}
}

func TestVersionString(t *testing.T) {
	cases := []struct {
		v    Version
		want string
	}{
		{Version{Raw: "1:2.4.7-1"}, "1:2.4.7-1"},
		{Version{Epoch: 1, Upstream: "2.4.7", Release: "1"}, "1:2.4.7-1"},
		{Version{Upstream: "2.4.7", Release: "1~deb12u2"}, "2.4.7-1~deb12u2"},
		{Version{Upstream: "2.4.7"}, "2.4.7"},
		{Version{}, ""},
	}
	for _, c := range cases {
		if got := c.v.String(); got != c.want {
			t.Errorf("String() 期望 %q，实际 %q", c.want, got)
		}
	}
}

func TestVersionIsZeroAndEqual(t *testing.T) {
	if !(Version{}).IsZero() {
		t.Error("空版本应判定为 zero")
	}
	if (Version{Raw: "1.0"}).IsZero() {
		t.Error("非空版本不应判定为 zero")
	}

	a := Version{Epoch: 0, Upstream: "6.8.0", Release: "31.31"}
	b := Version{Raw: "6.8.0-31.31", Upstream: "6.8.0", Release: "31.31"}
	if !a.StructurallyEqual(b) {
		t.Error("结构化分量相同应判定相等")
	}
	c := Version{Upstream: "6.8.0", Release: "34.34"}
	if a.StructurallyEqual(c) {
		t.Error("release 不同不应判定相等")
	}
}

func TestPackageKindAndManager(t *testing.T) {
	if !PackageKindSource.Valid() || !PackageKindBinary.Valid() {
		t.Error("source/binary 应为合法包类型")
	}
	if PackageKind("virtual").Valid() {
		t.Error("非法包类型不应通过校验")
	}
	if _, err := ParsePackageKind("binary"); err != nil {
		t.Errorf("解析 binary 失败: %v", err)
	}
	if _, err := ParsePackageKind("bogus"); err == nil {
		t.Error("非法包类型应报错")
	}
	for _, m := range []PackageManager{ManagerDPKG, ManagerRPM, ManagerAPK, ManagerPacman, ManagerNone} {
		if !m.Valid() {
			t.Errorf("%q 应为合法包管理器", m)
		}
	}
	if PackageManager("snap").Valid() {
		t.Error("未知包管理器不应合法")
	}
}

func TestPackageRefValidate(t *testing.T) {
	ok := PackageRef{Kind: PackageKindBinary, Name: "openssl", Arch: "amd64"}
	if err := ok.Validate(); err != nil {
		t.Errorf("合法包坐标不应报错: %v", err)
	}
	if got := ok.IdentityKey(); got != "binary:openssl:amd64" {
		t.Errorf("身份键格式不符: %q", got)
	}

	bad := []PackageRef{
		{Kind: "bogus", Name: "x", Arch: "amd64"},
		{Kind: PackageKindBinary, Name: "", Arch: "amd64"},
		{Kind: PackageKindBinary, Name: "x", Arch: ""},
	}
	for _, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("非法包坐标 %+v 应报错", r)
		}
	}
}

func TestArchMatches(t *testing.T) {
	cases := []struct {
		declared, installed string
		want                bool
	}{
		{ArchAny, "amd64", true},
		{"", "arm64", true},
		{"amd64", "amd64", true},
		{"amd64", "arm64", false},
		{"amd64", "all", true},
		{"amd64", "noarch", true},
		{"noarch", "amd64", false},
	}
	for _, c := range cases {
		if got := ArchMatches(c.declared, c.installed); got != c.want {
			t.Errorf("ArchMatches(%q,%q) 期望 %v，实际 %v", c.declared, c.installed, c.want, got)
		}
	}
}

func TestInstalledPackageValidate(t *testing.T) {
	p := InstalledPackage{
		Ref:     PackageRef{Kind: PackageKindBinary, Name: "openssl", Arch: "amd64"},
		Manager: ManagerDPKG,
	}
	if err := p.Validate(); err != nil {
		t.Errorf("合法安装包不应报错: %v", err)
	}

	p.Ref.Kind = PackageKindSource
	if err := p.Validate(); err == nil {
		t.Error("安装包类型必须是 binary")
	}
}

func TestReleaseLifecycle(t *testing.T) {
	active := Release{ID: "debian:12", Distro: DistroDebian, Version: "12", Codename: "bookworm", Lifecycle: LifecycleActive}
	if err := active.Validate(); err != nil {
		t.Errorf("合法 release 不应报错: %v", err)
	}
	if !active.SupportsAutoFix() {
		t.Error("active 生命周期应允许自动修复")
	}

	legacy := active
	legacy.Lifecycle = LifecycleLegacy
	if legacy.SupportsAutoFix() {
		t.Error("legacy 生命周期不得开放自动修复（Amazon Linux 2）")
	}

	bad := active
	bad.Distro = DistroID("gentoo")
	if err := bad.Validate(); err == nil {
		t.Error("未登记发行版应报错")
	}

	if DistroDebian.Family() != FamilyDebian {
		t.Error("Debian 应归属 debian 族")
	}
	if DistroID("gentoo").Family() != FamilyUnknown {
		t.Error("未登记发行版应返回 unknown 族")
	}
}

func TestAdvisoryUIDStable(t *testing.T) {
	cve, _ := ParseCVEID("CVE-2026-98432")
	a := AdvisoryUID(SourceDebianTracker, "DSA-5810-1", cve)
	b := AdvisoryUID(SourceDebianTracker, "DSA-5810-1", cve)
	if a != b {
		t.Error("相同内容必须得到相同 UID（幂等导入的前提）")
	}
	if len(a) != 16 {
		t.Errorf("UID 长度应为 16，实际 %d", len(a))
	}
	c := AdvisoryUID(SourceUbuntuUSN, "DSA-5810-1", cve)
	if a == c {
		t.Error("不同来源必须得到不同 UID")
	}
}

func TestAdvisoryValidate(t *testing.T) {
	cve, _ := ParseCVEID("CVE-2026-98432")
	a := Advisory{
		SourceID:   SourceDebianTracker,
		AdvisoryID: "DSA-5810-1",
		CVEID:      cve,
	}
	a.UID = AdvisoryUID(a.SourceID, a.AdvisoryID, a.CVEID)
	if err := a.Validate(); err != nil {
		t.Errorf("合法公告不应报错: %v", err)
	}

	a.UID = "deadbeefdeadbeef"
	if err := a.Validate(); err == nil {
		t.Error("UID 与内容不一致应报错")
	}

	broken := Advisory{SourceID: SourceDebianTracker, AdvisoryID: "X", CVEID: CVEID("bad")}
	if err := broken.Validate(); err == nil {
		t.Error("非法 CVE 应报错")
	}
}

func TestAdvisoryFixValidate(t *testing.T) {
	cve, _ := ParseCVEID("CVE-2026-98432")
	fix := AdvisoryFix{
		AdvisoryUID:  AdvisoryUID(SourceDebianTracker, "DSA-5810-1", cve),
		SourceID:     SourceDebianTracker,
		AdvisoryID:   "DSA-5810-1",
		CVEID:        cve,
		DistroID:     DistroDebian,
		Release:      "12",
		Channel:      "bookworm-security",
		Ref:          PackageRef{Kind: PackageKindSource, Name: "linux", Arch: ArchAny},
		FixedVersion: "6.1.140-1",
	}
	if err := fix.Validate(); err != nil {
		t.Errorf("合法修复记录不应报错: %v", err)
	}

	// 逐项删除必填字段，全部必须被拒绝：缺任何一项都无法可靠判定
	cases := map[string]func(f *AdvisoryFix){
		"缺公告UID":   func(f *AdvisoryFix) { f.AdvisoryUID = "" },
		"缺CVE":     func(f *AdvisoryFix) { f.CVEID = "" },
		"缺发行版":     func(f *AdvisoryFix) { f.DistroID = "" },
		"缺release": func(f *AdvisoryFix) { f.Release = "" },
		"缺渠道":      func(f *AdvisoryFix) { f.Channel = "" },
		"缺包类型":     func(f *AdvisoryFix) { f.Ref.Kind = "" },
		"缺包名":      func(f *AdvisoryFix) { f.Ref.Name = "" },
		"缺架构":      func(f *AdvisoryFix) { f.Ref.Arch = "" },
		"缺固定版本":    func(f *AdvisoryFix) { f.FixedVersion = "" },
	}
	for name, mutate := range cases {
		bad := fix
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s 应报错", name)
		}
	}
}

func TestNotAffectedValidate(t *testing.T) {
	cve, _ := ParseCVEID("CVE-2026-98432")
	n := NotAffected{
		SourceID: SourceDebianTracker,
		CVEID:    cve,
		DistroID: DistroDebian,
		Release:  "12",
		Ref:      PackageRef{Kind: PackageKindSource, Name: "linux", Arch: ArchAny},
		Reason:   NotAffectedDeclared,
	}
	if err := n.Validate(); err != nil {
		t.Errorf("合法不受影响声明不应报错: %v", err)
	}
	n.Reason = "guessed"
	if err := n.Validate(); err == nil {
		t.Error("非法原因应报错")
	}
}
