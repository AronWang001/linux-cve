package inventory

import (
	"testing"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

func TestParseDebianSourceField(t *testing.T) {
	cases := []struct {
		raw, derived string
		name, srcVer string
	}{
		{"glibc (2.36-9)", "", "glibc", "2.36-9"},
		{"bash", "5.2.15-2", "bash", "5.2.15-2"}, // 无括号版本时用 source:Version
		{"bash", "", "bash", ""},
		{"", "1.0", "", ""}, // Source 缺失 → 桥接失败
	}
	for _, c := range cases {
		n, v := parseDebianSource(c.raw, c.derived)
		if n != c.name || v != c.srcVer {
			t.Errorf("parseDebianSource(%q,%q) = (%q,%q)，期望 (%q,%q)",
				c.raw, c.derived, n, v, c.name, c.srcVer)
		}
	}
}

func TestParseSourceRPM(t *testing.T) {
	cases := []struct {
		in   string
		name string
		ok   bool
	}{
		{"openssl-3.0.7-2.el9.src.rpm", "openssl", true},
		{"kernel-5.14.0-427.13.1.el9_4.src.rpm", "kernel", true},
		{"java-1.8.0-openjdk-1.8.0.402.b06-1.el9.src.rpm", "java-1.8.0-openjdk", true},
		{"weird.src.rpm", "", false},
		{"noversion-1.0.src.rpm", "", false}, // 只有一刀
		{"nolike-1.0-2.rpm", "", false},      // 无 src 后缀不认定
		{"", "", false},
	}
	for _, c := range cases {
		n, ok := parseSourceRPM(c.in)
		if n != c.name || ok != c.ok {
			t.Errorf("parseSourceRPM(%q) = (%q,%v)，期望 (%q,%v)", c.in, n, ok, c.name, c.ok)
		}
	}
}

func TestParseVersionOrKeepFallback(t *testing.T) {
	// 非法版本：保留 Raw，不丢包、不猜测拆分
	v, warn := parseVersionOrKeep(domain.ManagerDPKG, "bad version!!")
	if v.Raw != "bad version!!" || v.Upstream != "" {
		t.Errorf("非法版本应保留 Raw-only: %+v", v)
	}
	if warn == "" {
		t.Error("降级必须产生警告")
	}
	// 空版本
	if _, w := parseVersionOrKeep(domain.ManagerRPM, "  "); w == "" {
		t.Error("空版本必须警告")
	}
	// 正常解析
	v2, w2 := parseVersionOrKeep(domain.ManagerDPKG, "1:2.3-4~deb12u1")
	if w2 != "" || v2.Epoch != 1 || v2.Release != "4~deb12u1" {
		t.Errorf("正常解析异常: %+v warn=%q", v2, w2)
	}
}

func TestJoinEVR(t *testing.T) {
	if got := joinEVR(0, "3.0.7", "2.el9"); got != "3.0.7-2.el9" {
		t.Errorf("joinEVR 无 epoch = %q", got)
	}
	if got := joinEVR(2, "1.0", "1"); got != "2:1.0-1" {
		t.Errorf("joinEVR 带 epoch = %q", got)
	}
	if got := joinEVR(0, "1.0", ""); got != "1.0" {
		t.Errorf("joinEVR 无 release = %q", got)
	}
}
