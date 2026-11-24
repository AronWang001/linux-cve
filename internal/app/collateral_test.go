package app

import (
	"testing"
)

// TestDiffPackages 验证执行前后的包集合差异。
//
// 这个差异是「变更集之外的改动」的唯一证据：升级一个包顺带装了 20 个依赖，
// 包管理器自己不会说，只能靠前后快照对比。
func TestDiffPackages(t *testing.T) {
	before := map[string]string{
		"libcap2\x00amd64":        "1:2.75-10+b1",
		"libcap2-bin\x00amd64":    "1:2.75-10+b1",
		"openssh-server\x00amd64": "1:10.0p1",
	}
	after := map[string]string{
		"libcap2\x00amd64":     "1:2.75-10+deb13u1", // 版本变化不算附带变更
		"libcap2-bin\x00amd64": "1:2.75-10+deb13u1",
		"libpam-cap\x00amd64":  "1:2.75-10+deb13u1", // 新装
	}

	d := diffPackages(before, after)
	if len(d.Added) != 1 || d.Added[0] != "libpam-cap (amd64)" {
		t.Errorf("Added = %v，期望 [libpam-cap (amd64)]", d.Added)
	}
	if len(d.Removed) != 1 || d.Removed[0] != "openssh-server (amd64)" {
		t.Errorf("Removed = %v，期望 [openssh-server (amd64)]", d.Removed)
	}
}

// TestDiffPackagesEmpty 确认没有变化时返回空，避免「0 个附带变更」被当成异常。
func TestDiffPackagesEmpty(t *testing.T) {
	same := map[string]string{"a\x00amd64": "1"}
	d := diffPackages(same, same)
	if len(d.Added) != 0 || len(d.Removed) != 0 {
		t.Errorf("相同集合不应有差异：%+v", d)
	}
}

// TestPkgLabel 确认键值还原不会把架构弄丢或错位。
func TestPkgLabel(t *testing.T) {
	if got := pkgLabel("libcap2\x00amd64"); got != "libcap2 (amd64)" {
		t.Errorf("pkgLabel = %q", got)
	}
	if got := pkgLabel("noarch-suffix"); got != "noarch-suffix" {
		t.Errorf("无架构分隔符时应原样返回，实际 %q", got)
	}
}
