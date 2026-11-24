package inventory

import (
	"testing"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// TestNormalizeRelease 固定「VERSION_ID → 情报源登记粒度」的收敛规则。
//
// 这条规则错了不会报错，只会让判定悄悄变成「0 条」——CI 在 alpine:3.20
// 容器里就这么撞上过一次：容器报 3.20.3，情报按 3.20 入库，精确匹配
// 一条都不命中，而退出码是 0（无洞）而不是「没对上」。
func TestNormalizeRelease(t *testing.T) {
	cases := []struct {
		distro  string
		release string
		want    string
	}{
		// Alpine 按 minor 线发布
		{"alpine", "3.20.3", "3.20"},
		{"alpine", "3.20", "3.20"},
		{"alpine", "3.19.1", "3.19"},
		// RHEL 系按主线号，补丁流共用同一支持线
		{"rhel", "9.4", "9"},
		{"rhel", "9", "9"},
		{"rhel", "10.1", "10"},
		{"rocky", "9.3", "9"},
		{"almalinux", "8.10", "8"},
		{"ol", "8.9", "8"},
		// 其余保持原样：它们本身就是登记粒度
		{"debian", "13", "13"},
		{"debian", "12", "12"},
		{"ubuntu", "24.04", "24.04"},
		{"sles", "15.6", "15.6"},
		{"opensuse-leap", "16.0", "16.0"},
		{"arch", "rolling", "rolling"},
		// 认不出来的形式原样返回，不猜
		{"alpine", "edge", "edge"},
		{"rhel", "", ""},
	}
	for _, c := range cases {
		got := normalizeRelease(domain.DistroID(c.distro), c.release)
		if got != c.want {
			t.Errorf("normalizeRelease(%s, %q) = %q，期望 %q", c.distro, c.release, got, c.want)
		}
	}
}

// TestDetectSystemNormalizesRelease 确认识别路径上确实调用了归一化。
func TestDetectSystemNormalizesRelease(t *testing.T) {
	info, err := DetectSystem([]byte("ID=alpine\nVERSION_ID=3.20.3\n"),
		"x86_64", "6.6.30-0-lts")
	if err != nil {
		t.Fatalf("识别失败: %v", err)
	}
	if info.Release != "3.20" {
		t.Errorf("Alpine release 应归一为 3.20，实际 %q", info.Release)
	}

	info, err = DetectSystem([]byte("ID=rhel\nVERSION_ID=\"9.4\"\n"), "x86_64", "5.14.0-427")
	if err != nil {
		t.Fatalf("识别失败: %v", err)
	}
	if info.Release != "9" {
		t.Errorf("RHEL release 应归一为 9，实际 %q", info.Release)
	}
}
