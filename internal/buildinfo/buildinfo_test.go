package buildinfo

import (
	"strings"
	"testing"
)

// TestDefaultsAreUnknown 固化 P1-7：未注入构建信息时显示 unknown，
// 不得回退为任何基线提交号。
func TestDefaultsAreUnknown(t *testing.T) {
	orig := Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
	t.Cleanup(func() {
		Version, Commit, BuildDate = orig.Version, orig.Commit, orig.BuildDate
	})

	if Commit != "unknown" {
		t.Errorf("默认 Commit 应为 unknown，实际 %q", Commit)
	}
	if BuildDate != "unknown" {
		t.Errorf("默认 BuildDate 应为 unknown，实际 %q", BuildDate)
	}
	if Version == "" {
		t.Error("默认 Version 不应为空")
	}
}

func TestGetAndString(t *testing.T) {
	orig := Info{Version: Version, Commit: Commit, BuildDate: BuildDate}
	t.Cleanup(func() {
		Version, Commit, BuildDate = orig.Version, orig.Commit, orig.BuildDate
	})

	Version = "2.0.0-dev"
	Commit = "abc1234"
	BuildDate = "2026-11-18T12:00:00Z"

	i := Get()
	if i.Version != "2.0.0-dev" || i.Commit != "abc1234" || i.BuildDate != "2026-11-18T12:00:00Z" {
		t.Errorf("Get() 未反映注入值: %+v", i)
	}
	if i.GoVersion == "" || i.Platform == "" {
		t.Errorf("GoVersion/Platform 应来自运行时: %+v", i)
	}

	s := String()
	for _, want := range []string{"2.0.0-dev", "abc1234", "2026-11-18T12:00:00Z"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() %q 应包含 %q", s, want)
		}
	}
}
