package apperr

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/AronWang001/linux-cve/internal/exitcode"
)

func TestCodeOf(t *testing.T) {
	sentinel := errors.New("底层失败")

	cases := []struct {
		name string
		err  error
		want exitcode.Code
	}{
		{"nil", nil, exitcode.OK},
		{"普通错误", sentinel, exitcode.Error},
		{"带码错误", New(exitcode.Usage, "cli", "参数错误"), exitcode.Usage},
		{"包装错误", Wrap(exitcode.Integrity, "db", "校验失败", sentinel), exitcode.Integrity},
		{"fmt 包装", fmt.Errorf("外层: %w", New(exitcode.Permission, "fix", "需要 root")), exitcode.Permission},
		{"未实现", NotImplementedf("%s 未实现", "scan"), exitcode.NotImplemented},
	}
	for _, c := range cases {
		if got := CodeOf(c.err); got != c.want {
			t.Errorf("%s: 期望 %v，实际 %v", c.name, c.want, got)
		}
	}
}

func TestUnwrapChain(t *testing.T) {
	sentinel := errors.New("磁盘只读")
	err := Wrap(exitcode.Error, "database.open", "打开数据库失败", sentinel)

	if !errors.Is(err, sentinel) {
		t.Fatal("errors.Is 应能穿透到 sentinel")
	}
	msg := err.Error()
	for _, want := range []string{"database.open", "打开数据库失败", "磁盘只读"} {
		if !strings.Contains(msg, want) {
			t.Errorf("错误信息 %q 应包含 %q", msg, want)
		}
	}
}

func TestErrorMessages(t *testing.T) {
	if got := New(exitcode.Error, "", "只有消息").Error(); got != "只有消息" {
		t.Errorf("无 Op 无 Err 时错误信息应为纯消息，实际 %q", got)
	}
	if got := New(exitcode.Usage, "cli", "缺参数").Error(); got != "cli: 缺参数" {
		t.Errorf("期望 \"cli: 缺参数\"，实际 %q", got)
	}
}
