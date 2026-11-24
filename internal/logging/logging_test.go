package logging

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

func TestNewTextAndJSON(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "debug", "text")
	if err != nil {
		t.Fatalf("构造 text logger 失败: %v", err)
	}
	l.Debug("文本日志", "k", "v")
	if !strings.Contains(buf.String(), "文本日志") {
		t.Errorf("输出应包含日志消息，实际 %q", buf.String())
	}

	buf.Reset()
	l, err = New(&buf, "info", "json")
	if err != nil {
		t.Fatalf("构造 json logger 失败: %v", err)
	}
	l.Info("json 日志")
	if !strings.Contains(buf.String(), `"msg":"json 日志"`) {
		t.Errorf("JSON 输出格式不符，实际 %q", buf.String())
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	l, err := New(&buf, "error", "text")
	if err != nil {
		t.Fatalf("构造 logger 失败: %v", err)
	}
	l.Info("不应出现")
	if buf.Len() != 0 {
		t.Errorf("error 级别不应输出 info 日志，实际 %q", buf.String())
	}
}

func TestInvalidLevelAndFormat(t *testing.T) {
	if _, err := ParseLevel("verbose"); err == nil {
		t.Error("非法级别应报错")
	} else if apperr.CodeOf(err) != exitcode.Usage {
		t.Errorf("退出码应为 USAGE，实际 %v", apperr.CodeOf(err))
	}

	if _, err := New(&bytes.Buffer{}, "info", "yaml"); err == nil {
		t.Error("非法格式应报错")
	}
}

func TestDiscardNeverPanics(t *testing.T) {
	Discard().Info("静默")
}
