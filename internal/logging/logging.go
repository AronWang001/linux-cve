// Package logging 提供基于 log/slog 的日志构造。
//
// 约定：日志一律写 stderr，stdout 只用于命令的业务输出（含 --json），
// 这样 `linux-cve list --json | jq` 不会被日志污染。
package logging

import (
	"io"
	"log/slog"
	"strings"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// ParseLevel 解析日志级别字符串。
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, apperr.Newf(exitcode.Usage, "logging.level",
			"非法的日志级别 %q（可选 debug|info|warn|error）", s)
	}
}

// New 构造 slog.Logger。format 取 text 或 json。
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	lv, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: lv}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text", "":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, apperr.Newf(exitcode.Usage, "logging.format",
			"非法的日志格式 %q（可选 text|json）", format)
	}
	return slog.New(h), nil
}

// Discard 返回一个丢弃全部日志的 logger，用于测试与 --quiet 场景。
func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
