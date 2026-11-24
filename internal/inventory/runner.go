// Package inventory 负责 Linux 系统资产采集：发行版、架构、内核、软件包清单。
//
// 全部采集动作必须只读：只允许查询类命令与只读文件，
// 严禁 apt update / dnf makecache / apk update / pacman -Sy 等刷新或变更操作。
//
// 证据规则（docs/data-model.md §2.2）：
//   - SourceName 只在采集工具有可靠输出时填写，禁止字符串前缀猜测；
//   - OriginChannel 无法证明时一律写 ChannelUnknown，不得猜测；
//   - 内核包映射只接受精确证据，映射不出留空。
package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// Runner 抽象只读命令执行，测试注入模拟输出。
// 实现必须保证：固定命令与参数、不经 Shell、有超时与输出上限。
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// 默认执行参数。
const (
	DefaultTimeout   = 30 * time.Second
	DefaultMaxOutput = 64 << 20 // 64 MiB，正常清单远小于此值
)

// ExecRunner 是真实执行器：exec.CommandContext + 超时 + 输出上限。
// 参数逐个传递，绝不拼接 Shell 命令，杜绝命令注入。
type ExecRunner struct {
	Timeout   time.Duration
	MaxOutput int64
}

// Run 执行单条只读命令并返回 stdout。
func (e ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxOut := e.MaxOutput
	if maxOut <= 0 {
		maxOut = DefaultMaxOutput
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	// 限制缓冲区：超限后继续写入被丢弃，最终按输出过大报错，
	// 避免异常命令输出耗尽内存。
	outW := &limitedWriter{buf: &stdout, limit: maxOut}
	cmd.Stdout = outW
	cmd.Stderr = &limitedWriter{buf: &stderr, limit: 1 << 20}

	err := cmd.Run()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, apperr.Newf(exitcode.Error, "inventory.exec",
				"命令超时（%s）", name)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, apperr.Newf(exitcode.Error, "inventory.exec",
				"命令非零退出（%s, code=%d）: %s", name, exitErr.ExitCode(), truncate(stderr.String(), 200))
		}
		return nil, apperr.Wrap(exitcode.Error, "inventory.exec",
			fmt.Sprintf("命令执行失败（%s）", name), err)
	}
	if outW.overflow {
		return nil, apperr.Newf(exitcode.Error, "inventory.exec",
			"命令输出超过 %d 字节上限（%s）", maxOut, name)
	}
	return stdout.Bytes(), nil
}

// limitedWriter 写满上限后丢弃后续内容并记 overflow。
type limitedWriter struct {
	buf      *bytes.Buffer
	limit    int64
	overflow bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.overflow {
		return len(p), nil // 丢弃但吞掉错误，让命令跑完统一按 overflow 报告
	}
	remain := w.limit - int64(w.buf.Len())
	if int64(len(p)) > remain {
		if remain > 0 {
			w.buf.Write(p[:remain])
		}
		w.overflow = true
		return len(p), nil
	}
	w.buf.Write(p)
	return len(p), nil
}

// truncate 截断长字符串用于错误信息。
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
