package plan

// 计划的执行与复检。
//
// 两条硬规则：
//  1. 逐步执行、失败即停。包升级不是可回滚操作，前一步失败后继续
//     会让系统停在部分升级状态，比不修更危险。
//  2. 结论只来自复检。命令返回 0 只代表包管理器认为成功，
//     真正的结论必须由「重新采集版本 + 按发行版原生规则比较」得出。

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/version"
)

// Runner 执行外部命令，便于测试注入。
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// OSRunner 是真实执行器。
//
// 与资产采集用的执行器不同：升级命令要几分钟、输出也大得多，
// 且必须把 stderr 一并带回——失败原因几乎都在 stderr 里。
type OSRunner struct {
	Timeout   time.Duration
	MaxOutput int64
}

// DefaultFixTimeout 是单步升级的超时。整套升级由多步组成，各自计时。
const DefaultFixTimeout = 15 * time.Minute

// Run 执行命令并返回合并输出。
func (o OSRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultFixTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, name, args...)
	var buf bytes.Buffer
	limit := o.MaxOutput
	if limit <= 0 {
		limit = 8 << 20
	}
	cmd.Stdout = &limitedWriter{w: &buf, left: limit}
	cmd.Stderr = cmd.Stdout

	err := cmd.Run()
	if cctx.Err() == context.DeadlineExceeded {
		return buf.Bytes(), fmt.Errorf("命令超时（%s）：%s %s", timeout, name, strings.Join(args, " "))
	}
	if err != nil {
		return buf.Bytes(), fmt.Errorf("%s %s 失败: %w", name, strings.Join(args, " "), err)
	}
	return buf.Bytes(), nil
}

// limitedWriter 截断过量输出，避免把整份 dpkg 日志读进内存。
type limitedWriter struct {
	w    *bytes.Buffer
	left int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.left <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	l.left -= int64(len(p))
	_, err := l.w.Write(p)
	return len(p), err
}

// StepResult 是单步执行结果。
type StepResult struct {
	Step   Step
	Output string
	Err    error
}

// ExecResult 是整次执行结果。
type ExecResult struct {
	Applied []StepResult
	// Failed 是第一个失败的步骤；nil 表示全部成功。
	Failed *StepResult
}

// Execute 依次执行计划中的每个步骤，失败即停。
func Execute(ctx context.Context, p *Plan, r Runner,
	progress func(step Step, index, total int)) (*ExecResult, error) {

	if p.Blocked {
		return nil, fmt.Errorf("plan: 计划不可执行：%s", p.BlockedDetail)
	}
	if len(p.Steps) == 0 {
		return &ExecResult{}, nil
	}
	if r == nil {
		return nil, fmt.Errorf("plan: 缺少命令执行器")
	}

	res := &ExecResult{}
	for i, s := range p.Steps {
		if progress != nil {
			progress(s, i+1, len(p.Steps))
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		name, args, err := s.Command()
		if err != nil {
			sr := StepResult{Step: s, Err: err}
			res.Failed = &sr
			res.Applied = append(res.Applied, sr)
			return res, nil
		}
		out, rerr := r.Run(ctx, name, args...)
		sr := StepResult{Step: s, Output: string(out), Err: rerr}
		res.Applied = append(res.Applied, sr)
		if rerr != nil {
			res.Failed = &sr
			return res, nil
		}
	}
	return res, nil
}

// VerifyResult 是单个包的复检结论。
type VerifyResult struct {
	Package string
	Arch    string
	Want    string
	Got     string
	OK      bool
	Detail  string
}

// Verify 用「执行后重新采集到的版本」核对每个步骤。
//
// installed 的键是 "包名\x00架构"，值是复检时读到的版本；
// 缺失表示复检时包已不存在——这既可能是被卸载，也可能是采集失败，
// 两种情况都不能算修好。
func Verify(p *Plan, installed map[string]string) ([]VerifyResult, bool) {
	out := make([]VerifyResult, 0, len(p.Steps))
	allOK := true
	for _, s := range p.Steps {
		got, ok := installed[s.Package+"\x00"+s.Arch]
		vr := VerifyResult{Package: s.Package, Arch: s.Arch, Want: s.To, Got: got}
		switch {
		case !ok || strings.TrimSpace(got) == "":
			vr.OK = false
			vr.Detail = "复检时未采集到该包版本"
		default:
			cmp, err := version.Compare(s.Manager, got, s.To)
			switch {
			case err != nil:
				vr.OK = false
				vr.Detail = "版本无法比较：" + err.Error()
			case cmp >= 0:
				vr.OK = true
				vr.Detail = "已不低于目标版本"
			default:
				vr.OK = false
				vr.Detail = "仍低于目标版本"
			}
		}
		if !vr.OK {
			allOK = false
		}
		out = append(out, vr)
	}
	return out, allOK
}

// InstalledKey 返回复检映射的键，供调用方拼装。
func InstalledKey(pkg domain.PackageRef) string { return pkg.Name + "\x00" + pkg.Arch }
