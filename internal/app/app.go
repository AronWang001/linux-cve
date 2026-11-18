// Package app 装配命令分发与输出。
//
// 约定：除本包与 cmd/linux-cve 外，其他包不直接写 stdout，也不调用 os.Exit。
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/config"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/inventory"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/logging"
)

// globalFlags 是所有子命令共享的全局参数。
type globalFlags struct {
	configPath string
	dbPath     string
	logLevel   string
	logFormat  string
	offline    bool
}

// env 是一次命令执行的上下文，持有输出流与已解析的配置，便于测试替换。
type env struct {
	stdout io.Writer
	stderr io.Writer
	flags  globalFlags
	cfg    *config.Config
	log    *slog.Logger
	getenv func(string) string

	// newCollector 是资产采集器工厂，测试注入合成夹具；nil 时用 inventory.New。
	newCollector func() *inventory.Collector
}

// Main 是进程入口，返回最终退出码。
// 退出码优先取自 error 携带的 Code，保证错误与退出码不会不一致。
func Main(ctx context.Context, args []string, stdout, stderr io.Writer) exitcode.Code {
	e := &env{stdout: stdout, stderr: stderr, getenv: os.Getenv}
	code, err := e.run(ctx, args)

	if err != nil {
		fmt.Fprintf(stderr, "error: %s\n", err)
		if c := apperr.CodeOf(err); c != exitcode.OK {
			code = c
		}
	}
	// 被信号中断时统一为 130，便于脚本识别
	if ctx.Err() != nil && code == exitcode.Error {
		code = exitcode.Interrupted
	}
	return code
}

// run 解析全局参数并分发子命令。
func (e *env) run(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("linux-cve", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.StringVar(&e.flags.configPath, "config", "", "配置文件路径")
	fs.StringVar(&e.flags.dbPath, "db", "", "数据库路径")
	fs.StringVar(&e.flags.logLevel, "log-level", "", "日志级别 debug|info|warn|error")
	fs.StringVar(&e.flags.logFormat, "log-format", "", "日志格式 text|json")
	fs.BoolVar(&e.flags.offline, "offline", false, "仅使用本地缓存情报")
	fs.Usage = func() { e.printHelp(e.stderr) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			e.printHelp(e.stdout)
			return exitcode.OK, nil
		}
		// flag 已把具体错误写到 stderr，这里只需给出退出码
		return exitcode.Usage, nil
	}

	rest := fs.Args()
	if len(rest) == 0 {
		e.printHelp(e.stdout)
		return exitcode.Usage, nil
	}

	cmd, cmdArgs := rest[0], rest[1:]
	switch cmd {
	case "version":
		return e.runVersion(cmdArgs)
	case "db":
		return e.runDB(ctx, cmdArgs)
	case "inventory":
		return e.runInventory(ctx, cmdArgs)
	case "help", "-h", "--help":
		return e.runHelp(cmdArgs)
	case "scan", "list", "show", "plan", "fix", "report", "feed", "support":
		// 已注册但未实现：明确失败，不静默返回成功
		return exitcode.NotImplemented, apperr.NotImplementedf("%s 尚未实现（%s）", cmd, phaseOf(cmd))
	default:
		return exitcode.Usage, apperr.Usagef("未知子命令: %s（运行 linux-cve help 查看用法）", cmd)
	}
}

// ensureConfig 惰性加载配置与日志器。version / help 不触发，避免无谓副作用。
func (e *env) ensureConfig() error {
	if e.cfg != nil {
		return nil
	}
	cfg, err := config.LoadWithEnv(e.flags.configPath, e.getenv)
	if err != nil {
		return err
	}

	// 命令行参数优先级最高
	if e.flags.dbPath != "" {
		cfg.General.DBPath = e.flags.dbPath
	}
	if e.flags.logLevel != "" {
		cfg.Logging.Level = e.flags.logLevel
	}
	if e.flags.logFormat != "" {
		cfg.Logging.Format = e.flags.logFormat
	}
	if e.flags.offline {
		cfg.General.Offline = true
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	logger, err := logging.New(e.stderr, cfg.Logging.Level, cfg.Logging.Format)
	if err != nil {
		return err
	}
	e.cfg = cfg
	e.log = logger
	return nil
}

// phaseOf 返回子命令所属阶段，用于未实现提示。
func phaseOf(cmd string) string {
	switch cmd {
	case "scan", "list", "show", "feed":
		return "阶段 3"
	case "plan", "fix":
		return "阶段 5"
	case "report":
		return "阶段 6"
	case "support":
		return "阶段 4"
	default:
		return "后续阶段"
	}
}
