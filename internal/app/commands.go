package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/buildinfo"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/database"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// runVersion 输出构建信息。
func (e *env) runVersion(args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}

	if asJSON {
		b, err := json.MarshalIndent(buildinfo.Get(), "", "  ")
		if err != nil {
			return exitcode.Error, apperr.Wrap(exitcode.Error, "version", "序列化版本信息失败", err)
		}
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}
	fmt.Fprintln(e.stdout, buildinfo.String())
	return exitcode.OK, nil
}

// runDB 分发数据库子命令。
func (e *env) runDB(ctx context.Context, args []string) (exitcode.Code, error) {
	if len(args) == 0 {
		return exitcode.Usage, apperr.Usagef("db 需要子命令: status | migrate")
	}
	switch args[0] {
	case "status":
		return e.dbStatus(ctx)
	case "migrate":
		return e.dbMigrate(ctx)
	default:
		return exitcode.Usage, apperr.Usagef("未知的 db 子命令: %s（可选 status | migrate）", args[0])
	}
}

// dbStatus 展示数据库路径、Schema 版本与迁移记录。
func (e *env) dbStatus(ctx context.Context) (exitcode.Code, error) {
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}

	// 只读语义：库不存在时直接汇报未初始化，不创建空文件
	if _, err := os.Stat(e.cfg.General.DBPath); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(e.stdout, "database    : %s\n", e.cfg.General.DBPath)
		fmt.Fprintf(e.stdout, "schema      : 0\n")
		fmt.Fprintf(e.stdout, "state       : not initialized（运行 linux-cve db migrate 初始化）\n")
		return exitcode.OK, nil
	}

	d, err := database.Open(ctx, e.cfg.General.DBPath)
	if err != nil {
		return exitcode.Error, err
	}
	defer func() { _ = d.Close() }()

	st, err := d.Status(ctx)
	if err != nil {
		return exitcode.Error, err
	}

	fmt.Fprintf(e.stdout, "database    : %s\n", st.Path)
	fmt.Fprintf(e.stdout, "schema      : %d\n", st.SchemaVersion)

	if len(st.Applied) == 0 {
		fmt.Fprintf(e.stdout, "migrations  : none（运行 linux-cve db migrate 初始化）\n")
	} else {
		parts := make([]string, 0, len(st.Applied))
		for _, a := range st.Applied {
			parts = append(parts, fmt.Sprintf("%04d_%s (%s)", a.Version, a.Name, a.AppliedAt))
		}
		fmt.Fprintf(e.stdout, "migrations  : %s\n", strings.Join(parts, ", "))
	}

	if len(st.Pending) == 0 {
		fmt.Fprintf(e.stdout, "pending     : none\n")
	} else {
		parts := make([]string, 0, len(st.Pending))
		for _, p := range st.Pending {
			parts = append(parts, fmt.Sprintf("%04d_%s", p.Version, p.Name))
		}
		fmt.Fprintf(e.stdout, "pending     : %s\n", strings.Join(parts, ", "))
	}

	fmt.Fprintf(e.stdout, "feed sources: %d registered\n", st.FeedSources)
	return exitcode.OK, nil
}

// dbMigrate 应用未执行的迁移。
func (e *env) dbMigrate(ctx context.Context) (exitcode.Code, error) {
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}

	d, err := database.Open(ctx, e.cfg.General.DBPath)
	if err != nil {
		return exitcode.Error, err
	}
	defer func() { _ = d.Close() }()

	n, err := d.Migrate(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	st, err := d.Status(ctx)
	if err != nil {
		return exitcode.Error, err
	}

	if n == 0 {
		fmt.Fprintf(e.stdout, "no pending migration; schema version = %d\n", st.SchemaVersion)
	} else {
		fmt.Fprintf(e.stdout, "applied %d migration(s); schema version = %d\n", n, st.SchemaVersion)
	}
	return exitcode.OK, nil
}

// runHelp 打印帮助；带参数时只打印该命令的用法。
func (e *env) runHelp(args []string) (exitcode.Code, error) {
	if len(args) > 0 {
		e.printCommandHelp(e.stdout, args[0])
		return exitcode.OK, nil
	}
	e.printHelp(e.stdout)
	return exitcode.OK, nil
}

// printHelp 打印总帮助。
func (e *env) printHelp(w io.Writer) {
	fmt.Fprint(w, `linux-cve — Linux 系统软件包 CVE 检测与自动修复

用法:
  linux-cve [全局参数] <命令> [命令参数]

命令:
  inventory         采集本机资产（软件包、内核、发行版）
  scan              扫描本机漏洞
  list              列出扫描结果
  show <CVE>        查看单个 CVE 详情与判定依据
  plan [CVE...]     生成修复计划（不执行）
  fix  [CVE...]     执行修复并复检
  report            输出 TXT / JSON 报告
  feed update       更新漏洞情报库
  feed status       查看各情报源状态
  support           打印支持矩阵
  db status         查看数据库状态
  db migrate        应用数据库迁移
  version           版本信息
  help [命令]       帮助

全局参数:
  --config <路径>       配置文件（默认 /etc/linux-cve/config.toml）
  --db <路径>           数据库路径
  --log-level <级别>    debug|info|warn|error
  --log-format <格式>   text|json
  --offline             仅使用本地缓存情报

退出码:
  0 成功  2 参数错误  3 发现漏洞  4 不支持  5 权限不足
  6 修复失败  7 完整性校验失败  8 未实现  9 覆盖不足  130 中断
`)
}

// printCommandHelp 打印单个命令的用法。
func (e *env) printCommandHelp(w io.Writer, cmd string) {
	switch cmd {
	case "version":
		fmt.Fprint(w, "用法: linux-cve version [--json]\n")
	case "db":
		fmt.Fprint(w, "用法: linux-cve db status | linux-cve db migrate\n")
	case "inventory":
		fmt.Fprint(w, "用法: linux-cve inventory [--json] [--save]\n\n  采集本机资产（软件包、内核、发行版）。\n  --json   以 JSON 输出采集结果\n  --save   将采集结果持久化到数据库\n")
	case "feed":
		fmt.Fprint(w, "用法: linux-cve feed update [源...] | linux-cve feed status [--json]\n\n"+
			"  更新漏洞情报库 / 查看各情报源状态。\n"+
			"  不带源名时更新全部已接入的源；源名见 feed status 的 ID 列。\n")
	case "support":
		fmt.Fprint(w, "用法: linux-cve support [--json]\n\n  打印发行版支持矩阵与自动修复许可。\n")
	case "scan":
		fmt.Fprint(w, "用法: linux-cve scan [--json] [--dry-run]\n\n"+
			"  采集本机资产并对照情报库判定。\n"+
			"  --json     以 JSON 输出\n"+
			"  --dry-run  只判定不写库\n")
	case "list":
		fmt.Fprint(w, "用法: linux-cve list [--json] [--vulnerable] [--state 状态] [--limit N]\n\n"+
			"  列出最近一次扫描的判定结果。\n")
	case "show":
		fmt.Fprint(w, "用法: linux-cve show <CVE-ID> [--json]\n\n  查看单个 CVE 的判定依据。\n")
	case "report":
		fmt.Fprint(w, "用法: linux-cve report [--json] [--save <路径>]\n\n"+
			"  输出最近一次扫描的报告（默认 Markdown）。\n")
	case "plan":
		fmt.Fprint(w, "用法: linux-cve plan [--json]\n\n"+
			"  基于最近一次扫描生成修复计划（只预演，不改系统）。\n")
	case "fix":
		fmt.Fprint(w, "用法: linux-cve fix [--yes] [--json]\n\n"+
			"  执行修复计划并复检。\n"+
			"  不带 --yes 时等同于 plan，绝不因为漏写参数就动系统。\n")
	default:
		fmt.Fprintf(w, "未知命令: %s\n", cmd)
		e.printHelp(w)
	}
}
