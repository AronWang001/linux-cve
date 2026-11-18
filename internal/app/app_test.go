package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// runCLI 执行一次命令，返回退出码、stdout 与 stderr。
func runCLI(t *testing.T, args ...string) (exitcode.Code, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := Main(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// isolatedArgs 生成隔离环境参数：临时配置文件 + 临时数据库，避免读写真实路径。
func isolatedArgs(t *testing.T) (cfgPath, dbPath string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[logging]\nlevel = \"info\"\n"), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	return cfgPath, filepath.Join(dir, "linux-cve.db")
}

func TestVersionCommand(t *testing.T) {
	code, out, errOut := runCLI(t, "version")
	if code != exitcode.OK {
		t.Fatalf("退出码应为 0，实际 %d（stderr: %s）", code, errOut)
	}
	if !strings.Contains(out, "linux-cve ") {
		t.Errorf("版本输出应包含程序名，实际 %q", out)
	}
	if !strings.Contains(out, "commit ") || !strings.Contains(out, "go") {
		t.Errorf("版本输出应包含提交与 Go 版本，实际 %q", out)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := runCLI(t, "version", "--json")
	if code != exitcode.OK {
		t.Fatalf("退出码应为 0，实际 %d", code)
	}
	var info struct {
		Version  string `json:"version"`
		Platform string `json:"platform"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("JSON 输出无法解析: %v（原始输出 %q）", err, out)
	}
	if info.Version == "" || info.Platform == "" {
		t.Errorf("JSON 字段缺失: %+v", info)
	}
}

// TestUnimplementedCommands 未实现的子命令必须明确失败，不能静默成功。
func TestUnimplementedCommands(t *testing.T) {
	for _, cmd := range []string{"scan", "list", "show", "plan", "fix", "report", "feed", "support"} {
		code, out, errOut := runCLI(t, cmd)
		if code != exitcode.NotImplemented {
			t.Errorf("%s 退出码应为 8，实际 %d", cmd, code)
		}
		if out != "" {
			t.Errorf("%s 不应向 stdout 输出内容，实际 %q", cmd, out)
		}
		if !strings.Contains(errOut, "尚未实现") {
			t.Errorf("%s 应说明未实现，实际 %q", cmd, errOut)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	code, _, errOut := runCLI(t, "hack")
	if code != exitcode.Usage {
		t.Errorf("未知命令退出码应为 2，实际 %d", code)
	}
	if !strings.Contains(errOut, "未知子命令") {
		t.Errorf("应提示未知子命令，实际 %q", errOut)
	}
}

func TestNoArgsShowsHelp(t *testing.T) {
	code, out, _ := runCLI(t)
	if code != exitcode.Usage {
		t.Errorf("无参数退出码应为 2（已打印帮助），实际 %d", code)
	}
	if !strings.Contains(out, "用法:") {
		t.Errorf("无参数应打印帮助，实际 %q", out)
	}
}

func TestHelpCommand(t *testing.T) {
	code, out, _ := runCLI(t, "help")
	if code != exitcode.OK {
		t.Errorf("help 退出码应为 0，实际 %d", code)
	}
	if !strings.Contains(out, "退出码:") {
		t.Errorf("帮助应包含退出码说明，实际 %q", out)
	}

	code, out, _ = runCLI(t, "help", "version")
	if code != exitcode.OK || !strings.Contains(out, "--json") {
		t.Errorf("命令级帮助应说明参数，实际 %q（code %d）", out, code)
	}
}

func TestDBCommands(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)

	// 迁移前状态应为 schema 0
	code, out, errOut := runCLI(t, "--config", cfgPath, "--db", dbPath, "db", "status")
	if code != exitcode.OK {
		t.Fatalf("db status 退出码应为 0，实际 %d（%s）", code, errOut)
	}
	if !strings.Contains(out, "schema      : 0") {
		t.Errorf("迁移前 schema 应为 0，实际 %q", out)
	}
	// 只读语义：status 不应创建数据库文件
	if _, statErr := os.Stat(dbPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("db status 不应创建数据库文件，实际 stat 错误: %v", statErr)
	}

	// 执行迁移
	code, out, errOut = runCLI(t, "--config", cfgPath, "--db", dbPath, "db", "migrate")
	if code != exitcode.OK {
		t.Fatalf("db migrate 退出码应为 0，实际 %d（%s）", code, errOut)
	}
	if !strings.Contains(out, "applied 1 migration(s); schema version = 1") {
		t.Errorf("迁移输出不符，实际 %q", out)
	}

	// 再次迁移应无待应用项
	code, out, _ = runCLI(t, "--config", cfgPath, "--db", dbPath, "db", "migrate")
	if code != exitcode.OK || !strings.Contains(out, "no pending migration") {
		t.Errorf("重复迁移应提示无待应用项，实际 %q（code %d）", out, code)
	}

	// 迁移后状态
	code, out, _ = runCLI(t, "--config", cfgPath, "--db", dbPath, "db", "status")
	if code != exitcode.OK {
		t.Fatalf("db status 退出码应为 0，实际 %d", code)
	}
	for _, want := range []string{"schema      : 1", "0001_init", "pending     : none"} {
		if !strings.Contains(out, want) {
			t.Errorf("状态输出应包含 %q，实际 %q", want, out)
		}
	}
}

func TestDBSubcommandValidation(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)

	code, _, errOut := runCLI(t, "--config", cfgPath, "--db", dbPath, "db")
	if code != exitcode.Usage || !strings.Contains(errOut, "db 需要子命令") {
		t.Errorf("缺子命令应返回 2 并提示，实际 %d / %q", code, errOut)
	}

	code, _, errOut = runCLI(t, "--config", cfgPath, "--db", dbPath, "db", "drop")
	if code != exitcode.Usage || !strings.Contains(errOut, "未知的 db 子命令") {
		t.Errorf("未知子命令应返回 2 并提示，实际 %d / %q", code, errOut)
	}
}

func TestMissingConfigFileFails(t *testing.T) {
	code, _, errOut := runCLI(t, "--config", filepath.Join(t.TempDir(), "nope.toml"), "db", "status")
	if code != exitcode.Usage {
		t.Errorf("显式指定的配置文件不存在时应返回 2，实际 %d", code)
	}
	if !strings.Contains(errOut, "配置文件不存在") {
		t.Errorf("应提示配置文件不存在，实际 %q", errOut)
	}
}

func TestInvalidLogLevelFlag(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	code, _, errOut := runCLI(t, "--config", cfgPath, "--db", dbPath, "--log-level", "verbose", "db", "status")
	if code != exitcode.Usage {
		t.Errorf("非法日志级别应返回 2，实际 %d", code)
	}
	if !strings.Contains(errOut, "日志级别") {
		t.Errorf("应提示日志级别非法，实际 %q", errOut)
	}
}
