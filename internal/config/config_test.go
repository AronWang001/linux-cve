package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// noEnv 模拟「没有任何环境变量」的运行环境。
func noEnv(string) string { return "" }

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("写入测试配置失败: %v", err)
	}
	return path
}

func TestDefault(t *testing.T) {
	c := Default()
	if c.Logging.Level != "info" || c.Logging.Format != "text" {
		t.Errorf("默认日志配置应为 info/text，实际 %s/%s", c.Logging.Level, c.Logging.Format)
	}
	if c.Remediation.AllowAutoFix {
		t.Error("默认必须关闭自动修复（allow_auto_fix=false）")
	}
	if c.Remediation.MaxCollateralPackages != 5 {
		t.Errorf("默认附带变更上限应为 5，实际 %d", c.Remediation.MaxCollateralPackages)
	}
	if c.General.DBPath == "" || c.General.DataDir == "" {
		t.Error("默认数据库路径与数据目录不能为空")
	}
	if err := c.Validate(); err != nil {
		t.Errorf("默认配置应通过校验: %v", err)
	}
}

func TestLoadFileOverridesDefaults(t *testing.T) {
	path := writeTempConfig(t, `
[general]
db_path = "/tmp/test-linux-cve.db"
offline = true
[logging]
level = "warn"
format = "json"
[feed]
http_timeout = "30s"
max_age = "24h"
[remediation]
allow_auto_fix = true
max_collateral_packages = 3
`)
	c, err := LoadWithEnv(path, noEnv)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if c.General.DBPath != "/tmp/test-linux-cve.db" || !c.General.Offline {
		t.Errorf("general 段未生效: %+v", c.General)
	}
	if c.Logging.Level != "warn" || c.Logging.Format != "json" {
		t.Errorf("logging 段未生效: %+v", c.Logging)
	}
	if c.Feed.HTTPTimeout.Duration().Seconds() != 30 {
		t.Errorf("http_timeout 应为 30s，实际 %s", c.Feed.HTTPTimeout)
	}
	if c.Feed.MaxAge.Duration().Hours() != 24 {
		t.Errorf("max_age 应为 24h，实际 %s", c.Feed.MaxAge)
	}
	if !c.Remediation.AllowAutoFix || c.Remediation.MaxCollateralPackages != 3 {
		t.Errorf("remediation 段未生效: %+v", c.Remediation)
	}
	if c.Path != path {
		t.Errorf("Path 应记录实际加载路径，实际 %q", c.Path)
	}
}

func TestPartialFileKeepsDefaults(t *testing.T) {
	path := writeTempConfig(t, "[logging]\nlevel = \"debug\"\n")
	c, err := LoadWithEnv(path, noEnv)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if c.Logging.Level != "debug" {
		t.Errorf("level 应为 debug，实际 %s", c.Logging.Level)
	}
	// 未出现在文件中的键必须保留默认值，而不是被零值覆盖
	if c.Feed.HTTPTimeout.Duration().Seconds() != 60 {
		t.Errorf("http_timeout 应保留默认 60s，实际 %s", c.Feed.HTTPTimeout)
	}
	if c.General.DBPath == "" {
		t.Error("db_path 应保留默认值")
	}
}

func TestEnvOverridesFile(t *testing.T) {
	path := writeTempConfig(t, "[logging]\nlevel = \"debug\"\n")
	env := func(k string) string {
		switch k {
		case "LINUX_CVE_LOG_LEVEL":
			return "error"
		case "LINUX_CVE_MAX_COLLATERAL_PACKAGES":
			return "9"
		case "LINUX_CVE_OFFLINE":
			return "true"
		}
		return ""
	}
	c, err := LoadWithEnv(path, env)
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if c.Logging.Level != "error" {
		t.Errorf("环境变量应覆盖文件，实际 %s", c.Logging.Level)
	}
	if c.Remediation.MaxCollateralPackages != 9 {
		t.Errorf("环境变量 max_collateral_packages 应生效，实际 %d", c.Remediation.MaxCollateralPackages)
	}
	if !c.General.Offline {
		t.Error("环境变量 offline 应生效")
	}
}

func TestExplicitMissingFileFails(t *testing.T) {
	_, err := LoadWithEnv(filepath.Join(t.TempDir(), "absent.toml"), noEnv)
	if err == nil {
		t.Fatal("显式指定不存在的配置文件应报错")
	}
	if got := apperr.CodeOf(err); got != exitcode.Usage {
		t.Errorf("退出码应为 USAGE，实际 %v", got)
	}
}

func TestInvalidLogLevelFails(t *testing.T) {
	path := writeTempConfig(t, "[logging]\nlevel = \"verbose\"\n")
	_, err := LoadWithEnv(path, noEnv)
	if err == nil {
		t.Fatal("非法日志级别应报错")
	}
	if !strings.Contains(err.Error(), "日志级别") {
		t.Errorf("错误信息应说明日志级别问题，实际: %v", err)
	}
}

func TestInvalidDurationFails(t *testing.T) {
	path := writeTempConfig(t, "[feed]\nhttp_timeout = \"很快\"\n")
	_, err := LoadWithEnv(path, noEnv)
	if err == nil {
		t.Fatal("非法时间间隔应报错")
	}
	if got := apperr.CodeOf(err); got != exitcode.Usage {
		t.Errorf("退出码应为 USAGE，实际 %v", got)
	}
}

func TestValidateRejectsEmptyDBPath(t *testing.T) {
	c := Default()
	c.General.DBPath = "  "
	if err := c.Validate(); err == nil {
		t.Fatal("空 db_path 应被拒绝")
	}
}

func TestValidateDerivesDataDir(t *testing.T) {
	c := Default()
	c.General.DataDir = ""
	c.General.DBPath = filepath.Join("var", "lib", "linux-cve", "linux-cve.db")
	if err := c.Validate(); err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if c.General.DataDir != filepath.Join("var", "lib", "linux-cve") {
		t.Errorf("data_dir 应由 db_path 推导，实际 %q", c.General.DataDir)
	}
}

func TestDefaultPathNotEmpty(t *testing.T) {
	if DefaultPath() == "" {
		t.Error("默认配置路径不能为空")
	}
}
