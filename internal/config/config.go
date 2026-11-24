// Package config 负责配置的默认值、文件加载、环境变量覆盖与校验。
//
// 优先级（后者覆盖前者）：内置默认值 → 配置文件 → 环境变量 → 命令行参数。
// 配置文件格式为 TOML，因为它对运维人员最友好且支持注释。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// Duration 让 TOML 里的 "60s" 这类字符串可直接解析为时间间隔。
type Duration time.Duration

// Duration 返回标准库时间间隔。
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// String 返回可读字符串。
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalText 实现 encoding.TextUnmarshaler，供 TOML 解码使用。
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("无法解析时间间隔 %q: %w", string(b), err)
	}
	if v < 0 {
		return fmt.Errorf("时间间隔不能为负: %q", string(b))
	}
	*d = Duration(v)
	return nil
}

// General 是通用配置。
type General struct {
	DBPath  string `toml:"db_path"`
	DataDir string `toml:"data_dir"`
	Offline bool   `toml:"offline"`
}

// Logging 是日志配置。
type Logging struct {
	Level  string `toml:"level"`  // debug|info|warn|error
	Format string `toml:"format"` // text|json
}

// Feed 是情报抓取配置。
type Feed struct {
	HTTPTimeout Duration `toml:"http_timeout"`
	MaxAge      Duration `toml:"max_age"`
}

// Remediation 是修复配置。
// AllowAutoFix 是硬开关：为 false 时命令行 --yes 也不能绕过。
type Remediation struct {
	AllowAutoFix          bool `toml:"allow_auto_fix"`
	MaxCollateralPackages int  `toml:"max_collateral_packages"`
}

// Config 是完整配置。
type Config struct {
	// Path 是实际加载的配置文件路径，空表示全部使用默认值。
	Path        string      `toml:"-"`
	General     General     `toml:"general"`
	Logging     Logging     `toml:"logging"`
	Feed        Feed        `toml:"feed"`
	Remediation Remediation `toml:"remediation"`
}

// Default 返回内置默认配置。
func Default() *Config {
	dbPath := defaultDBPath()
	return &Config{
		General: General{
			DBPath:  dbPath,
			DataDir: filepath.Dir(dbPath),
			Offline: false,
		},
		Logging: Logging{Level: "info", Format: "text"},
		Feed: Feed{
			HTTPTimeout: Duration(60 * time.Second),
			MaxAge:      Duration(72 * time.Hour),
		},
		Remediation: Remediation{
			AllowAutoFix:          false,
			MaxCollateralPackages: 5,
		},
	}
}

// DefaultPath 返回默认配置文件路径。
//
// Linux 走 /etc/linux-cve/config.toml；其他平台回退到用户配置目录，
// 便于开发机（Windows/macOS）运行同一份代码。
func DefaultPath() string {
	if runtime.GOOS == "linux" {
		return "/etc/linux-cve/config.toml"
	}
	return filepath.Join(userConfigDir(), "linux-cve", "config.toml")
}

// defaultDBPath 返回默认数据库路径。
func defaultDBPath() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/linux-cve/linux-cve.db"
	}
	return filepath.Join(userDataDir(), "linux-cve", "linux-cve.db")
}

// userConfigDir 返回用户配置目录，取不到时退化为当前目录。
func userConfigDir() string {
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		return d
	}
	return "."
}

// userDataDir 返回用户数据目录。
func userDataDir() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return d
		}
	}
	if d, err := os.UserConfigDir(); err == nil && d != "" {
		return d
	}
	return "."
}

// Load 加载配置。
//
// explicitPath 非空时必须是存在的文件，否则报错；
// 为空时依次尝试环境变量 LINUX_CVE_CONFIG 与默认路径，都不存在则用默认值。
func Load(explicitPath string) (*Config, error) {
	return LoadWithEnv(explicitPath, os.Getenv)
}

// LoadWithEnv 与 Load 相同，但可注入环境变量读取函数，便于测试。
func LoadWithEnv(explicitPath string, getenv func(string) string) (*Config, error) {
	cfg := Default()

	path := explicitPath
	required := path != ""
	if path == "" {
		if p := getenv("LINUX_CVE_CONFIG"); p != "" {
			path = p
			required = true
		}
	}
	if path == "" {
		path = DefaultPath()
	}

	if _, err := os.Stat(path); err == nil {
		// 解码到已有默认值的结构上：文件中未出现的键保持默认值
		if _, err := toml.DecodeFile(path, cfg); err != nil {
			return nil, apperr.Wrap(exitcode.Usage, "config.load",
				fmt.Sprintf("解析配置文件 %s 失败", path), err)
		}
		cfg.Path = path
	} else if required {
		return nil, apperr.Wrap(exitcode.Usage, "config.load",
			fmt.Sprintf("配置文件不存在: %s", path), err)
	}

	applyEnv(cfg, getenv)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv 应用环境变量覆盖。空值不覆盖。
func applyEnv(cfg *Config, getenv func(string) string) {
	if v := getenv("LINUX_CVE_DB_PATH"); v != "" {
		cfg.General.DBPath = v
	}
	if v := getenv("LINUX_CVE_DATA_DIR"); v != "" {
		cfg.General.DataDir = v
	}
	if v := getenv("LINUX_CVE_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := getenv("LINUX_CVE_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	}
	if v := getenv("LINUX_CVE_OFFLINE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.General.Offline = b
		}
	}
	if v := getenv("LINUX_CVE_ALLOW_AUTO_FIX"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Remediation.AllowAutoFix = b
		}
	}
	if v := getenv("LINUX_CVE_MAX_COLLATERAL_PACKAGES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Remediation.MaxCollateralPackages = n
		}
	}
}

// Validate 校验配置取值，并补齐可推导字段。
func (c *Config) Validate() error {
	if strings.TrimSpace(c.General.DBPath) == "" {
		return apperr.New(exitcode.Usage, "config.validate", "db_path 不能为空")
	}
	if c.General.DataDir == "" {
		c.General.DataDir = filepath.Dir(c.General.DBPath)
	}
	switch c.Logging.Level {
	case "debug", "info", "warn", "error":
	default:
		return apperr.Newf(exitcode.Usage, "config.validate",
			"非法的日志级别 %q（可选 debug|info|warn|error）", c.Logging.Level)
	}
	switch c.Logging.Format {
	case "text", "json":
	default:
		return apperr.Newf(exitcode.Usage, "config.validate",
			"非法的日志格式 %q（可选 text|json）", c.Logging.Format)
	}
	if c.Feed.HTTPTimeout.Duration() <= 0 {
		return apperr.New(exitcode.Usage, "config.validate", "feed.http_timeout 必须大于 0")
	}
	if c.Feed.MaxAge.Duration() <= 0 {
		return apperr.New(exitcode.Usage, "config.validate", "feed.max_age 必须大于 0")
	}
	if c.Remediation.MaxCollateralPackages < 0 {
		return apperr.New(exitcode.Usage, "config.validate", "max_collateral_packages 不能为负")
	}
	return nil
}

// EnsureDataDir 创建数据目录（含父目录），权限 0750。
func (c *Config) EnsureDataDir() error {
	if err := os.MkdirAll(c.General.DataDir, 0o750); err != nil {
		return apperr.Wrap(exitcode.Error, "config.mkdir",
			fmt.Sprintf("创建数据目录 %s 失败", c.General.DataDir), err)
	}
	return nil
}
