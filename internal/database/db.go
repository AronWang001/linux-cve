// Package database 负责 SQLite 的打开、连接参数与 Schema 迁移。
//
// 采用纯 Go 驱动 modernc.org/sqlite，不依赖 cgo，便于交叉编译 amd64/arm64。
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// driverName 是 modernc.org/sqlite 注册的驱动名。
const driverName = "sqlite"

// DB 包装 *sql.DB 并记录数据库绝对路径。
type DB struct {
	db   *sql.DB
	path string
}

// Open 打开（必要时创建）数据库并验证可连接。
func Open(ctx context.Context, path string) (*DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, apperr.New(exitcode.Usage, "database.open", "数据库路径为空")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.open",
			fmt.Sprintf("解析数据库路径失败: %s", path), err)
	}
	if dir := filepath.Dir(abs); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.open",
				fmt.Sprintf("创建数据库目录失败: %s", dir), err)
		}
	}

	h, err := sql.Open(driverName, buildDSN(abs))
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.open", "初始化数据库驱动失败", err)
	}

	// CLI 是单进程顺序执行。限制单连接可彻底避免 SQLite 写锁竞争，
	// 代价是失去并行读，对本工具的访问模式没有影响。
	h.SetMaxOpenConns(1)
	h.SetMaxIdleConns(1)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.PingContext(pingCtx); err != nil {
		_ = h.Close()
		return nil, apperr.Wrap(exitcode.Error, "database.open",
			fmt.Sprintf("打开数据库失败: %s", abs), err)
	}

	d := &DB{db: h, path: abs}
	// 数据库高于本二进制的 Schema 版本时拒绝打开（含只读命令），
	// 防止旧程序误读未知表结构或写坏新库。
	if err := guardSchemaAge(ctx, d); err != nil {
		_ = h.Close()
		return nil, err
	}
	return d, nil
}

// buildDSN 拼装 modernc sqlite 的 DSN，PRAGMA 通过 _pragma 参数在连接建立时生效。
//
// foreign_keys 是连接级设置，必须走 DSN；journal_mode(WAL) 是库级持久设置，
// 放在这里只是保证新建库时立即生效。
func buildDSN(abs string) string {
	return "file:" + filepath.ToSlash(abs) +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"
}

// Close 关闭数据库连接。
func (d *DB) Close() error {
	if d == nil || d.db == nil {
		return nil
	}
	return d.db.Close()
}

// SQL 返回底层连接，供后续阶段的事务与查询使用。
func (d *DB) SQL() *sql.DB { return d.db }

// Path 返回数据库绝对路径。
func (d *DB) Path() string { return d.path }

// hasTable 判断表是否存在，用于在迁移前后安全探测。
func (d *DB) hasTable(ctx context.Context, name string) (bool, error) {
	var n int
	err := d.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
