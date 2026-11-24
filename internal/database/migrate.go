package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// migrationFS 内嵌全部迁移 SQL，二进制自带 Schema，不依赖外部文件。
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// migrationNamePattern 约束迁移文件命名：0001_init.sql。
var migrationNamePattern = regexp.MustCompile(`^(\d{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// Migration 是一个待执行的迁移。
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string // SQL 内容 SHA256，入库后用于检测手工篡改
}

// AppliedMigration 是已应用的迁移记录。
type AppliedMigration struct {
	Version   int
	Name      string
	Checksum  string
	AppliedAt string
}

// PendingMigration 是尚未应用的迁移（只暴露元信息）。
type PendingMigration struct {
	Version int
	Name    string
}

// Status 是数据库状态快照。
type Status struct {
	Path          string
	SchemaVersion int
	Applied       []AppliedMigration
	Pending       []PendingMigration
	FeedSources   int
}

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL,
    checksum   TEXT    NOT NULL,
    applied_at TEXT    NOT NULL
)`

// LoadMigrations 读取并排序内嵌迁移。
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.migrations", "读取内嵌迁移失败", err)
	}

	migrations := make([]Migration, 0, len(entries))
	seen := make(map[int]string, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		m := migrationNamePattern.FindStringSubmatch(name)
		if m == nil {
			return nil, apperr.Newf(exitcode.Error, "database.migrations",
				"迁移文件名不合规（应为 0001_init.sql）: %s", name)
		}
		version, err := strconv.Atoi(m[1])
		if err != nil || version <= 0 {
			return nil, apperr.Newf(exitcode.Error, "database.migrations",
				"迁移版本号非法: %s", name)
		}
		if prev, dup := seen[version]; dup {
			return nil, apperr.Newf(exitcode.Error, "database.migrations",
				"迁移版本号重复: %04d 同时出现在 %s 与 %s", version, prev, name)
		}
		seen[version] = name

		content, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.migrations",
				fmt.Sprintf("读取迁移 %s 失败", name), err)
		}
		sum := sha256.Sum256(content)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     m[2],
			SQL:      string(content),
			Checksum: hex.EncodeToString(sum[:]),
		})
	}
	if len(migrations) == 0 {
		return nil, apperr.New(exitcode.Error, "database.migrations", "未找到任何迁移文件")
	}

	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// Migrate 应用所有未执行的迁移，返回本次应用的条数。
//
// 前置校验：
//   - 已应用迁移的 checksum 必须与内嵌文件一致（防止手改库）
//   - 数据库中不能存在比二进制更新的版本（防止旧二进制写坏新库）
func (d *DB) Migrate(ctx context.Context) (int, error) {
	migrations, err := LoadMigrations()
	if err != nil {
		return 0, err
	}

	if _, err := d.db.ExecContext(ctx, createMigrationsTable); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.migrate", "创建迁移记录表失败", err)
	}

	applied, err := d.appliedMigrations(ctx)
	if err != nil {
		return 0, err
	}

	if err := validateApplied(applied, migrations); err != nil {
		return 0, err
	}

	appliedSet := make(map[int]struct{}, len(applied))
	for _, a := range applied {
		appliedSet[a.Version] = struct{}{}
	}

	count := 0
	for _, m := range migrations {
		if _, ok := appliedSet[m.Version]; ok {
			continue
		}
		if err := d.applyOne(ctx, m); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// validateApplied 校验已应用迁移与内嵌迁移的一致性。
//
// schema_migrations 是 Schema 版本的唯一权威来源。以下任一不一致都拒绝继续迁移：
//   - 库中存在二进制不认识的迁移记录
//   - 库 Schema 版本高于二进制内嵌版本（旧二进制不得操作新库）
//   - 已应用迁移的 checksum 与内嵌文件不符（防手改库）
//   - 迁移序列缺档（低版本未应用却存在更高版本记录，说明库被破坏或降级混用）
func validateApplied(applied []AppliedMigration, migrations []Migration) error {
	if len(migrations) == 0 {
		return apperr.New(exitcode.Error, "database.migrate", "未找到任何内嵌迁移")
	}
	byVersion := make(map[int]Migration, len(migrations))
	maxEmbedded := 0
	for _, m := range migrations {
		byVersion[m.Version] = m
		if m.Version > maxEmbedded {
			maxEmbedded = m.Version
		}
	}

	seen := make(map[int]struct{}, len(applied))
	maxApplied := 0
	for _, a := range applied {
		seen[a.Version] = struct{}{}
		if a.Version > maxApplied {
			maxApplied = a.Version
		}
		m, ok := byVersion[a.Version]
		if !ok {
			if a.Version > maxEmbedded {
				return apperr.Newf(exitcode.Integrity, "database.migrate",
					"数据库 Schema 版本 %d 高于本程序内置版本 %d，请升级 linux-cve", a.Version, maxEmbedded)
			}
			return apperr.Newf(exitcode.Integrity, "database.migrate",
				"数据库中存在本程序不认识的迁移记录: %04d_%s", a.Version, a.Name)
		}
		if a.Checksum != m.Checksum {
			return apperr.Newf(exitcode.Integrity, "database.migrate",
				"迁移 %04d_%s 校验和不一致，数据库可能被手工修改", a.Version, a.Name)
		}
	}

	for _, m := range migrations {
		if m.Version >= maxApplied {
			break
		}
		if _, ok := seen[m.Version]; !ok {
			return apperr.Newf(exitcode.Integrity, "database.migrate",
				"迁移序列缺档：%04d_%s 未应用却存在更高版本记录 %d，数据库不一致",
				m.Version, m.Name, maxApplied)
		}
	}
	return nil
}

// guardSchemaAge 在 Open 时拒绝 Schema 高于内置版本的数据库。
// 连只读命令也不得打开新库，避免旧二进制误读未知表结构。
func guardSchemaAge(ctx context.Context, d *DB) error {
	has, err := d.hasTable(ctx, "schema_migrations")
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.open", "探测迁移表失败", err)
	}
	if !has {
		return nil
	}
	var maxDB sql.NullInt64
	if err := d.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&maxDB); err != nil {
		return apperr.Wrap(exitcode.Error, "database.open", "读取 Schema 版本失败", err)
	}
	if !maxDB.Valid {
		return nil
	}
	migrations, err := LoadMigrations()
	if err != nil {
		return err
	}
	maxEmbedded := 0
	for _, m := range migrations {
		if m.Version > maxEmbedded {
			maxEmbedded = m.Version
		}
	}
	if int(maxDB.Int64) > maxEmbedded {
		return apperr.Newf(exitcode.Integrity, "database.open",
			"数据库 Schema 版本 %d 高于本程序内置版本 %d，请升级 linux-cve", int(maxDB.Int64), maxEmbedded)
	}
	return nil
}

// applyOne 在单个事务内执行一个迁移并记录。
func (d *DB) applyOne(ctx context.Context, m Migration) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.migrate",
			fmt.Sprintf("开启迁移事务失败: %04d_%s", m.Version, m.Name), err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return apperr.Wrap(exitcode.Error, "database.migrate",
			fmt.Sprintf("执行迁移失败: %04d_%s", m.Version, m.Name), err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.Version, m.Name, m.Checksum, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return apperr.Wrap(exitcode.Error, "database.migrate",
			fmt.Sprintf("写入迁移记录失败: %04d_%s", m.Version, m.Name), err)
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(exitcode.Error, "database.migrate",
			fmt.Sprintf("提交迁移失败: %04d_%s", m.Version, m.Name), err)
	}
	return nil
}

// appliedMigrations 读取已应用迁移，按版本升序。
func (d *DB) appliedMigrations(ctx context.Context) ([]AppliedMigration, error) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT version, name, checksum, applied_at FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.migrate", "读取迁移记录失败", err)
	}
	defer func() { _ = rows.Close() }()

	var out []AppliedMigration
	for rows.Next() {
		var a AppliedMigration
		if err := rows.Scan(&a.Version, &a.Name, &a.Checksum, &a.AppliedAt); err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.migrate", "解析迁移记录失败", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.migrate", "遍历迁移记录失败", err)
	}
	return out, nil
}

// Status 返回数据库当前状态（不修改任何数据）。
func (d *DB) Status(ctx context.Context) (Status, error) {
	migrations, err := LoadMigrations()
	if err != nil {
		return Status{}, err
	}
	st := Status{Path: d.path}

	has, err := d.hasTable(ctx, "schema_migrations")
	if err != nil {
		return Status{}, apperr.Wrap(exitcode.Error, "database.status", "探测迁移表失败", err)
	}
	if has {
		applied, err := d.appliedMigrations(ctx)
		if err != nil {
			return Status{}, err
		}
		st.Applied = applied
		for _, a := range applied {
			if a.Version > st.SchemaVersion {
				st.SchemaVersion = a.Version
			}
		}
	}

	appliedSet := make(map[int]struct{}, len(st.Applied))
	for _, a := range st.Applied {
		appliedSet[a.Version] = struct{}{}
	}
	for _, m := range migrations {
		if _, ok := appliedSet[m.Version]; !ok {
			st.Pending = append(st.Pending, PendingMigration{Version: m.Version, Name: m.Name})
		}
	}

	if ok, err := d.hasTable(ctx, "feed_sources"); err == nil && ok {
		var n int
		if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM feed_sources`).Scan(&n); err == nil {
			st.FeedSources = n
		}
	}
	return st, nil
}

// Meta 读取 app_meta 中的键值，不存在时返回空串。
func (d *DB) Meta(ctx context.Context, key string) (string, error) {
	var v string
	err := d.db.QueryRowContext(ctx, `SELECT value FROM app_meta WHERE key = ?`, key).Scan(&v)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", apperr.Wrap(exitcode.Error, "database.meta", "读取元信息失败", err)
	}
	return v, nil
}
