package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// newTestDB 在临时目录创建独立数据库，测试结束自动关闭并删除。
func newTestDB(t *testing.T) *DB {
	t.Helper()
	ctx := context.Background()
	d, err := Open(ctx, filepath.Join(t.TempDir(), "linux-cve.db"))
	if err != nil {
		t.Fatalf("打开测试数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestLoadMigrationsOrdered(t *testing.T) {
	migs, err := LoadMigrations()
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("应至少加载到一个迁移")
	}
	for i := 1; i < len(migs); i++ {
		if migs[i-1].Version >= migs[i].Version {
			t.Fatalf("迁移未按版本升序排列: %d >= %d", migs[i-1].Version, migs[i].Version)
		}
	}
	if migs[0].Checksum == "" || len(migs[0].Checksum) != 64 {
		t.Errorf("迁移校验和应为 SHA256 十六进制串，实际 %q", migs[0].Checksum)
	}
}

func TestStatusBeforeMigrate(t *testing.T) {
	d := newTestDB(t)
	st, err := d.Status(context.Background())
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	if st.SchemaVersion != 0 {
		t.Errorf("迁移前 schema 版本应为 0，实际 %d", st.SchemaVersion)
	}
	if len(st.Applied) != 0 {
		t.Errorf("迁移前不应有已应用记录，实际 %d", len(st.Applied))
	}
	if len(st.Pending) == 0 {
		t.Error("迁移前应有待应用迁移")
	}
	if st.FeedSources != 0 {
		t.Errorf("迁移前情报源计数应为 0，实际 %d", st.FeedSources)
	}
}

func TestMigrateFreshDatabase(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)

	n, err := d.Migrate(ctx)
	if err != nil {
		t.Fatalf("首次迁移失败: %v", err)
	}
	if n != 1 {
		t.Errorf("首次应应用 1 个迁移，实际 %d", n)
	}

	st, err := d.Status(ctx)
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	if st.SchemaVersion != 1 {
		t.Errorf("schema 版本应为 1，实际 %d", st.SchemaVersion)
	}
	if len(st.Applied) != 1 || st.Applied[0].Name != "init" {
		t.Errorf("已应用记录不符: %+v", st.Applied)
	}
	if len(st.Pending) != 0 {
		t.Errorf("不应存在待应用迁移，实际 %+v", st.Pending)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("首次迁移失败: %v", err)
	}
	n, err := d.Migrate(ctx)
	if err != nil {
		t.Fatalf("重复迁移应成功: %v", err)
	}
	if n != 0 {
		t.Errorf("重复迁移应应用 0 个，实际 %d", n)
	}
}

// TestSeedData 校验种子数据，尤其是 Amazon Linux 2 的 Legacy 定位。
func TestSeedData(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	var distros int
	if err := d.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM distros`).Scan(&distros); err != nil {
		t.Fatalf("统计发行版失败: %v", err)
	}
	if distros != 13 {
		t.Errorf("应登记 13 个发行版，实际 %d", distros)
	}

	var lifecycle, eol string
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT lifecycle_state, COALESCE(eol_date,'') FROM distro_releases WHERE id = 'amzn:2'`).
		Scan(&lifecycle, &eol); err != nil {
		t.Fatalf("查询 amzn:2 失败: %v", err)
	}
	if lifecycle != "legacy" {
		t.Errorf("Amazon Linux 2 必须为 legacy，实际 %q", lifecycle)
	}
	if eol != "2026-06-30" {
		t.Errorf("Amazon Linux 2 EOL 应为 2026-06-30，实际 %q", eol)
	}

	var debian12 string
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT lifecycle_state FROM distro_releases WHERE id = 'debian:12'`).Scan(&debian12); err != nil {
		t.Fatalf("查询 debian:12 失败: %v", err)
	}
	if debian12 != "active" {
		t.Errorf("Debian 12 应为 active，实际 %q", debian12)
	}

	var schemaVersion string
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT value FROM app_meta WHERE key = 'schema_version'`).Scan(&schemaVersion); err != nil {
		t.Fatalf("读取 schema_version 失败: %v", err)
	}
	if schemaVersion != "1" {
		t.Errorf("app_meta.schema_version 应为 1，实际 %q", schemaVersion)
	}
}

// seedAdvisory 插入一条公告，供修复版本相关测试使用。
func seedAdvisory(t *testing.T, d *DB, sourceID, advisoryID, cveID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := d.SQL().ExecContext(ctx,
		`INSERT OR IGNORE INTO feed_sources (id, name, kind, url, trust_level) VALUES (?, ?, 'tracker', 'https://example.invalid', 'B')`,
		sourceID, "test source"); err != nil {
		t.Fatalf("插入情报源失败: %v", err)
	}
	uid := advisoryID + "-" + cveID
	if _, err := d.SQL().ExecContext(ctx,
		`INSERT INTO advisories (uid, source_id, advisory_id, cve_id, fetched_at) VALUES (?, ?, ?, ?, ?)`,
		uid, sourceID, advisoryID, cveID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("插入公告失败: %v", err)
	}
}

func insertFix(t *testing.T, d *DB, distroID, release, channel, pkg, version string) error {
	t.Helper()
	_, err := d.SQL().ExecContext(context.Background(),
		`INSERT INTO advisory_fixes
		 (advisory_uid, source_id, advisory_id, cve_id, distro_id, release, channel,
		  package_kind, package_name, arch, fixed_version_raw, fixed_version)
		 VALUES ('DSA-1-CVE-2026-0001','debian-tracker','DSA-1','CVE-2026-0001',?,?,?,'source',?,'any',?,?)`,
		distroID, release, channel, pkg, version, version)
	return err
}

// TestAdvisoryFixUniqueScopedByCoordinate 固化修订 2：
// 唯一键必须包含 发行版 + release + 渠道 + 包类型 + 包名 + 架构，
// 否则同包名跨发行版会互相覆盖。
func TestAdvisoryFixUniqueScopedByCoordinate(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	seedAdvisory(t, d, "debian-tracker", "DSA-1", "CVE-2026-0001")

	// 同一包名，不同发行版：必须都能存在
	if err := insertFix(t, d, "debian", "12", "bookworm-security", "openssl", "3.0.11-1~deb12u2"); err != nil {
		t.Fatalf("插入 debian 修复记录失败: %v", err)
	}
	if err := insertFix(t, d, "ubuntu", "24.04", "noble-updates", "openssl", "3.0.13-0ubuntu3.5"); err != nil {
		t.Fatalf("插入 ubuntu 修复记录失败（说明唯一键缺少 distro 维度）: %v", err)
	}
	// 同一发行版，不同 release：也必须都能存在
	if err := insertFix(t, d, "debian", "13", "trixie-security", "openssl", "3.0.16-1"); err != nil {
		t.Fatalf("插入 debian 13 修复记录失败（说明唯一键缺少 release 维度）: %v", err)
	}
	// 同一 release，不同渠道：也必须都能存在
	if err := insertFix(t, d, "debian", "12", "bookworm-backports", "openssl", "3.0.16-1~bpo12+1"); err != nil {
		t.Fatalf("插入 backports 记录失败（说明唯一键缺少 channel 维度）: %v", err)
	}

	var n int
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM advisory_fixes WHERE package_name = 'openssl'`).Scan(&n); err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 4 {
		t.Errorf("应有 4 条互不冲突的修复记录，实际 %d", n)
	}

	// 完全相同的坐标必须被唯一索引拒绝
	if err := insertFix(t, d, "debian", "12", "bookworm-security", "openssl", "3.0.11-1~deb12u2"); err == nil {
		t.Error("重复坐标应被唯一索引拒绝")
	}
}

func TestForeignKeyEnforced(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	seedAdvisory(t, d, "debian-tracker", "DSA-1", "CVE-2026-0001")

	// 未登记的发行版必须被外键拒绝，防止脏数据进入判定链
	if err := insertFix(t, d, "gentoo", "12", "main", "openssl", "1.0"); err == nil {
		t.Error("未登记发行版应被外键约束拒绝")
	}
}

// TestChecksumTamperDetected 手工改库必须被发现。
func TestChecksumTamperDetected(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if _, err := d.SQL().ExecContext(ctx,
		`UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1`); err != nil {
		t.Fatalf("篡改校验和失败: %v", err)
	}

	_, err := d.Migrate(ctx)
	if err == nil {
		t.Fatal("校验和被篡改时应报错")
	}
	if got := apperr.CodeOf(err); got != exitcode.Integrity {
		t.Errorf("退出码应为 INTEGRITY，实际 %v", got)
	}
}

// TestNewerSchemaRejected 旧二进制不得打开新库。
func TestNewerSchemaRejected(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if _, err := d.SQL().ExecContext(ctx,
		`UPDATE schema_migrations SET version = 99 WHERE version = 1`); err != nil {
		t.Fatalf("伪造新版本失败: %v", err)
	}

	_, err := d.Migrate(ctx)
	if err == nil {
		t.Fatal("库版本高于二进制时应报错")
	}
	if got := apperr.CodeOf(err); got != exitcode.Integrity {
		t.Errorf("退出码应为 INTEGRITY，实际 %v", got)
	}
}

func TestMeta(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	v, err := d.Meta(ctx, "schema_version")
	if err != nil {
		t.Fatalf("读取元信息失败: %v", err)
	}
	if v != "1" {
		t.Errorf("schema_version 应为 1，实际 %q", v)
	}
	missing, err := d.Meta(ctx, "absent_key")
	if err != nil || missing != "" {
		t.Errorf("缺失键应返回空串且不报错，实际 %q / %v", missing, err)
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(context.Background(), "  "); err == nil {
		t.Error("空路径应报错")
	} else if apperr.CodeOf(err) != exitcode.Usage {
		t.Errorf("退出码应为 USAGE，实际 %v", apperr.CodeOf(err))
	}
}

func TestWALAndForeignKeysEnabled(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)

	var journal string
	if err := d.SQL().QueryRowContext(ctx, `PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("读取 journal_mode 失败: %v", err)
	}
	if journal != "wal" {
		t.Errorf("journal_mode 应为 wal，实际 %q", journal)
	}

	var fk int
	if err := d.SQL().QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("读取 foreign_keys 失败: %v", err)
	}
	if fk != 1 {
		t.Errorf("foreign_keys 应开启，实际 %d", fk)
	}
}
