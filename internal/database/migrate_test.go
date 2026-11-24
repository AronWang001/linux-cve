package database

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/exitcode"
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
	want := wantMigrationCount(t)
	if n != want {
		t.Errorf("首次应应用 %d 个迁移，实际 %d", want, n)
	}

	st, err := d.Status(ctx)
	if err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	if st.SchemaVersion != want {
		t.Errorf("schema 版本应为 %d，实际 %d", want, st.SchemaVersion)
	}
	if len(st.Applied) != want {
		t.Errorf("已应用记录数应为 %d，实际 %d", want, len(st.Applied))
	}
	// 前两个迁移的语义不回退：0001 建骨架，0002 建资产采集。
	if len(st.Applied) >= 2 && (st.Applied[0].Name != "init" || st.Applied[1].Name != "inventory") {
		t.Errorf("前两个迁移名称不符: %+v", st.Applied[:2])
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

	// schema 版本唯一权威来源是 schema_migrations，app_meta 不再冗余 schema_version
	var schemaVersion string
	err := d.SQL().QueryRowContext(ctx,
		`SELECT value FROM app_meta WHERE key = 'schema_version'`).Scan(&schemaVersion)
	if err == nil {
		t.Errorf("app_meta 不应再冗余 schema_version，实际存在值 %q", schemaVersion)
	}

	var maxVer int
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT MAX(version) FROM schema_migrations`).Scan(&maxVer); err != nil {
		t.Fatalf("读取 schema_migrations 失败: %v", err)
	}
	if maxVer != wantMigrationCount(t) {
		t.Errorf("schema_migrations 最大版本应为 %d，实际 %d", wantMigrationCount(t), maxVer)
	}
}

// wantMigrationCount 返回内嵌迁移总数。
//
// 断言写成动态值而不是硬编码数字：新增迁移不应需要改测试，
// 但「全部迁移都应用了」这件事必须继续被验证。
func wantMigrationCount(t *testing.T) int {
	t.Helper()
	ms, err := LoadMigrations()
	if err != nil {
		t.Fatalf("读取内嵌迁移失败: %v", err)
	}
	return len(ms)
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
		 (source_id, advisory_id, cve_id, distro_id, release, channel,
		  package_kind, package_name, arch, fixed_version_raw, fixed_version)
		 VALUES ('debian-tracker','DSA-1','CVE-2026-0001',?,?,?,'source',?,'any',?,?)`,
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
	v, err := d.Meta(ctx, "db_created_at")
	if err != nil {
		t.Fatalf("读取元信息失败: %v", err)
	}
	if v == "" {
		t.Error("db_created_at 不应为空")
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

// TestCompositeReleaseFK 固化 P1-4：distro_id + release 必须整体锚定 distro_releases，
// 合法发行版配非法 release 也必须被拒绝。
func TestCompositeReleaseFK(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	seedAdvisory(t, d, "debian-tracker", "DSA-1", "CVE-2026-0001")

	if err := insertFix(t, d, "debian", "99", "bookworm-security", "openssl", "3.0.11-1"); err == nil {
		t.Error("debian:99 不存在，组合外键应拒绝")
	}
	if err := insertFix(t, d, "debian", "12", "bookworm-security", "openssl", "3.0.11-1"); err != nil {
		t.Errorf("debian:12 存在，应接受: %v", err)
	}

	// advisory_not_affected 同样受组合外键约束
	_, err := d.SQL().ExecContext(ctx,
		`INSERT INTO advisory_not_affected
		 (source_id, cve_id, distro_id, release, package_kind, package_name, arch, reason)
		 VALUES ('debian-tracker','CVE-2026-0001','debian','99','source','linux','any','not-affected')`)
	if err == nil {
		t.Error("not_affected 的 debian:99 应被组合外键拒绝")
	}
	_, err = d.SQL().ExecContext(ctx,
		`INSERT INTO advisory_not_affected
		 (source_id, cve_id, distro_id, release, package_kind, package_name, arch, reason)
		 VALUES ('debian-tracker','CVE-2026-0001','debian','12','source','linux','any','not-affected')`)
	if err != nil {
		t.Errorf("not_affected 的 debian:12 应接受: %v", err)
	}
}

// TestAdvisoryTripleFK 固化 P1-4：修复记录的公告三元组必须指向真实公告行。
func TestAdvisoryTripleFK(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	seedAdvisory(t, d, "debian-tracker", "DSA-1", "CVE-2026-0001")

	_, err := d.SQL().ExecContext(ctx,
		`INSERT INTO advisory_fixes
		 (source_id, advisory_id, cve_id, distro_id, release, channel,
		  package_kind, package_name, arch, fixed_version_raw, fixed_version)
		 VALUES ('debian-tracker','DSA-9999','CVE-2026-0001','debian','12','bookworm-security',
		         'source','openssl','any','3.0.11-1','3.0.11-1')`)
	if err == nil {
		t.Error("未登记的公告三元组应被组合外键拒绝")
	}

	// 删除公告应级联清理修复记录
	if err := insertFix(t, d, "debian", "12", "bookworm-security", "openssl", "3.0.11-1"); err != nil {
		t.Fatalf("插入修复记录失败: %v", err)
	}
	if _, err := d.SQL().ExecContext(ctx,
		`DELETE FROM advisories WHERE advisory_id = 'DSA-1'`); err != nil {
		t.Fatalf("删除公告失败: %v", err)
	}
	var n int
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM advisory_fixes`).Scan(&n); err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 0 {
		t.Errorf("删除公告后修复记录应级联删除，实际残留 %d 条", n)
	}
}

// TestFeedSourceSignatureIntegrity 固化 P1-5：签名状态与完整性状态独立、各有默认值。
func TestFeedSourceSignatureIntegrity(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	// 默认值：未验证签名、未比对哈希
	if _, err := d.SQL().ExecContext(ctx,
		`INSERT INTO feed_sources (id, name, kind, url, trust_level) VALUES ('src-a','A','api','https://a','B')`); err != nil {
		t.Fatalf("插入情报源失败: %v", err)
	}
	var sig, integ string
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT signature_status, integrity_status FROM feed_sources WHERE id='src-a'`).Scan(&sig, &integ); err != nil {
		t.Fatalf("读取状态失败: %v", err)
	}
	if sig != "unverified" || integ != "unchecked" {
		t.Errorf("默认状态应为 unverified/unchecked，实际 %q/%q", sig, integ)
	}

	// 可写入合法组合：B 级源 = 无签名 + 哈希通过
	if _, err := d.SQL().ExecContext(ctx,
		`UPDATE feed_sources SET signature_status='not-applicable', integrity_status='verified' WHERE id='src-a'`); err != nil {
		t.Errorf("合法状态组合应被接受: %v", err)
	}

	// 非法枚举必须被 CHECK 拒绝
	if _, err := d.SQL().ExecContext(ctx,
		`UPDATE feed_sources SET signature_status='verified-by-hash' WHERE id='src-a'`); err == nil {
		t.Error("非法 signature_status 应被 CHECK 拒绝")
	}
	if _, err := d.SQL().ExecContext(ctx,
		`UPDATE feed_sources SET integrity_status='signed' WHERE id='src-a'`); err == nil {
		t.Error("非法 integrity_status 应被 CHECK 拒绝")
	}
}

// TestApplyOneRollbackOnError 固化 P1-6：迁移执行失败必须整体回滚，不留半成品。
func TestApplyOneRollbackOnError(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)

	// applyOne 不负责建 schema_migrations（由 Migrate 统一创建），此处补前置
	if _, err := d.SQL().ExecContext(ctx, createMigrationsTable); err != nil {
		t.Fatalf("创建迁移记录表失败: %v", err)
	}

	bad := Migration{Version: 1, Name: "bad", SQL: "THIS IS NOT SQL;", Checksum: "x"}
	if err := d.applyOne(ctx, bad); err == nil {
		t.Fatal("非法 SQL 应报错")
	}

	// 不得留下迁移记录
	var n int
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("统计迁移记录失败: %v", err)
	}
	if n != 0 {
		t.Errorf("失败迁移不得留下记录，实际 %d 条", n)
	}
}

// TestValidateAppliedConsistency 固化 P1-6：版本不一致的各类形态都必须拒绝。
func TestValidateAppliedConsistency(t *testing.T) {
	migs, err := LoadMigrations()
	if err != nil {
		t.Fatalf("加载迁移失败: %v", err)
	}
	// 构造两份内嵌迁移，覆盖缺档分支
	two := append([]Migration{}, migs...)
	if len(two) == 1 {
		two = append(two, Migration{Version: 2, Name: "future", SQL: "SELECT 1;", Checksum: "c2"})
	}
	ok := AppliedMigration{Version: 1, Name: migs[0].Name, Checksum: migs[0].Checksum, AppliedAt: "now"}

	if err := validateApplied(nil, two); err != nil {
		t.Errorf("空已应用列表应合法: %v", err)
	}
	if err := validateApplied([]AppliedMigration{ok}, two); err != nil {
		t.Errorf("完全一致时应合法: %v", err)
	}

	// 校验和篡改
	tampered := ok
	tampered.Checksum = "bad"
	if err := validateApplied([]AppliedMigration{tampered}, two); err == nil {
		t.Error("校验和不一致应拒绝")
	}

	// 库版本高于二进制
	newer := AppliedMigration{Version: 99, Name: "x", Checksum: "y", AppliedAt: "now"}
	if err := validateApplied([]AppliedMigration{newer}, two); err == nil {
		t.Error("库版本高于内嵌应拒绝")
	}

	// 迁移序列缺档：应用了 2 却没应用 1
	if len(two) > 1 {
		gap := AppliedMigration{Version: 2, Name: two[1].Name, Checksum: two[1].Checksum, AppliedAt: "now"}
		if err := validateApplied([]AppliedMigration{gap}, two); err == nil {
			t.Error("迁移缺档应拒绝")
		}
	}
}

// TestOpenRejectsNewerSchema 固化 P1-6：旧二进制连打开都不允许。
func TestOpenRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "linux-cve.db")

	d, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if _, err := d.SQL().ExecContext(ctx,
		`UPDATE schema_migrations SET version = 99 WHERE version = 1`); err != nil {
		t.Fatalf("伪造新版本失败: %v", err)
	}
	if err := d.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	_, err = Open(ctx, path)
	if err == nil {
		t.Fatal("Schema 高于二进制时 Open 应拒绝")
	}
	if got := apperr.CodeOf(err); got != exitcode.Integrity {
		t.Errorf("退出码应为 INTEGRITY，实际 %v", got)
	}
}
