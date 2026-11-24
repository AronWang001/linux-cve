package database_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/feed"
)

// TestDebianSnapshotEndToEnd 用真实 Debian Tracker 数据走完整链路：
// 解析 → 落 Artifact → 单事务写库 → 校验可查询。
//
// 默认跳过，需要真实数据集：
//
//	DEBIAN_TRACKER_JSON=/tmp/debian.json go test ./internal/database/ -run Snapshot -v
//
// 这条测试存在的意义：0003 迁移与 21 万行写入在真实规模下是否成立，
// 只有真跑一次才知道；用小样本永远测不出耗时与事务行为。
func TestDebianSnapshotEndToEnd(t *testing.T) {
	path := os.Getenv("DEBIAN_TRACKER_JSON")
	if path == "" {
		t.Skip("未设置 DEBIAN_TRACKER_JSON，跳过真实数据写库验证")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取真实数据集失败: %v", err)
	}

	dir := t.TempDir()
	db, err := database.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	// 源配置必须先落库：feed_artifacts 有外键指向 feed_sources。
	src, ok := feed.SourceByID(domain.SourceDebianTracker)
	if !ok {
		t.Fatal("找不到 Debian 源配置")
	}
	if err := db.UpsertFeedSources(ctx, []database.FeedSourceRow{{
		ID: src.ID, Name: src.Name, Kind: src.Kind, URL: src.URL,
		TrustLevel: src.TrustLevel, SignatureKind: src.SignatureKind,
	}}); err != nil {
		t.Fatalf("写入源配置失败: %v", err)
	}

	artifactSHA := feed.HashBytes(body)
	store, err := feed.NewStore(filepath.Join(dir, "feed"))
	if err != nil {
		t.Fatalf("创建 Artifact 存储失败: %v", err)
	}
	storedPath, _, err := store.Put(artifactSHA, body)
	if err != nil {
		t.Fatalf("落盘 Artifact 失败: %v", err)
	}

	fetchedAt := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	res, err := feed.DebianParser{}.Parse(ctx, feed.ParseInput{
		Source: src, ArtifactSHA: artifactSHA, Body: body, FetchedAt: fetchedAt,
	})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	batch := database.SnapshotBatch{
		Snapshot: database.SnapshotRow{
			ID:            "snap-debian-1",
			SourceID:      domain.SourceDebianTracker,
			StartedAt:     fetchedAt,
			CompletedAt:   fetchedAt.Add(5 * time.Second),
			ContentHash:   artifactSHA,
			ParserVersion: src.ParserVersion,
		},
		Artifacts: []database.ArtifactRow{{
			SHA256:          artifactSHA,
			SourceID:        domain.SourceDebianTracker,
			SizeBytes:       int64(len(body)),
			DownloadURL:     src.URL,
			FetchedAt:       fetchedAt,
			SignatureStatus: domain.SignatureNotApplicable,
			IntegrityStatus: domain.IntegrityVerified,
			StoredPath:      storedPath,
		}},
		Advisories:  res.Advisories,
		Fixes:       res.Fixes,
		NotAffected: res.NotAffected,
		Skipped:     res.Skipped,
	}
	for _, r := range res.Releases {
		batch.Releases = append(batch.Releases, database.ReleaseKey{
			DistroID: r.DistroID, Release: r.Release, Codename: r.Codename,
		})
	}

	start := time.Now()
	if err := db.CommitSnapshot(ctx, batch); err != nil {
		t.Fatalf("提交快照失败: %v", err)
	}
	t.Logf("写入 %d 条公告 / %d 条修复记录耗时 %v", len(res.Advisories), len(res.Fixes), time.Since(start))

	// 库内计数必须与解析产出严格一致，不能少也不能多。
	var advCount, fixCount, snapCount, artCount int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM advisories`).Scan(&advCount); err != nil {
		t.Fatal(err)
	}
	if advCount != len(res.Advisories) {
		t.Errorf("公告数不一致: 库 %d，解析 %d", advCount, len(res.Advisories))
	}
	if err := db.SQL().QueryRowContext(ctx, `
SELECT COUNT(*) FROM advisory_fixes f
JOIN advisories a ON a.source_id=f.source_id AND a.advisory_id=f.advisory_id AND a.cve_id=f.cve_id
WHERE f.source_id='debian-tracker'`).Scan(&fixCount); err != nil {
		t.Fatal(err)
	}
	if fixCount != len(res.Fixes) {
		t.Errorf("修复记录数不一致: 库 %d，解析 %d", fixCount, len(res.Fixes))
	}
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM feed_snapshots WHERE is_active=1`).Scan(&snapCount); err != nil {
		t.Fatal(err)
	}
	if snapCount != 1 {
		t.Errorf("生效快照应恰好 1 个，实际 %d", snapCount)
	}
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM feed_artifacts`).Scan(&artCount); err != nil {
		t.Fatal(err)
	}
	if artCount != 1 {
		t.Errorf("Artifact 应恰好 1 个（同一内容去重），实际 %d", artCount)
	}

	// 目标 CVE 必须能按 (distro, release, 包) 查出来，且版本与官方一致。
	var fixedRaw, source, channel string
	err = db.SQL().QueryRowContext(ctx, `
SELECT fixed_version_raw, fixed_version_source, channel FROM advisory_fixes
WHERE cve_id='CVE-2026-98432' AND distro_id='debian' AND release='13' AND package_name='linux'`,
	).Scan(&fixedRaw, &source, &channel)
	if err != nil {
		t.Fatalf("查询目标 CVE 修复记录失败: %v", err)
	}
	if fixedRaw != "6.12.113-1" {
		t.Errorf("目标 CVE 修复版本应为 6.12.113-1，实际 %q", fixedRaw)
	}
	if source != domain.FixVersionOfficial {
		t.Errorf("来源应标记 official，实际 %q", source)
	}
	if channel != "trixie-security" {
		t.Errorf("渠道应为 trixie-security，实际 %q", channel)
	}

	// 溯源列必须能回指 Artifact。
	var artifactRef string
	if err := db.SQL().QueryRowContext(ctx, `
SELECT artifact_sha256 FROM advisories
WHERE advisory_id='CVE-2026-98432/linux/13'`).Scan(&artifactRef); err != nil {
		t.Fatalf("查询溯源列失败: %v", err)
	}
	if artifactRef != artifactSHA {
		t.Errorf("公告未指向正确 Artifact: %q", artifactRef)
	}

	// 重复提交同一内容：不得重复累积行。
	batch.Snapshot.ID = "snap-debian-2"
	batch.Snapshot.CompletedAt = fetchedAt.Add(10 * time.Second)
	if err := db.CommitSnapshot(ctx, batch); err != nil {
		t.Fatalf("二次提交失败: %v", err)
	}
	var advAfter int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM advisories`).Scan(&advAfter); err != nil {
		t.Fatal(err)
	}
	if advAfter != len(res.Advisories) {
		t.Errorf("二次提交后公告数应保持不变（%d），实际 %d", len(res.Advisories), advAfter)
	}
	var activeAfter int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM feed_snapshots WHERE is_active=1`).Scan(&activeAfter); err != nil {
		t.Fatal(err)
	}
	if activeAfter != 1 {
		t.Errorf("二次提交后生效快照仍应唯一，实际 %d", activeAfter)
	}
}

// TestCommitSnapshotRollsBackOnBadRecord 验证：一条不合格记录会让整批回滚，
// 库中不留下任何半套数据。这是「宁可不更新，也不能写坏」的底线。
func TestCommitSnapshotRollsBackOnBadRecord(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if err := db.UpsertFeedSources(ctx, []database.FeedSourceRow{{
		ID: domain.SourceDebianTracker, Name: "Debian", Kind: "tracker",
		URL: "https://example.invalid", TrustLevel: domain.TrustLevelB, SignatureKind: "none",
	}}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	good := domain.Advisory{
		UID:        domain.AdvisoryUID(domain.SourceDebianTracker, "CVE-2026-0001/linux/13", "CVE-2026-0001"),
		SourceID:   domain.SourceDebianTracker,
		AdvisoryID: "CVE-2026-1/linux/13",
		CVEID:      "CVE-2026-0001",
		FetchedAt:  now,
	}
	bad := good
	bad.CVEID = "not-a-cve"
	bad.UID = domain.AdvisoryUID(domain.SourceDebianTracker, bad.AdvisoryID, bad.CVEID)

	batch := database.SnapshotBatch{
		Snapshot: database.SnapshotRow{
			ID: "snap-1", SourceID: domain.SourceDebianTracker,
			StartedAt: now, CompletedAt: now, ContentHash: "abc",
		},
		Advisories: []domain.Advisory{good, bad},
	}
	if err := db.CommitSnapshot(ctx, batch); err == nil {
		t.Fatal("含非法记录的快照必须被拒绝")
	}

	var n int
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM advisories`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("失败提交不得留下任何数据，实际写入 %d 条", n)
	}
	if err := db.SQL().QueryRowContext(ctx, `SELECT COUNT(*) FROM feed_snapshots`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("失败提交不得留下快照记录，实际 %d 条", n)
	}
}

// TestCommitSnapshotKeepsPreviousOnFailure 验证：新快照失败时，上一份有效情报不受影响。
func TestCommitSnapshotKeepsPreviousOnFailure(t *testing.T) {
	dir := t.TempDir()
	db, err := database.Open(context.Background(), filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	if err := db.UpsertFeedSources(ctx, []database.FeedSourceRow{{
		ID: domain.SourceDebianTracker, Name: "Debian", Kind: "tracker",
		URL: "https://example.invalid", TrustLevel: domain.TrustLevelB, SignatureKind: "none",
	}}); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	mk := func(id, cve string) domain.Advisory {
		return domain.Advisory{
			UID:        domain.AdvisoryUID(domain.SourceDebianTracker, id, domain.CVEID(cve)),
			SourceID:   domain.SourceDebianTracker,
			AdvisoryID: id,
			CVEID:      domain.CVEID(cve),
			FetchedAt:  now,
		}
	}
	first := database.SnapshotBatch{
		Snapshot: database.SnapshotRow{
			ID: "snap-ok", SourceID: domain.SourceDebianTracker,
			StartedAt: now, CompletedAt: now, ContentHash: "hash-1",
		},
		Advisories: []domain.Advisory{mk("CVE-2026-0001/linux/13", "CVE-2026-0001")},
	}
	if err := db.CommitSnapshot(ctx, first); err != nil {
		t.Fatalf("首次提交失败: %v", err)
	}

	// 第二次带入一条非法记录，整批应失败。
	second := database.SnapshotBatch{
		Snapshot: database.SnapshotRow{
			ID: "snap-bad", SourceID: domain.SourceDebianTracker,
			StartedAt: now, CompletedAt: now, ContentHash: "hash-2",
		},
		Advisories: []domain.Advisory{mk("CVE-2026-0002/linux/13", "CVE-2026-0002"), mk("CVE-2026-0003/linux/13", "bad")},
	}
	if err := db.CommitSnapshot(ctx, second); err == nil {
		t.Fatal("含非法记录的快照必须被拒绝")
	}

	var active string
	if err := db.SQL().QueryRowContext(ctx,
		`SELECT id FROM feed_snapshots WHERE is_active=1`).Scan(&active); err != nil {
		t.Fatalf("生效快照丢失: %v", err)
	}
	if active != "snap-ok" {
		t.Errorf("失败后应保持原生效快照 snap-ok，实际 %q", active)
	}
	var cve string
	if err := db.SQL().QueryRowContext(ctx, `SELECT cve_id FROM advisories`).Scan(&cve); err != nil {
		t.Fatalf("原情报丢失: %v", err)
	}
	if cve != "CVE-2026-0001" {
		t.Errorf("应保留旧情报 CVE-2026-0001，实际 %q", cve)
	}
}
