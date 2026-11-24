package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/version"
)

// ArtifactRow 是 feed_artifacts 的一行。
type ArtifactRow struct {
	SHA256          string
	SourceID        domain.SourceID
	SizeBytes       int64
	DownloadURL     string
	FetchedAt       time.Time
	SignatureStatus domain.SignatureStatus
	IntegrityStatus domain.IntegrityStatus
	StoredPath      string
	ETag            string
	LastModified    string
}

// SnapshotRow 是一次同步的元信息。
type SnapshotRow struct {
	ID            string
	SourceID      domain.SourceID
	StartedAt     time.Time
	CompletedAt   time.Time
	ContentHash   string
	ParserVersion string
}

// ReleaseKey 是需要确保登记在 distro_releases 的发行版坐标。
// 情报里出现的 release 若未登记，迁移层不拦（资产事实优先），
// 但 advisory_fixes 有外键，写库前必须存在。
type ReleaseKey struct {
	DistroID domain.DistroID
	Release  string
	Codename string
}

// SnapshotBatch 是一次原子提交的全部内容。
//
// 约定：该函数被调用时，Artifact 字节已经落盘（不可变），
// 这里只做「把归一化结果与索引写进 SQLite」这一半。
// 文件系统与 SQLite 无法共同原子提交，因此顺序固定为：
// 先落 Artifact（失败不影响旧库），后单事务写归一化数据并翻转 active 指针。
type SnapshotBatch struct {
	Snapshot    SnapshotRow
	Artifacts   []ArtifactRow
	Releases    []ReleaseKey
	Advisories  []domain.Advisory
	Fixes       []domain.AdvisoryFix
	NotAffected []domain.NotAffected
	// Skipped 是解析阶段跳过的异常记录数，进快照统计供质量判断。
	Skipped int
}

// CommitSnapshot 在一个事务内写入快照、链接 Artifact、替换该源的归一化数据，
// 并翻转 active 指针。任何一步失败整体回滚，上一份有效情报保持完好。
func (d *DB) CommitSnapshot(ctx context.Context, b SnapshotBatch) error {
	if b.Snapshot.ID == "" || b.Snapshot.SourceID == "" {
		return apperr.New(exitcode.Error, "database.feed", "快照缺少 ID 或情报源")
	}
	if b.Snapshot.ContentHash == "" {
		return apperr.New(exitcode.Error, "database.feed", "快照缺少内容哈希")
	}

	// 先全量校验，再动库：宁可在写第一行之前失败，也不要留下半套数据。
	for i, a := range b.Advisories {
		if err := a.Validate(); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("第 %d 条公告不合格", i+1), err)
		}
	}
	for i, f := range b.Fixes {
		if err := f.Validate(); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("第 %d 条修复记录不合格", i+1), err)
		}
	}
	for i, n := range b.NotAffected {
		if err := n.Validate(); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("第 %d 条不受影响声明不合格", i+1), err)
		}
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "开启快照事务失败", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := ensureReleases(ctx, tx, b.Releases); err != nil {
		return err
	}
	if err := insertArtifacts(ctx, tx, b.Artifacts); err != nil {
		return err
	}
	if err := insertSnapshot(ctx, tx, b.Snapshot, b.Skipped); err != nil {
		return err
	}
	if err := linkArtifacts(ctx, tx, b.Snapshot.ID, b.Artifacts); err != nil {
		return err
	}
	// 按源全量替换归一化数据：Artifact 是不可变事实，归一化结果可随时重建。
	// 撤回的公告靠 retracted_at 表达，不靠「留着旧行」。
	if err := replaceNormalized(ctx, tx, b); err != nil {
		return err
	}
	if err := flipActive(ctx, tx, b.Snapshot); err != nil {
		return err
	}
	if err := markSourceOK(ctx, tx, b); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "提交快照失败", err)
	}
	return nil
}

// ensureReleases 确保 distro_releases 存在对应坐标。
// 未登记 release 以 lifecycle_state='unknown' 落库：允许采集事实，
// 但不因此推断它受支持（修复准入另查 lifecycle）。
func ensureReleases(ctx context.Context, tx *sql.Tx, keys []ReleaseKey) error {
	if len(keys) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO distro_releases (id, distro_id, release, codename, lifecycle_state)
		 VALUES (?, ?, ?, ?, 'unknown')
		 ON CONFLICT(distro_id, release) DO NOTHING`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备 release 语句失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, k := range keys {
		if k.Release == "" || k.DistroID == "" {
			continue
		}
		id := string(k.DistroID) + ":" + k.Release
		if _, err := stmt.ExecContext(ctx, id, string(k.DistroID), k.Release, k.Codename); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("登记 release %s 失败", id), err)
		}
	}
	return nil
}

// insertArtifacts 写入 Artifact 记录。同哈希已存在时保留首次抓取时间与签名结论，
// 不因重复下载覆盖历史（内容相同意味着字节相同，结论也相同）。
func insertArtifacts(ctx context.Context, tx *sql.Tx, rows []ArtifactRow) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO feed_artifacts (sha256, source_id, size_bytes, download_url, fetched_at,
                            signature_status, integrity_status, stored_path,
                            etag, last_modified)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(sha256) DO UPDATE SET
    -- 内容相同则哈希相同，签名/完整性结论不会被后续抓取改差；
    -- 只在前次未验证时补写结论，避免把已验证降级成未验证。
    signature_status = CASE WHEN feed_artifacts.signature_status = 'unverified'
                            THEN excluded.signature_status ELSE feed_artifacts.signature_status END,
    integrity_status = CASE WHEN feed_artifacts.integrity_status = 'unchecked'
                            THEN excluded.integrity_status ELSE feed_artifacts.integrity_status END,
    etag = CASE WHEN excluded.etag <> '' THEN excluded.etag ELSE feed_artifacts.etag END,
    last_modified = CASE WHEN excluded.last_modified <> '' THEN excluded.last_modified
                         ELSE feed_artifacts.last_modified END`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备 Artifact 语句失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, a := range rows {
		if _, err := stmt.ExecContext(ctx, a.SHA256, string(a.SourceID), a.SizeBytes,
			a.DownloadURL, fmtTime(a.FetchedAt), string(a.SignatureStatus),
			string(a.IntegrityStatus), a.StoredPath, a.ETag, a.LastModified); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("写入 Artifact %s 失败", shortHash(a.SHA256)), err)
		}
	}
	return nil
}

// insertSnapshot 写入快照行（初始 is_active=0，提交末尾才翻转）。
func insertSnapshot(ctx context.Context, tx *sql.Tx, s SnapshotRow, skipped int) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO feed_snapshots (id, source_id, started_at, completed_at, is_active,
                            content_hash, parser_version, skipped)
VALUES (?, ?, ?, ?, 0, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
    completed_at = excluded.completed_at,
    content_hash = excluded.content_hash,
    parser_version = excluded.parser_version,
    skipped = excluded.skipped`,
		s.ID, string(s.SourceID), fmtTime(s.StartedAt), fmtTime(s.CompletedAt),
		s.ContentHash, s.ParserVersion, skipped)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "写入快照失败", err)
	}
	return nil
}

// linkArtifacts 建立快照与 Artifact 的多对多关系。
func linkArtifacts(ctx context.Context, tx *sql.Tx, snapshotID string, rows []ArtifactRow) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO feed_snapshot_artifacts (snapshot_id, artifact_sha)
		 VALUES (?, ?) ON CONFLICT DO NOTHING`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备快照链接语句失败", err)
	}
	defer func() { _ = stmt.Close() }()
	for _, a := range rows {
		if _, err := stmt.ExecContext(ctx, snapshotID, a.SHA256); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("链接 Artifact %s 失败", shortHash(a.SHA256)), err)
		}
	}
	return nil
}

// replaceNormalized 删除该源旧归一化数据并写入新数据。
// advisory_fixes 通过复合外键 ON DELETE CASCADE 随 advisories 一起清理。
func replaceNormalized(ctx context.Context, tx *sql.Tx, b SnapshotBatch) error {
	src := string(b.Snapshot.SourceID)
	if _, err := tx.ExecContext(ctx, `DELETE FROM advisories WHERE source_id = ?`, src); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "清理旧公告失败", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM advisory_not_affected WHERE source_id = ?`, src); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "清理旧不受影响声明失败", err)
	}

	if err := insertAdvisories(ctx, tx, b.Advisories); err != nil {
		return err
	}
	if err := insertFixes(ctx, tx, b.Fixes); err != nil {
		return err
	}
	return insertNotAffected(ctx, tx, b.NotAffected)
}

// insertAdvisories 写入公告，含指向不可变 Artifact 的溯源列。
func insertAdvisories(ctx context.Context, tx *sql.Tx, rows []domain.Advisory) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO advisories (uid, source_id, advisory_id, cve_id, title, severity,
                        severity_source, issued_at, updated_at, url, fetched_at,
                        artifact_sha256, raw_locator, raw_record_hash, parser_version,
                        vendor_status, retracted_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(uid) DO UPDATE SET
    title = excluded.title,
    severity = excluded.severity,
    severity_source = excluded.severity_source,
    issued_at = excluded.issued_at,
    updated_at = excluded.updated_at,
    url = excluded.url,
    fetched_at = excluded.fetched_at,
    artifact_sha256 = excluded.artifact_sha256,
    raw_locator = excluded.raw_locator,
    raw_record_hash = excluded.raw_record_hash,
    parser_version = excluded.parser_version,
    vendor_status = excluded.vendor_status,
    retracted_at = excluded.retracted_at`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备公告语句失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, a := range rows {
		if _, err := stmt.ExecContext(ctx,
			a.UID, string(a.SourceID), a.AdvisoryID, string(a.CVEID), a.Title,
			severityOrDefault(a.Severity), a.SeveritySource,
			fmtTimePtr(a.IssuedAt), fmtTimePtr(a.UpdatedAt), a.URL, fmtTime(a.FetchedAt),
			a.ArtifactSHA256, a.RawLocator, a.RawRecordHash, a.ParserVersion,
			a.VendorStatus, fmtTimePtr(a.RetractedAt)); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("写入公告 %s 失败", a.AdvisoryID), err)
		}
	}
	return nil
}

// insertFixes 写入修复版本。固定版本按包管理器规则拆成 epoch/upstream/release 三元组，
// 同时逐字保留原始串：拆分只用于结构化比较，原始串才是审计依据。
func insertFixes(ctx context.Context, tx *sql.Tx, rows []domain.AdvisoryFix) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO advisory_fixes (source_id, advisory_id, cve_id, distro_id, release, channel,
                            package_kind, package_name, arch,
                            fixed_version_raw, fixed_epoch, fixed_version, fixed_release,
                            fixed_at, evidence_url, fixed_version_source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (source_id, advisory_id, cve_id, distro_id, release, channel,
             package_kind, package_name, arch) DO UPDATE SET
    fixed_version_raw = excluded.fixed_version_raw,
    fixed_epoch = excluded.fixed_epoch,
    fixed_version = excluded.fixed_version,
    fixed_release = excluded.fixed_release,
    fixed_at = excluded.fixed_at,
    evidence_url = excluded.evidence_url,
    fixed_version_source = excluded.fixed_version_source`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备修复版本语句失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, f := range rows {
		epoch, up, rel := splitVersion(f.DistroID, f.FixedVersion)
		src := f.FixedVersionSource
		if src == "" {
			src = domain.FixVersionOfficial
		}
		if _, err := stmt.ExecContext(ctx,
			string(f.SourceID), f.AdvisoryID, string(f.CVEID), string(f.DistroID), f.Release, f.Channel,
			string(f.Ref.Kind), f.Ref.Name, f.Ref.Arch,
			f.FixedVersion, epoch, up, rel,
			fmtTimePtr(f.FixedAt), f.EvidenceURL, src); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("写入修复记录 %s/%s 失败", f.AdvisoryID, f.Ref.Name), err)
		}
	}
	return nil
}

// insertNotAffected 写入显式「不受影响」声明。
func insertNotAffected(ctx context.Context, tx *sql.Tx, rows []domain.NotAffected) error {
	if len(rows) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO advisory_not_affected (source_id, advisory_id, cve_id, distro_id, release,
                                   package_kind, package_name, arch, reason, evidence_url)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (source_id, cve_id, distro_id, release, package_kind, package_name, arch)
    DO UPDATE SET
    advisory_id = excluded.advisory_id,
    reason = excluded.reason,
    evidence_url = excluded.evidence_url`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备不受影响语句失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, n := range rows {
		if _, err := stmt.ExecContext(ctx,
			string(n.SourceID), n.AdvisoryID, string(n.CVEID), string(n.DistroID), n.Release,
			string(n.Ref.Kind), n.Ref.Name, n.Ref.Arch, string(n.Reason), n.EvidenceURL); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("写入不受影响声明 %s/%s 失败", n.CVEID, n.Ref.Name), err)
		}
	}
	return nil
}

// flipActive 翻转该源的 active 指针：旧的置 0，本次置 1。
// 唯一索引保证任何时刻至多一个 active 快照。
func flipActive(ctx context.Context, tx *sql.Tx, s SnapshotRow) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE feed_snapshots SET is_active = 0 WHERE source_id = ? AND is_active = 1`,
		string(s.SourceID)); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "清除旧生效快照失败", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE feed_snapshots SET is_active = 1 WHERE id = ?`, s.ID); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "置位新生效快照失败", err)
	}
	return nil
}

// markSourceOK 更新源同步状态与全局元信息。
func markSourceOK(ctx context.Context, tx *sql.Tx, b SnapshotBatch) error {
	// 统计以实际写入库的行为准（而不是解析计数），避免报告与库不一致。
	var adv, fix, na int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM advisories WHERE source_id = ?`, string(b.Snapshot.SourceID)).Scan(&adv); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "统计公告数失败", err)
	}
	if err := tx.QueryRowContext(ctx, `
SELECT COUNT(*) FROM advisory_fixes f
JOIN advisories a ON a.source_id = f.source_id AND a.advisory_id = f.advisory_id AND a.cve_id = f.cve_id
WHERE f.source_id = ?`, string(b.Snapshot.SourceID)).Scan(&fix); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "统计修复记录数失败", err)
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM advisory_not_affected WHERE source_id = ?`,
		string(b.Snapshot.SourceID)).Scan(&na); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "统计不受影响声明数失败", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE feed_snapshots SET advisories = ?, fixes = ?, not_affected = ? WHERE id = ?`,
		adv, fix, na, b.Snapshot.ID); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "回写快照统计失败", err)
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE feed_sources SET
    status = 'ok',
    last_checked_at = ?,
    last_success_at = ?,
    content_hash = ?,
    last_error = ''
WHERE id = ?`,
		fmtTime(b.Snapshot.CompletedAt), fmtTime(b.Snapshot.CompletedAt),
		b.Snapshot.ContentHash, string(b.Snapshot.SourceID)); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "更新源同步状态失败", err)
	}

	if _, err := tx.ExecContext(ctx, `
INSERT INTO app_meta (key, value) VALUES ('feed_last_update', ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmtTime(b.Snapshot.CompletedAt)); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "更新同步时间失败", err)
	}
	return nil
}

// MarkSourceError 记录某源同步失败。失败不触碰已有情报：
// 旧快照仍 active，只是状态标成 error 并留下原因。
func (d *DB) MarkSourceError(ctx context.Context, sourceID domain.SourceID, msg string) error {
	_, err := d.db.ExecContext(ctx, `
UPDATE feed_sources SET status = 'error', last_checked_at = ?, last_error = ?
WHERE id = ?`,
		fmtTime(time.Now()), truncate(msg, 2000), string(sourceID))
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "记录源失败状态失败", err)
	}
	return nil
}

// splitVersion 按发行版的包管理器规则把固定版本拆成 epoch/upstream/release。
// 拆不出来不算错误：原始串已逐字保存，比较仍走包管理器原生规则。
func splitVersion(distro domain.DistroID, raw string) (int, string, string) {
	mgr := managerForDistro(distro)
	v, err := version.Parse(mgr, raw)
	if err != nil || v.Upstream == "" {
		return 0, raw, ""
	}
	return v.Epoch, v.Upstream, v.Release
}

// managerForDistro 按发行版族选包管理器，只用于版本串拆分。
func managerForDistro(distro domain.DistroID) domain.PackageManager {
	switch distro {
	case domain.DistroDebian, domain.DistroUbuntu:
		return domain.ManagerDPKG
	case domain.DistroAlpine:
		return domain.ManagerAPK
	case domain.DistroArch:
		return domain.ManagerPacman
	default:
		return domain.ManagerRPM
	}
}

// severityOrDefault 把严重程度收敛到 CHECK 允许的取值。
func severityOrDefault(s domain.Severity) string {
	if s == "" || !s.Valid() {
		return string(domain.SeverityUnknown)
	}
	return string(s)
}

// fmtTime 统一 RFC3339 UTC 文本。
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// fmtTimePtr 空时间写 NULL，避免把零值时间当成真实时间。
func fmtTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

// shortHash 返回哈希前 12 位用于错误信息。
func shortHash(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12]
}

// truncate 截断过长文本，避免把整页 HTML 写进 last_error。
func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
