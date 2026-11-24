package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// FeedSourceRow 是 feed_sources 的一行配置。
// 配置的唯一来源是 internal/feed/registry.go，本包只负责落库。
type FeedSourceRow struct {
	ID            domain.SourceID
	Name          string
	Kind          string
	URL           string
	TrustLevel    domain.TrustLevel
	SignatureKind string
}

// SourceStatus 是 feed status 命令需要的单源状态。
type SourceStatus struct {
	ID            domain.SourceID
	Name          string
	Kind          string
	URL           string
	TrustLevel    domain.TrustLevel
	SignatureKind string

	// Status: ok | stale | error | unknown
	Status string
	// SignatureStatus / IntegrityStatus 是最近一次实际校验结果，不是应然等级。
	SignatureStatus domain.SignatureStatus
	IntegrityStatus domain.IntegrityStatus

	LastCheckedAt *time.Time
	LastSuccessAt *time.Time
	LastError     string

	// 当前生效快照
	ActiveSnapshot string
	SnapshotAt     *time.Time
	Advisories     int
	Fixes          int
	NotAffected    int
	ParserVersion  string
	ArtifactCount  int
	// Age 由调用方按当前时间计算；这里只给出快照完成时间。
}

// UpsertFeedSources 写入或更新源配置。已存在时只更新名称/URL/信任等级等元信息，
// 不动最近一次同步状态（status/last_success_at），避免把运行态覆盖成初始值。
func (d *DB) UpsertFeedSources(ctx context.Context, rows []FeedSourceRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "开启源配置事务失败", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO feed_sources (id, name, kind, url, trust_level, signature_kind, scope,
                          signature_status, integrity_status, status)
VALUES (?, ?, ?, ?, ?, ?, 'advisory', 'unverified', 'unchecked', 'unknown')
ON CONFLICT(id) DO UPDATE SET
    name = excluded.name,
    kind = excluded.kind,
    url = excluded.url,
    trust_level = excluded.trust_level,
    signature_kind = excluded.signature_kind`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "准备源配置语句失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx, string(r.ID), r.Name, r.Kind, r.URL,
			string(r.TrustLevel), r.SignatureKind); err != nil {
			return apperr.Wrap(exitcode.Error, "database.feed",
				fmt.Sprintf("写入情报源 %s 失败", r.ID), err)
		}
	}
	if err := tx.Commit(); err != nil {
		return apperr.Wrap(exitcode.Error, "database.feed", "提交源配置失败", err)
	}
	return nil
}

// FeedStatus 返回所有情报源的当前状态，含当前生效快照的统计。
func (d *DB) FeedStatus(ctx context.Context) ([]SourceStatus, error) {
	rows, err := d.db.QueryContext(ctx, `
SELECT s.id, s.name, s.kind, s.url, s.trust_level, s.signature_kind,
       s.status, s.signature_status, s.integrity_status,
       s.last_checked_at, s.last_success_at, COALESCE(s.last_error, ''),
       COALESCE(p.id, ''), p.completed_at,
       COALESCE(p.advisories, 0), COALESCE(p.fixes, 0), COALESCE(p.not_affected, 0),
       COALESCE(p.parser_version, ''),
       (SELECT COUNT(*) FROM feed_snapshot_artifacts a WHERE a.snapshot_id = p.id)
FROM feed_sources s
LEFT JOIN feed_snapshots p ON p.source_id = s.id AND p.is_active = 1
ORDER BY s.id`)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.feed", "查询情报源状态失败", err)
	}
	defer func() { _ = rows.Close() }()

	var out []SourceStatus
	for rows.Next() {
		var st SourceStatus
		var trust, sig, status, lastChecked, lastSuccess, completed sql.NullString
		var sigStatus, integStatus string
		if err := rows.Scan(&st.ID, &st.Name, &st.Kind, &st.URL, &trust, &sig,
			&status, &sigStatus, &integStatus,
			&lastChecked, &lastSuccess, &st.LastError,
			&st.ActiveSnapshot, &completed,
			&st.Advisories, &st.Fixes, &st.NotAffected,
			&st.ParserVersion, &st.ArtifactCount); err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.feed", "解析情报源状态失败", err)
		}
		st.TrustLevel = domain.TrustLevel(trust.String)
		st.SignatureKind = sig.String
		st.Status = status.String
		st.SignatureStatus = domain.SignatureStatus(sigStatus)
		st.IntegrityStatus = domain.IntegrityStatus(integStatus)
		st.LastCheckedAt = parseTimePtr(lastChecked)
		st.LastSuccessAt = parseTimePtr(lastSuccess)
		st.SnapshotAt = parseTimePtr(completed)
		out = append(out, st)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.feed", "遍历情报源状态失败", err)
	}
	return out, nil
}

// ActiveSnapshot 返回某源当前生效的快照 ID；无生效快照时返回空串。
func (d *DB) ActiveSnapshot(ctx context.Context, sourceID domain.SourceID) (string, error) {
	var id string
	err := d.db.QueryRowContext(ctx,
		`SELECT id FROM feed_snapshots WHERE source_id = ? AND is_active = 1`,
		string(sourceID)).Scan(&id)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", apperr.Wrap(exitcode.Error, "database.feed", "查询生效快照失败", err)
	}
	return id, nil
}

// LastArtifact 返回某源最近一次成功抓取的 Artifact，用于条件请求与内容比对。
// 无记录时返回 false，不当作错误。
func (d *DB) LastArtifact(ctx context.Context, sourceID domain.SourceID) (ArtifactRow, bool, error) {
	var a ArtifactRow
	var sig, integ string
	var fetched string
	err := d.db.QueryRowContext(ctx, `
SELECT sha256, source_id, size_bytes, download_url, fetched_at,
       signature_status, integrity_status, stored_path, etag, last_modified
FROM feed_artifacts WHERE source_id = ?
ORDER BY fetched_at DESC LIMIT 1`, string(sourceID)).Scan(
		&a.SHA256, &a.SourceID, &a.SizeBytes, &a.DownloadURL, &fetched,
		&sig, &integ, &a.StoredPath, &a.ETag, &a.LastModified)
	if err == sql.ErrNoRows {
		return ArtifactRow{}, false, nil
	}
	if err != nil {
		return ArtifactRow{}, false, apperr.Wrap(exitcode.Error, "database.feed", "查询最近 Artifact 失败", err)
	}
	if t, perr := time.Parse(time.RFC3339, fetched); perr == nil {
		a.FetchedAt = t
	}
	a.SignatureStatus = domain.SignatureStatus(sig)
	a.IntegrityStatus = domain.IntegrityStatus(integ)
	return a, true, nil
}

// ArtifactByURL 按 (source_id, download_url) 查最近一次落库的 Artifact。
//
// 按文档发布的源（CSAF）用它判断「这份文档本地有没有、什么时候抓的」：
// 清单时间戳不比 fetched_at 新就直接复用本地字节，避免几万次无意义下载。
// 同一 URL 可能对应多个历史版本（内容变过），取最新一条。
func (d *DB) ArtifactByURL(ctx context.Context, sourceID domain.SourceID,
	url string) (ArtifactRow, bool, error) {

	row := d.db.QueryRowContext(ctx, `
SELECT sha256, source_id, size_bytes, download_url, fetched_at,
       signature_status, integrity_status, stored_path, etag, last_modified
FROM feed_artifacts
WHERE source_id = ? AND download_url = ?
ORDER BY fetched_at DESC
LIMIT 1`, string(sourceID), url)

	var a ArtifactRow
	var fetched, src, sig, integ string
	err := row.Scan(&a.SHA256, &src, &a.SizeBytes, &a.DownloadURL, &fetched,
		&sig, &integ, &a.StoredPath, &a.ETag, &a.LastModified)
	if err == sql.ErrNoRows {
		return ArtifactRow{}, false, nil
	}
	if err != nil {
		return ArtifactRow{}, false, apperr.Wrap(exitcode.Error, "database.artifact",
			"查询 Artifact 失败", err)
	}
	a.SourceID = domain.SourceID(src)
	if t, perr := time.Parse(time.RFC3339, fetched); perr == nil {
		a.FetchedAt = t
	}
	a.SignatureStatus = domain.SignatureStatus(sig)
	a.IntegrityStatus = domain.IntegrityStatus(integ)
	return a, true, nil
}

// SetMeta 写入或更新 app_meta 键值。
func (d *DB) SetMeta(ctx context.Context, key, value string) error {
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO app_meta (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.meta", "写入元信息失败", err)
	}
	return nil
}

// parseTimePtr 解析 RFC3339 文本为时间指针，空值返回 nil。
func parseTimePtr(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s.String)
	if err != nil {
		return nil
	}
	return &t
}
