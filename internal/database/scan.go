package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// ScanRow 是一次扫描的元数据。
type ScanRow struct {
	ID             string
	InventoryID    int64
	DistroID       string
	Release        string
	Arch           string
	StartedAt      time.Time
	CompletedAt    *time.Time
	Coverage       string
	CoverageDetail string
	FeedSnapshot   string
	FindingsTotal  int
	Vulnerable     int
	Unknown        int
}

// FindingRow 是一条已入库的判定结果。
type FindingRow struct {
	CVEID       domain.CVEID
	Package     string
	Arch        string
	Installed   string
	Fixed       string
	Vuln        domain.VulnState
	Remediation domain.RemediationState
	Reboot      domain.RebootState
	Confidence  domain.Confidence
	Severity    domain.Severity
	AdvisoryID  string
	SourceID    domain.SourceID
	Evidence    string
}

// NewScanID 生成扫描 ID：时间戳可读、哈希后缀防并发冲突。
func NewScanID(now time.Time, inventoryHash string) string {
	sum := sha256.Sum256([]byte(inventoryHash))
	return fmt.Sprintf("scan-%s-%s", now.UTC().Format("20060102T150405Z"), hex.EncodeToString(sum[:4]))
}

// SaveScan 在一个事务里写入扫描与其全部判定结果。
//
// 先写 scans 再写 findings：findings 有外键指向 scans，
// 顺序反了会直接失败。整批要么全部可见，要么一条都看不见。
func (d *DB) SaveScan(ctx context.Context, s ScanRow, findings []domain.Finding) error {
	if s.ID == "" || s.InventoryID == 0 {
		return apperr.New(exitcode.Error, "database.scan", "扫描缺少 ID 或资产快照引用")
	}
	// 保留调用方给的扫描时刻；缺失时才用当前时间，避免用写库时刻冒充扫描时刻。
	if s.StartedAt.IsZero() {
		s.StartedAt = time.Now().UTC()
	}
	completed := s.StartedAt
	if s.CompletedAt != nil {
		completed = *s.CompletedAt
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.scan", "开启事务失败", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
INSERT INTO scans (id, inventory_id, distro_id, release, arch, started_at, completed_at,
                   coverage, coverage_detail, feed_snapshot, findings_total, vulnerable, unknown)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		s.ID, s.InventoryID, s.DistroID, s.Release, s.Arch,
		s.StartedAt.UTC().Format(time.RFC3339), completed.UTC().Format(time.RFC3339),
		orDefault(s.Coverage, "UNKNOWN"), s.CoverageDetail, s.FeedSnapshot,
		len(findings), s.Vulnerable, s.Unknown); err != nil {
		return apperr.Wrap(exitcode.Error, "database.scan", "写入扫描记录失败", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO findings (scan_id, inventory_id, cve_id, package_name, package_arch,
                      installed_version, fixed_version, vuln_state, remediation_state,
                      reboot_state, confidence, severity, advisory_id, source_id, evidence)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return apperr.Wrap(exitcode.Error, "database.scan", "准备写入判定结果失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, f := range findings {
		ev, _ := json.Marshal(f.Evidence)
		fixed := ""
		if f.FixedVersion != nil {
			fixed = f.FixedVersion.String()
		}
		if _, err := stmt.ExecContext(ctx,
			s.ID, s.InventoryID, string(f.CVE), f.Package.Name, f.Package.Arch,
			f.Installed.String(), fixed, string(f.Vuln), string(f.Remediation),
			string(f.Runtime.Reboot), string(confidenceOf(f)), string(f.Severity),
			f.AdvisoryID, sourceOf(f), string(ev)); err != nil {
			return apperr.Wrap(exitcode.Error, "database.scan",
				fmt.Sprintf("写入判定结果失败（%s / %s）", f.CVE, f.Package.Name), err)
		}
	}

	if err := tx.Commit(); err != nil {
		return apperr.Wrap(exitcode.Error, "database.scan", "提交扫描失败", err)
	}
	return nil
}

// confidenceOf 由证据推导可信度。
// 有可追溯的官方证据才算 CONFIRMED；其余一律 UNKNOWN，不虚构可信度。
func confidenceOf(f domain.Finding) domain.Confidence {
	if f.Vuln == domain.VulnStateUnknown {
		return domain.ConfidenceUnknown
	}
	for _, e := range f.Evidence {
		if e.MatchKind == domain.MatchCompareError || e.MatchKind == domain.MatchSourceGap {
			return domain.ConfidenceUnknown
		}
	}
	if len(f.Evidence) == 0 {
		return domain.ConfidenceUnknown
	}
	return domain.ConfidenceConfirmed
}

// sourceOf 取该判定主要依据的情报源。
func sourceOf(f domain.Finding) string {
	if len(f.Evidence) > 0 {
		return string(f.Evidence[0].SourceID)
	}
	return ""
}

// LatestScan 返回最近一次扫描。
func (d *DB) LatestScan(ctx context.Context) (ScanRow, bool, error) {
	var s ScanRow
	var started, completed, arch, cov, detail, snap string
	err := d.db.QueryRowContext(ctx, `
SELECT id, inventory_id, distro_id, release, COALESCE(arch,''), started_at,
       COALESCE(completed_at,''), coverage, coverage_detail, feed_snapshot,
       findings_total, vulnerable, unknown
FROM scans ORDER BY started_at DESC, id DESC LIMIT 1`).Scan(
		&s.ID, &s.InventoryID, &s.DistroID, &s.Release, &arch, &started,
		&completed, &cov, &detail, &snap, &s.FindingsTotal, &s.Vulnerable, &s.Unknown)
	if err != nil {
		if err == sql.ErrNoRows {
			return ScanRow{}, false, nil
		}
		return ScanRow{}, false, apperr.Wrap(exitcode.Error, "database.scan", "查询最近扫描失败", err)
	}
	s.Arch, s.Coverage, s.CoverageDetail, s.FeedSnapshot = arch, cov, detail, snap
	if t, perr := time.Parse(time.RFC3339, started); perr == nil {
		s.StartedAt = t
	}
	if completed != "" {
		if t, perr := time.Parse(time.RFC3339, completed); perr == nil {
			s.CompletedAt = &t
		}
	}
	return s, true, nil
}

// ScanFindings 读取某次扫描的判定结果，可按漏洞状态过滤。
func (d *DB) ScanFindings(ctx context.Context, scanID string,
	states []domain.VulnState, limit int) ([]FindingRow, error) {

	q := `SELECT cve_id, package_name, package_arch, installed_version, fixed_version,
                 vuln_state, remediation_state, reboot_state, confidence, severity,
                 advisory_id, source_id, evidence
          FROM findings WHERE scan_id = ?`
	args := []any{scanID}
	if len(states) > 0 {
		ph := ""
		for i, st := range states {
			if i > 0 {
				ph += ","
			}
			ph += "?"
			args = append(args, string(st))
		}
		q += " AND vuln_state IN (" + ph + ")"
	}
	// 排序必须稳定：同一严重程度内按 CVE 与包名排，报告才不会每次顺序不同。
	q += " ORDER BY CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3" +
		" WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, cve_id, package_name"
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.scan", "查询判定结果失败", err)
	}
	defer func() { _ = rows.Close() }()

	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		var vuln, rem, reboot, conf, sev, src string
		if err := rows.Scan(&f.CVEID, &f.Package, &f.Arch, &f.Installed, &f.Fixed,
			&vuln, &rem, &reboot, &conf, &sev, &f.AdvisoryID, &src, &f.Evidence); err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.scan", "读取判定结果失败", err)
		}
		f.Vuln = domain.VulnState(vuln)
		f.Remediation = domain.RemediationState(rem)
		f.Reboot = domain.RebootState(reboot)
		f.Confidence = domain.Confidence(conf)
		f.Severity = domain.Severity(sev)
		f.SourceID = domain.SourceID(src)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.scan", "遍历判定结果失败", err)
	}
	return out, nil
}

// CountFindings 统计满足状态过滤的判定条数（与 ScanFindings 的过滤条件保持一致）。
// 单独提供这个函数，是因为 list --limit 需要同时说清「显示几条」和「一共几条」：
// 只打印显示条数会让 12 万条的结果看起来只有 3 条。
func (d *DB) CountFindings(ctx context.Context, scanID string,
	states []domain.VulnState) (int, error) {

	q := `SELECT COUNT(*) FROM findings WHERE scan_id = ?`
	args := []any{scanID}
	if len(states) > 0 {
		ph := ""
		for i, st := range states {
			if i > 0 {
				ph += ","
			}
			ph += "?"
			args = append(args, string(st))
		}
		q += " AND vuln_state IN (" + ph + ")"
	}
	var n int
	if err := d.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.scan", "统计判定条数失败", err)
	}
	return n, nil
}

// CountByState 统计某次扫描各漏洞状态的条数。
func (d *DB) CountByState(ctx context.Context, scanID string) (map[domain.VulnState]int, error) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT vuln_state, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY vuln_state`, scanID)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.scan", "统计判定结果失败", err)
	}
	defer func() { _ = rows.Close() }()

	out := map[domain.VulnState]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.scan", "读取统计失败", err)
		}
		out[domain.VulnState(st)] = n
	}
	return out, rows.Err()
}

// orDefault 返回非空值或默认值。
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
