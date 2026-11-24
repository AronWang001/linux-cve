package database

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// FixRow 是「某发行版某 release 中某包被某 CVE 修复」的一条可比较事实。
//
// 它只承载判定所需的最小字段：判定逻辑不关心公告全文，
// 但必须能说出这条结论来自哪个源、哪份 Artifact、签名与哈希各自是什么状态。
type FixRow struct {
	SourceID    domain.SourceID
	AdvisoryID  string
	CVEID       domain.CVEID
	Severity    domain.Severity
	Title       string
	URL         string
	Channel     string
	PackageKind domain.PackageKind
	PackageName string
	Arch        string

	FixedVersion string
	// Official 为 false 表示该版本取自仓库当前版本（弱证据），
	// 只能用于「已修复」而不能用于「受影响」。
	Official bool

	Signature domain.SignatureStatus
	Integrity domain.IntegrityStatus
	FetchedAt time.Time
}

// NotAffectedRow 是官方显式的不受影响声明。
type NotAffectedRow struct {
	SourceID   domain.SourceID
	AdvisoryID string
	CVEID      domain.CVEID
	Package    string
	Kind       domain.PackageKind
	Arch       string
	Reason     domain.NotAffectedReason
	URL        string
}

// nameChunk 是单条 SQL 里 IN 列表的上限。
// SQLite 的变量上限是 32766（编译期可调），一次塞几万个包名会直接报错；
// 分块查询同时避免生成过长的语句。
const nameChunk = 500

// FixesForPackages 查询指定 release 下这些包名对应的全部修复事实。
//
// 只按 (distro, release, package_name) 过滤，不在这里做版本比较：
// 版本比较必须用发行版原生规则，属于匹配器的职责。
func (d *DB) FixesForPackages(ctx context.Context, distro domain.DistroID, release string,
	names []string) ([]FixRow, error) {

	if len(names) == 0 {
		return nil, nil
	}
	out := make([]FixRow, 0, len(names))
	for _, chunk := range chunkNames(names, nameChunk) {
		rows, err := d.fixesForChunk(ctx, distro, release, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

func (d *DB) fixesForChunk(ctx context.Context, distro domain.DistroID, release string,
	names []string) ([]FixRow, error) {

	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")
	q := `
SELECT f.source_id, f.advisory_id, f.cve_id, a.severity, a.title, a.url, f.channel,
       f.package_kind, f.package_name, f.arch, f.fixed_version_raw, f.fixed_version_source,
       COALESCE(fa.signature_status, 'unverified'), COALESCE(fa.integrity_status, 'unchecked'),
       a.fetched_at
FROM advisory_fixes f
JOIN advisories a
  ON a.source_id = f.source_id AND a.advisory_id = f.advisory_id AND a.cve_id = f.cve_id
LEFT JOIN feed_artifacts fa ON fa.sha256 = a.artifact_sha256
WHERE f.distro_id = ? AND f.release = ? AND f.package_name IN (` + placeholders + `)
  AND a.retracted_at IS NULL`

	args := make([]any, 0, len(names)+2)
	args = append(args, string(distro), release)
	for _, n := range names {
		args = append(args, n)
	}

	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.fix", "查询修复记录失败", err)
	}
	defer func() { _ = rows.Close() }()

	var out []FixRow
	for rows.Next() {
		var r FixRow
		var sev, sig, integ, fetched, src string
		var fvs string
		if err := rows.Scan(&src, &r.AdvisoryID, &r.CVEID, &sev, &r.Title, &r.URL, &r.Channel,
			&r.PackageKind, &r.PackageName, &r.Arch, &r.FixedVersion, &fvs,
			&sig, &integ, &fetched); err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.fix", "读取修复记录失败", err)
		}
		r.SourceID = domain.SourceID(src)
		r.Severity = domain.Severity(sev)
		r.Signature = domain.SignatureStatus(sig)
		r.Integrity = domain.IntegrityStatus(integ)
		r.Official = fvs == "" || fvs == domain.FixVersionOfficial
		if t, perr := time.Parse(time.RFC3339, fetched); perr == nil {
			r.FetchedAt = t
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(exitcode.Error, "database.fix", "遍历修复记录失败", err)
	}
	return out, nil
}

// NotAffectedForPackages 查询官方显式的不受影响声明。
func (d *DB) NotAffectedForPackages(ctx context.Context, distro domain.DistroID, release string,
	names []string) ([]NotAffectedRow, error) {

	if len(names) == 0 {
		return nil, nil
	}
	var out []NotAffectedRow
	for _, chunk := range chunkNames(names, nameChunk) {
		placeholders := strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",")
		q := `
SELECT source_id, advisory_id, cve_id, package_name, package_kind, arch, reason, evidence_url
FROM advisory_not_affected
WHERE distro_id = ? AND release = ? AND package_name IN (` + placeholders + `)`

		args := make([]any, 0, len(chunk)+2)
		args = append(args, string(distro), release)
		for _, n := range chunk {
			args = append(args, n)
		}
		rows, err := d.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, apperr.Wrap(exitcode.Error, "database.fix", "查询不受影响声明失败", err)
		}
		for rows.Next() {
			var r NotAffectedRow
			var src, reason, kind string
			if err := rows.Scan(&src, &r.AdvisoryID, &r.CVEID, &r.Package, &kind, &r.Arch, &reason, &r.URL); err != nil {
				_ = rows.Close()
				return nil, apperr.Wrap(exitcode.Error, "database.fix", "读取不受影响声明失败", err)
			}
			r.SourceID = domain.SourceID(src)
			r.Kind = domain.PackageKind(kind)
			r.Reason = domain.NotAffectedReason(reason)
			out = append(out, r)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return nil, apperr.Wrap(exitcode.Error, "database.fix", "遍历不受影响声明失败", err)
		}
		_ = rows.Close()
	}
	return out, nil
}

// chunkNames 去空、去重后按固定大小切块，保持输入顺序。
func chunkNames(names []string, size int) [][]string {
	seen := make(map[string]struct{}, len(names))
	uniq := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		uniq = append(uniq, n)
	}
	sort.Strings(uniq)
	if size <= 0 {
		size = nameChunk
	}
	var out [][]string
	for i := 0; i < len(uniq); i += size {
		end := i + size
		if end > len(uniq) {
			end = len(uniq)
		}
		out = append(out, uniq[i:end])
	}
	return out
}

// CountFixes 返回当前库中可用于判定的修复记录总数，供 feed status 与报告引用。
func (d *DB) CountFixes(ctx context.Context) (int, error) {
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM advisory_fixes`).Scan(&n); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.fix", "统计修复记录失败", err)
	}
	return n, nil
}

// CountAdvisories 返回当前库中的公告总数。
func (d *DB) CountAdvisories(ctx context.Context) (int, error) {
	var n int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM advisories`).Scan(&n); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.fix", "统计公告失败", err)
	}
	return n, nil
}
