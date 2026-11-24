package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/feed"
	"github.com/AronWang001/linux-cve/internal/matcher"
	"github.com/AronWang001/linux-cve/internal/support"
)

// scanReport 是一次扫描的完整结果，供 scan/list/show/report 复用。
type scanReport struct {
	Scan      database.ScanRow
	Counts    map[domain.VulnState]int
	Findings  []database.FindingRow
	Coverage  []feed.Coverage
	NoData    int
	Evaluated int
}

// runScan 采集资产并执行判定。
//
// 用法：linux-cve scan [--json] [--dry-run]
//
// 判定结果默认写库（list/show/report 都基于最近一次扫描）；
// --dry-run 只打印不写库，便于先看结论再决定是否留痕。
func (e *env) runScan(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON, dryRun bool
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	fs.BoolVar(&dryRun, "dry-run", false, "只判定不写库")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}

	started := time.Now().UTC()
	result, err := e.collector().Collect(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	sys := result.System
	inv := result.Inventory

	// 一个包都没采到，只可能是采集链路坏了（包管理器不可用、输出格式变了）。
	// 这时继续走下去会得到「0 条判定」，报告与退出码都是「一切正常」——
	// 正是这个工具最不该犯的错。
	if len(inv.Packages) == 0 {
		return exitcode.Error, apperr.Newf(exitcode.Error, "cli.scan",
			"未采集到任何已安装包（发行版 %s %s，包管理器 %s），拒绝给出「无漏洞」结论",
			inv.DistroID, inv.Release, sys.Manager)
	}

	d, err := e.openDB(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	defer func() { _ = d.Close() }()

	lifecycle := support.Lifecycle(inv.DistroID, inv.Release, started)
	eng := &matcher.Engine{
		Store: d,
		Opts:  matcher.Options{Lifecycle: lifecycle, Now: func() time.Time { return started }},
	}
	mres, err := eng.Match(ctx, inv)
	if err != nil {
		return apperr.CodeOf(err), err
	}

	coverage, covErr := e.coverageOf(ctx, d, inv)
	if covErr != nil {
		return apperr.CodeOf(covErr), covErr
	}
	status, detail := aggregateCoverage(coverage)

	// 有包、但一个都没命中情报库：这不是「没问题」，而是「没对上」。
	// 最常见的成因是 release 粒度不一致（3.20.3 vs 3.20）或包名桥接失效。
	if mres.Evaluated == 0 && len(inv.Packages) > 0 {
		status = feed.CoverageUnknown
		detail = fmt.Sprintf("已安装 %d 个包，没有任何一个命中情报库（release %s、包名或渠道对不上），"+
			"本次结论不可作为安全依据", len(inv.Packages), inv.Release)
	}

	counts := map[domain.VulnState]int{}
	for _, f := range mres.Findings {
		counts[f.Vuln]++
	}

	rep := &scanReport{
		Scan: database.ScanRow{
			ID: database.NewScanID(started, inv.Hash), DistroID: string(inv.DistroID),
			Release: inv.Release, Arch: inv.Arch, StartedAt: started,
			Coverage: status, CoverageDetail: detail,
			FindingsTotal: len(mres.Findings),
			Vulnerable:    counts[domain.VulnStateVulnerable],
			Unknown:       counts[domain.VulnStateUnknown],
		},
		Counts: counts, Coverage: coverage, NoData: mres.NoData, Evaluated: mres.Evaluated,
	}

	if !dryRun {
		invID, err := d.SaveInventory(ctx, &inv)
		if err != nil {
			return apperr.CodeOf(err), err
		}
		rep.Scan.InventoryID = invID
		completed := time.Now().UTC()
		rep.Scan.CompletedAt = &completed
		if err := d.SaveScan(ctx, rep.Scan, mres.Findings); err != nil {
			return apperr.CodeOf(err), err
		}
		rows, err := d.ScanFindings(ctx, rep.Scan.ID, nil, 0)
		if err != nil {
			return apperr.CodeOf(err), err
		}
		rep.Findings = rows
	} else {
		rep.Findings = toFindingRows(mres.Findings)
	}

	if asJSON {
		return e.printScanJSON(rep, sys.Release)
	}
	e.printScanText(rep, lifecycle)
	return scanExitCode(counts, status), nil
}

// scanExitCode 把结论映射为退出码。
//
// 优先级：发现漏洞 > 覆盖不足 > 成功。
// 发现漏洞最具体、最可操作，所以排在最前；覆盖不足排在成功之前，
// 是因为在数据不全时返回 0 会让 CI 把「没检查到」读成「没问题」。
func scanExitCode(counts map[domain.VulnState]int, coverage string) exitcode.Code {
	if counts[domain.VulnStateVulnerable] > 0 {
		// 任务成功但发现漏洞：用 Findings 而不是 Error，
		// 让脚本能区分「跑失败」与「跑成功且有洞」。
		return exitcode.Findings
	}
	if coverage != feed.CoverageCovered {
		return exitcode.Coverage
	}
	return exitcode.OK
}

// coverageOf 汇总每个情报源的覆盖状态。
//
// 这里回答的是「我们的数据够不够用来下结论」，与「有没有漏洞」是两回事：
// 数据缺失时必须显式说明，绝不能让用户把 UNKNOWN 读成安全。
func (e *env) coverageOf(ctx context.Context, d *database.DB,
	inv domain.Inventory) ([]feed.Coverage, error) {

	rows, err := d.FeedStatus(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	maxAge := time.Duration(e.cfg.Feed.MaxAge)

	out := make([]feed.Coverage, 0, len(rows))
	for _, r := range rows {
		src, known := feed.SourceByID(r.ID)
		if known && !src.AppliesTo(inv.DistroID) {
			// 与目标发行版无关的源不参与覆盖判定。
			continue
		}
		c := feed.Coverage{SourceID: r.ID, State: feed.CoverageUnknown}
		switch {
		case r.LastSuccessAt == nil:
			c.Reason = "从未成功同步"
		case maxAge > 0 && now.Sub(*r.LastSuccessAt) > maxAge:
			c.State = feed.CoveragePartial
			c.Reason = fmt.Sprintf("情报已过期（最近同步于 %s）", r.LastSuccessAt.Format("2006-01-02"))
			c.LastSyncAt = *r.LastSuccessAt
			c.Age = now.Sub(*r.LastSuccessAt)
			c.Stale = true
		default:
			c.State = feed.CoverageCovered
			c.Reason = "已同步"
			c.LastSyncAt = *r.LastSuccessAt
			c.Age = now.Sub(*r.LastSuccessAt)
		}
		// 必须用 ParserReady 而不是 ParserFor：CSAF 源按文档发布，
		// 用单文件解析器表去判断会把已经接入的 RHEL/SUSE 误报成「未实现」。
		if known {
			if _, reason := feed.ParserReady(src); reason != "" {
				c.State = feed.CoverageUnknown
				c.Reason = "解析器未就绪：" + reason
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// aggregateCoverage 把各源状态聚合成整次扫描的覆盖判定。
func aggregateCoverage(cov []feed.Coverage) (string, string) {
	covered, partial := 0, 0
	var notes []string
	for _, c := range cov {
		switch c.State {
		case feed.CoverageCovered:
			covered++
			continue
		case feed.CoveragePartial:
			partial++
		}
		if c.Reason != "" {
			notes = append(notes, string(c.SourceID)+"："+c.Reason)
		}
	}
	switch {
	case len(cov) == 0:
		return feed.CoverageUnknown, "没有与该发行版对应的情报源，本次结论不可作为安全依据"
	case covered > 0 && partial == 0 && len(notes) == 0:
		return feed.CoverageCovered, "该发行版所需的全部情报源均可用且未过期"
	case covered == 0 && partial == 0:
		return feed.CoverageUnknown, "没有任何可用的情报源：" + strings.Join(notes, "；")
	default:
		return feed.CoveragePartial, strings.Join(notes, "；")
	}
}

// printScanText 输出人类可读的扫描摘要。
func (e *env) printScanText(rep *scanReport, lifecycle domain.LifecycleState) {
	s := rep.Scan
	fmt.Fprintf(e.stdout, "扫描：%s  %s  架构 %s\n", s.DistroID, s.Release, s.Arch)
	fmt.Fprintf(e.stdout, "覆盖：%s（%s）\n", s.Coverage, s.CoverageDetail)
	fmt.Fprintf(e.stdout, "生命周期：%s —— %s\n\n", lifecycle, support.Note(domain.DistroID(s.DistroID), s.Release))
	fmt.Fprintf(e.stdout, "判定 %d 条：受影响 %d、已修复 %d、不受影响 %d、未知 %d\n",
		s.FindingsTotal,
		rep.Counts[domain.VulnStateVulnerable], rep.Counts[domain.VulnStateFixed],
		rep.Counts[domain.VulnStateNotAffected], rep.Counts[domain.VulnStateUnknown])
	fmt.Fprintf(e.stdout, "统计：参与判定包 %d 个，其中 %d 个在情报库中无任何记录（属覆盖缺口，不代表安全）\n",
		rep.Evaluated, rep.NoData)

	if n := rep.Counts[domain.VulnStateVulnerable]; n > 0 {
		fmt.Fprintf(e.stdout, "\n受影响明细（前 20 条，完整清单用 list）：\n")
		printed := 0
		for _, f := range rep.Findings {
			if f.Vuln != domain.VulnStateVulnerable {
				continue
			}
			fmt.Fprintf(e.stdout, "  %-8s %-16s %-24s 本机 %-24s 修复 %-24s %s\n",
				f.Severity, f.Package, f.CVEID, f.Installed, orDash(f.Fixed), f.Remediation)
			printed++
			if printed >= 20 {
				break
			}
		}
	}
}

// printScanJSON 输出机器可读结果。
func (e *env) printScanJSON(rep *scanReport, systemRelease string) (exitcode.Code, error) {
	type findingDTO struct {
		CVE         string `json:"cve_id"`
		Package     string `json:"package"`
		Arch        string `json:"arch"`
		Installed   string `json:"installed_version"`
		Fixed       string `json:"fixed_version,omitempty"`
		Vuln        string `json:"vuln_state"`
		Remediation string `json:"remediation_state"`
		Reboot      string `json:"reboot_state"`
		Confidence  string `json:"confidence"`
		Severity    string `json:"severity"`
		AdvisoryID  string `json:"advisory_id,omitempty"`
		SourceID    string `json:"source_id,omitempty"`
	}
	out := make([]findingDTO, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, findingDTO{
			CVE: string(f.CVEID), Package: f.Package, Arch: f.Arch, Installed: f.Installed,
			Fixed: f.Fixed, Vuln: string(f.Vuln), Remediation: string(f.Remediation),
			Reboot: string(f.Reboot), Confidence: string(f.Confidence),
			Severity: string(f.Severity), AdvisoryID: f.AdvisoryID, SourceID: string(f.SourceID),
		})
	}
	payload := map[string]any{
		"schema_version":  1,
		"scan_id":         rep.Scan.ID,
		"distro":          rep.Scan.DistroID,
		"release":         rep.Scan.Release,
		"arch":            rep.Scan.Arch,
		"coverage":        rep.Scan.Coverage,
		"coverage_detail": rep.Scan.CoverageDetail,
		"counts": map[string]int{
			"total":        rep.Scan.FindingsTotal,
			"vulnerable":   rep.Counts[domain.VulnStateVulnerable],
			"fixed":        rep.Counts[domain.VulnStateFixed],
			"not_affected": rep.Counts[domain.VulnStateNotAffected],
			"unknown":      rep.Counts[domain.VulnStateUnknown],
			"no_data":      rep.NoData,
			"evaluated":    rep.Evaluated,
		},
		"findings": out,
	}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return exitcode.Error, apperr.Wrap(exitcode.Error, "cli.scan", "序列化失败", err)
	}
	fmt.Fprintln(e.stdout, string(b))
	return scanExitCode(rep.Counts, rep.Scan.Coverage), nil
}

// runList 列出最近一次扫描的判定结果。
func (e *env) runList(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON, onlyVuln bool
	var state string
	var limit int
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	fs.BoolVar(&onlyVuln, "vulnerable", false, "只列受影响项")
	fs.StringVar(&state, "state", "", "按状态过滤：VULNERABLE|FIXED|NOT_AFFECTED|UNKNOWN")
	fs.IntVar(&limit, "limit", 0, "最多显示条数")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}
	d, err := e.openDB(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	defer func() { _ = d.Close() }()

	scan, ok, err := d.LatestScan(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	if !ok {
		return exitcode.Error, apperr.New(exitcode.Error, "cli.list",
			"还没有任何扫描记录，请先运行 linux-cve scan")
	}

	var states []domain.VulnState
	switch {
	case state != "":
		st := domain.VulnState(strings.ToUpper(state))
		if !st.Valid() {
			return exitcode.Usage, apperr.Newf(exitcode.Usage, "cli.list", "非法的状态 %q", state)
		}
		states = []domain.VulnState{st}
	case onlyVuln:
		states = []domain.VulnState{domain.VulnStateVulnerable}
	}

	rows, err := d.ScanFindings(ctx, scan.ID, states, limit)
	if err != nil {
		return apperr.CodeOf(err), err
	}

	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"schema_version": 1, "scan_id": scan.ID, "items": rows,
		}, "", "  ")
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}

	if len(rows) == 0 {
		fmt.Fprintln(e.stdout, "没有匹配的判定结果。")
		return exitcode.OK, nil
	}
	total := len(rows)
	if limit > 0 {
		// --limit 只影响「显示」，不能改变「一共多少」这个事实。
		if n, err := d.CountFindings(ctx, scan.ID, states); err == nil {
			total = n
		}
	}
	if total > len(rows) {
		fmt.Fprintf(e.stdout, "扫描 %s（%s %s）共 %d 条，显示前 %d 条（--limit）：\n\n",
			scan.ID, scan.DistroID, scan.Release, total, len(rows))
	} else {
		fmt.Fprintf(e.stdout, "扫描 %s（%s %s）共 %d 条：\n\n", scan.ID, scan.DistroID, scan.Release, total)
	}
	fmt.Fprintf(e.stdout, "%-8s %-16s %-20s %-22s %-22s %-16s\n",
		"严重度", "包", "CVE", "本机版本", "修复版本", "结论")
	for _, f := range rows {
		fmt.Fprintf(e.stdout, "%-8s %-16s %-20s %-22s %-22s %-16s\n",
			f.Severity, truncateText(f.Package, 16), f.CVEID,
			truncateText(f.Installed, 22), truncateText(orDash(f.Fixed), 22), f.Vuln)
	}
	return exitcode.OK, nil
}

// runShow 展示单条判定的完整证据链。
//
// 证据必须能回答三个问题：数据来自哪份原始文件、签名与哈希各是什么状态、
// 判定用了哪条规则。缺任何一项，这条结论就无法被审计。
func (e *env) runShow(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("show", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	if fs.NArg() == 0 {
		return exitcode.Usage, apperr.New(exitcode.Usage, "cli.show", "show 需要 CVE 编号")
	}
	cve := strings.ToUpper(strings.TrimSpace(fs.Arg(0)))
	if !domain.CVEID(cve).Valid() {
		return exitcode.Usage, apperr.Newf(exitcode.Usage, "cli.show", "非法 CVE 编号 %q", cve)
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}
	d, err := e.openDB(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	defer func() { _ = d.Close() }()

	scan, ok, err := d.LatestScan(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	if !ok {
		return exitcode.Error, apperr.New(exitcode.Error, "cli.show",
			"还没有任何扫描记录，请先运行 linux-cve scan")
	}
	rows, err := d.ScanFindings(ctx, scan.ID, nil, 0)
	if err != nil {
		return apperr.CodeOf(err), err
	}

	var hits []database.FindingRow
	for _, r := range rows {
		if string(r.CVEID) == cve {
			hits = append(hits, r)
		}
	}
	if len(hits) == 0 {
		return exitcode.Unsupported, apperr.Newf(exitcode.Unsupported, "cli.show",
			"最近一次扫描（%s）中没有 %s 的记录", scan.ID, cve)
	}

	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"schema_version": 1, "scan_id": scan.ID, "cve_id": cve, "items": hits,
		}, "", "  ")
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}

	for i, h := range hits {
		if i > 0 {
			fmt.Fprintln(e.stdout)
		}
		fmt.Fprintf(e.stdout, "CVE：%s\n", h.CVEID)
		fmt.Fprintf(e.stdout, "包：%s（%s）\n", h.Package, h.Arch)
		fmt.Fprintf(e.stdout, "本机版本：%s\n", h.Installed)
		fmt.Fprintf(e.stdout, "修复版本：%s\n", orDash(h.Fixed))
		fmt.Fprintf(e.stdout, "严重度：%s\n", h.Severity)
		fmt.Fprintf(e.stdout, "检测结论：%s\n", h.Vuln)
		fmt.Fprintf(e.stdout, "修复可行性：%s\n", h.Remediation)
		fmt.Fprintf(e.stdout, "证据可信度：%s\n", h.Confidence)
		fmt.Fprintf(e.stdout, "公告：%s（%s）\n", orDash(h.AdvisoryID), orDash(string(h.SourceID)))
		if h.Evidence != "" && h.Evidence != "null" {
			fmt.Fprintf(e.stdout, "证据链：%s\n", h.Evidence)
		}
	}
	return exitcode.OK, nil
}

// runReport 生成 Markdown 验收报告。
func (e *env) runReport(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var outPath string
	fs.StringVar(&outPath, "out", "", "写入文件（默认输出到标准输出）")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}
	d, err := e.openDB(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	defer func() { _ = d.Close() }()

	scan, ok, err := d.LatestScan(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	if !ok {
		return exitcode.Error, apperr.New(exitcode.Error, "cli.report",
			"还没有任何扫描记录，请先运行 linux-cve scan")
	}
	rows, err := d.ScanFindings(ctx, scan.ID, nil, 0)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	adv, _ := d.CountAdvisories(ctx)
	fixes, _ := d.CountFixes(ctx)
	srcStatus, _ := d.FeedStatus(ctx)

	md := renderReport(scan, rows, adv, fixes, srcStatus)
	if outPath != "" {
		if err := writeFile(outPath, md); err != nil {
			return exitcode.Error, err
		}
		fmt.Fprintf(e.stdout, "报告已写入 %s\n", outPath)
		return exitcode.OK, nil
	}
	fmt.Fprint(e.stdout, md)
	return exitcode.OK, nil
}

// toFindingRows 把领域对象转成展示用行，供 --dry-run 使用。
func toFindingRows(fs []domain.Finding) []database.FindingRow {
	out := make([]database.FindingRow, 0, len(fs))
	for _, f := range fs {
		fixed := ""
		if f.FixedVersion != nil {
			fixed = f.FixedVersion.String()
		}
		src := ""
		if len(f.Evidence) > 0 {
			src = string(f.Evidence[0].SourceID)
		}
		conf := domain.ConfidenceUnknown
		if f.Vuln != domain.VulnStateUnknown && len(f.Evidence) > 0 {
			conf = domain.ConfidenceConfirmed
		}
		out = append(out, database.FindingRow{
			CVEID: f.CVE, Package: f.Package.Name, Arch: f.Package.Arch,
			Installed: f.Installed.String(), Fixed: fixed, Vuln: f.Vuln,
			Remediation: f.Remediation, Reboot: f.Runtime.Reboot, Confidence: conf,
			Severity: f.Severity, AdvisoryID: f.AdvisoryID, SourceID: domain.SourceID(src),
		})
	}
	return out
}

// orDash 空值显示为短横线，避免表格错位。
func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
