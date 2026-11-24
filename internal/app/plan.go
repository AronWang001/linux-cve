package app

// plan / fix 两个子命令。
//
// plan 是纯预演：读最近一次扫描结果，生成「要升级哪些包、到哪个版本、
// 覆盖哪些 CVE」，一个字节都不改系统。
// fix 才是执行，且必须显式 --yes；执行后重新采集版本再复检，
// 结论只认复检结果。

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/plan"
	"github.com/AronWang001/linux-cve/internal/support"
)

// pkgFilter 是 --package 的取值集合（逗号分隔，可重复出现）。
//
// 提供这个开关的唯一理由是范围控制：默认修复「扫描判定的全部受影响包」，
// 而在生产机上往往要先只修一两个包验证行为。少一个开关，用户就只能
// 用包管理器手工做，绕开复检——那才是真正的风险。
type pkgFilter []string

func (f *pkgFilter) String() string { return strings.Join(*f, ",") }

func (f *pkgFilter) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

// allowed 返回包名判定函数；未指定过滤时返回 nil 表示全部允许。
func (f pkgFilter) allowed() func(string) bool {
	if len(f) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(f))
	for _, name := range f {
		set[name] = struct{}{}
	}
	return func(name string) bool { _, ok := set[name]; return ok }
}

// buildPlan 从最近一次扫描结果生成计划。
//
// 复用最近一次扫描而不是重新判定：修复计划必须与用户看过的清单一致，
// 否则「我批准的那份」与「实际执行的那份」不是同一份。
func (e *env) buildPlan(ctx context.Context, d *database.DB, entry support.Entry,
	only func(string) bool) (*plan.Plan, database.ScanRow, error) {
	scan, ok, err := d.LatestScan(ctx)
	if err != nil {
		return nil, scan, err
	}
	if !ok {
		return nil, scan, apperr.New(exitcode.Error, "cli.plan",
			"还没有扫描记录，请先运行 linux-cve scan")
	}
	rows, err := d.ScanFindings(ctx, scan.ID, nil, 0)
	if err != nil {
		return nil, scan, err
	}

	cands := make([]plan.Candidate, 0, len(rows))
	for _, r := range rows {
		if only != nil && !only(r.Package) {
			continue
		}
		cands = append(cands, plan.Candidate{
			Package: r.Package, Arch: r.Arch, Installed: r.Installed, Fixed: r.Fixed,
			CVE: r.CVEID, Severity: r.Severity, Vuln: r.Vuln,
			Remediation: r.Remediation, Lifecycle: support.Lifecycle(
				domain.DistroID(scan.DistroID), scan.Release, time.Now()),
			Channel: "",
		})
	}
	manager := managerForDistro(domain.DistroID(scan.DistroID))
	p := plan.Build(domain.DistroID(scan.DistroID), scan.Release, manager, cands, entry, time.Now().UTC())

	// 配置开关是硬闸门：默认关闭，`--yes` 也不能绕过。
	// 这条判断必须放在这里而不是 runFix 里，plan 也要显示「为什么不可执行」，
	// 否则用户看到的是一份看似可执行的计划，执行时才被拒。
	if !e.cfg.Remediation.AllowAutoFix {
		p.Blocked = true
		p.Reason = domain.ReasonPlanBlocked
		p.BlockedDetail = "配置未开启自动修复（remediation.allow_auto_fix = false）"
	}
	return p, scan, nil
}

// managerForDistro 按发行版族推断包管理器。
//
// 这里不是「猜命令」：Command() 只生成升级命令，真正的可用性
// 由执行时的返回码体现；族到管理器的映射在支持矩阵范围内是确定的。
func managerForDistro(d domain.DistroID) domain.PackageManager {
	switch d.Family() {
	case domain.FamilyDebian:
		return domain.ManagerDPKG
	case domain.FamilyRPM, domain.FamilySUSE:
		return domain.ManagerRPM
	case domain.FamilyAlpine:
		return domain.ManagerAPK
	case domain.FamilyArch:
		return domain.ManagerPacman
	default:
		return domain.ManagerNone
	}
}

// runPlan 实现 linux-cve plan。
func (e *env) runPlan(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON bool
	var filter pkgFilter
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	fs.Var(&filter, "package", "只处理指定包（逗号分隔，可重复）")
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

	// 计划先要知道目标系统是哪个 release 才能查支持矩阵。
	scan, ok, err := d.LatestScan(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	if !ok {
		return exitcode.Error, apperr.New(exitcode.Error, "cli.plan",
			"还没有扫描记录，请先运行 linux-cve scan")
	}
	entry, found := support.Lookup(domain.DistroID(scan.DistroID), scan.Release)
	if !found {
		// 未登记的 release 不按「最新的那个」兜底：生命周期未知就不能自动修复。
		entry = support.Entry{Distro: domain.DistroID(scan.DistroID), Version: scan.Release,
			Note: "该 release 未登记在支持矩阵中"}
	}

	p, scan, err := e.buildPlan(ctx, d, entry, filter.allowed())
	if err != nil {
		return apperr.CodeOf(err), err
	}
	if len(filter) > 0 && len(p.Steps) == 0 {
		// 过滤后没有命中，多半是包名写错或该包本来就不受影响。
		// 静默返回「没有可修复项」会让人以为修复完成，必须说清。
		fmt.Fprintf(e.stdout, "指定的包 %s 在本次扫描中没有可执行的修复步骤。\n",
			strings.Join(filter, ","))
	}

	if asJSON {
		b, merr := json.MarshalIndent(planDTO(p, scan), "", "  ")
		if merr != nil {
			return exitcode.Error, apperr.Wrap(exitcode.Error, "cli.plan", "序列化失败", merr)
		}
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}
	e.printPlan(p, scan)
	return exitcode.OK, nil
}

func planDTO(p *plan.Plan, scan database.ScanRow) map[string]any {
	steps := make([]map[string]any, 0, len(p.Steps))
	for _, s := range p.Steps {
		cves := make([]string, 0, len(s.CVEs))
		for _, c := range s.CVEs {
			cves = append(cves, string(c))
		}
		steps = append(steps, map[string]any{
			"package": s.Package, "arch": s.Arch, "from": s.From, "to": s.To,
			"manager": string(s.Manager), "severity": string(s.Severity), "cves": cves,
		})
	}
	skips := make([]map[string]any, 0, len(p.Skipped))
	for _, s := range p.Skipped {
		skips = append(skips, map[string]any{
			"reason": string(s.Reason), "description": s.Reason.Description(), "count": s.Count,
		})
	}
	return map[string]any{
		"schema_version": 1,
		"scan_id":        scan.ID,
		"distro":         string(p.Distro),
		"release":        p.Release,
		"manager":        string(p.Manager),
		"lifecycle":      string(p.Lifecycle),
		"blocked":        p.Blocked,
		"blocked_reason": string(p.Reason),
		"blocked_detail": p.BlockedDetail,
		"executable":     p.Executable(),
		"steps":          steps,
		"skipped":        skips,
		"findings":       p.Findings,
		"cves_covered":   p.TotalCVEs(),
	}
}

// printPlan 输出人类可读的计划。
func (e *env) printPlan(p *plan.Plan, scan database.ScanRow) {
	fmt.Fprintf(e.stdout, "修复计划（基于扫描 %s）\n", scan.ID)
	fmt.Fprintf(e.stdout, "目标：%s %s，包管理器 %s，生命周期 %s\n",
		p.Distro, p.Release, p.Manager, p.Lifecycle)
	fmt.Fprintf(e.stdout, "参与判定 %d 条，计划覆盖 %d 个 CVE、%d 个包\n\n",
		p.Findings, p.TotalCVEs(), len(p.Steps))

	if p.Blocked {
		fmt.Fprintf(e.stdout, "状态：不可执行 —— %s\n", p.BlockedDetail)
		if len(p.Steps) > 0 {
			fmt.Fprintf(e.stdout, "以下步骤仅为预演，不会执行：\n")
		}
	} else if len(p.Steps) == 0 {
		fmt.Fprintf(e.stdout, "状态：没有可自动修复的项\n")
	}

	if len(p.Steps) > 0 {
		fmt.Fprintf(e.stdout, "%-28s %-10s %-26s %-26s %s\n",
			"包", "严重度", "本机版本", "目标版本", "覆盖 CVE")
		for _, s := range p.Steps {
			fmt.Fprintf(e.stdout, "%-28s %-10s %-26s %-26s %d\n",
				truncateText(s.Package, 28), s.Severity, truncateText(s.From, 26), truncateText(s.To, 26), len(s.CVEs))
		}
	}
	if len(p.Skipped) > 0 {
		fmt.Fprintf(e.stdout, "\n未纳入计划的判定：\n")
		for _, s := range p.Skipped {
			fmt.Fprintf(e.stdout, "  %-6d %s（%s）\n", s.Count, s.Reason.Description(), s.Reason)
		}
	}
}

// runFix 实现 linux-cve fix。
func (e *env) runFix(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON, yes, dryRun bool
	var filter pkgFilter
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	fs.BoolVar(&yes, "yes", false, "确认执行（无此参数只打印计划）")
	fs.BoolVar(&dryRun, "dry-run", false, "只打印计划，不执行")
	fs.Var(&filter, "package", "只处理指定包（逗号分隔，可重复）")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}
	if !yes || dryRun {
		// 没有确认就当作预演：绝不因为「参数忘了写」就动系统。
		code, err := e.runPlan(ctx, filterArgs(filter))
		if err != nil {
			return code, err
		}
		fmt.Fprintln(e.stdout, "\n以上为预演。确认执行请加 --yes。")
		return code, nil
	}
	if !isRoot() {
		return exitcode.Permission, apperr.New(exitcode.Permission, "cli.fix",
			"修复需要 root 权限（升级软件包）")
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
		return exitcode.Error, apperr.New(exitcode.Error, "cli.fix",
			"还没有扫描记录，请先运行 linux-cve scan")
	}
	entry, found := support.Lookup(domain.DistroID(scan.DistroID), scan.Release)
	if !found {
		entry = support.Entry{Distro: domain.DistroID(scan.DistroID), Version: scan.Release,
			Note: "该 release 未登记在支持矩阵中"}
	}
	p, scan, err := e.buildPlan(ctx, d, entry, filter.allowed())
	if err != nil {
		return apperr.CodeOf(err), err
	}
	// 闸门判断必须在「没有步骤」之前：被闸门拦下的计划也常常没有步骤，
	// 先判 0 会把「配置禁止自动修复」报成「没有需要修复的项」，
	// 脚本读退出码就会以为一切正常。
	if p.Blocked {
		e.printPlan(p, scan)
		return exitcode.Unsupported, apperr.Newf(exitcode.Unsupported, "cli.fix",
			"计划不可执行：%s", p.BlockedDetail)
	}
	if len(filter) > 0 && len(p.Steps) == 0 {
		e.printPlan(p, scan)
		fmt.Fprintf(e.stdout, "指定的包 %s 没有可执行的修复步骤，未做任何改动。\n",
			strings.Join(filter, ","))
		return exitcode.OK, nil
	}
	if len(p.Steps) == 0 {
		e.printPlan(p, scan)
		fmt.Fprintln(e.stdout, "没有需要自动修复的项。")
		return exitcode.OK, nil
	}

	// 执行前留一份包清单：升级可能顺带装上依赖，那是变更集之外的改动。
	// 没有这份快照，就只能事后听包管理器自己说装了什么。
	before, berr := e.collectVersions(ctx)
	if berr != nil {
		return apperr.CodeOf(berr), berr
	}

	runner := plan.OSRunner{}
	execRes, err := plan.Execute(ctx, p, runner, func(s plan.Step, i, total int) {
		fmt.Fprintf(e.stderr, "[%d/%d] 升级 %s → %s\n", i, total, s.Package, s.To)
	})
	if err != nil {
		return apperr.CodeOf(err), err
	}

	// 复检：重新采集版本，按发行版原生规则比较。
	current, cerr := e.collectVersions(ctx)
	if cerr != nil {
		return apperr.CodeOf(cerr), cerr
	}
	verifications, allOK := plan.Verify(p, current)
	collateral := diffPackages(before, current)
	limit := e.cfg.Remediation.MaxCollateralPackages
	overLimit := limit > 0 && len(collateral.Added) > limit

	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{
			"schema_version": 1,
			"scan_id":        scan.ID,
			"steps":          execRes.Applied,
			"verified":       verifications,
			"collateral":     collateral,
			"ok":             allOK && execRes.Failed == nil && !overLimit,
		}, "", "  ")
		fmt.Fprintln(e.stdout, string(b))
	} else {
		e.printFixResult(execRes, verifications, allOK)
		e.printCollateral(collateral, limit)
	}

	if execRes.Failed != nil {
		return exitcode.RemediationFailed, apperr.Newf(exitcode.RemediationFailed, "cli.fix",
			"%s 升级失败", execRes.Failed.Step.Package)
	}
	if !allOK {
		return exitcode.RemediationFailed, apperr.New(exitcode.RemediationFailed, "cli.fix",
			"复检未通过：仍有包低于目标版本")
	}
	if overLimit {
		return exitcode.RemediationFailed, apperr.Newf(exitcode.RemediationFailed, "cli.fix",
			"附带变更 %d 个包，超过上限 %d（remediation.max_collateral_packages），请人工复核",
			len(collateral.Added), limit)
	}
	return exitcode.OK, nil
}

// pkgDiff 是执行前后的包集合差异。
type pkgDiff struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

// diffPackages 比较执行前后的包清单。
//
// 只关心「包名 × 架构」的增删，不关心版本变化——版本变化是计划内的事。
// 但「顺带装了 27 个新包」不是计划内的事，必须报出来。
func diffPackages(before, after map[string]string) pkgDiff {
	var d pkgDiff
	for k := range after {
		if _, ok := before[k]; !ok {
			d.Added = append(d.Added, pkgLabel(k))
		}
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			d.Removed = append(d.Removed, pkgLabel(k))
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	return d
}

// pkgLabel 把「名\x00架构」还原成可读形式。
func pkgLabel(k string) string {
	if i := strings.IndexByte(k, 0); i >= 0 {
		return k[:i] + " (" + k[i+1:] + ")"
	}
	return k
}

// printCollateral 输出附带变更。
func (e *env) printCollateral(d pkgDiff, limit int) {
	if len(d.Added) == 0 && len(d.Removed) == 0 {
		return
	}
	if len(d.Added) > 0 {
		fmt.Fprintf(e.stdout, "\n附带安装 %d 个包（上限 %d）：%s\n",
			len(d.Added), limit, strings.Join(d.Added, ", "))
	}
	if len(d.Removed) > 0 {
		fmt.Fprintf(e.stdout, "附带移除 %d 个包：%s\n", len(d.Removed), strings.Join(d.Removed, ", "))
	}
}

// collectVersions 复检时重新采集已安装版本。
func (e *env) collectVersions(ctx context.Context) (map[string]string, error) {
	res, err := e.collector().Collect(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(res.Inventory.Packages))
	for _, p := range res.Inventory.Packages {
		out[p.Ref.Name+"\x00"+p.Ref.Arch] = p.Ref.Version.String()
	}
	return out, nil
}

// printFixResult 输出执行与复检结论。
func (e *env) printFixResult(res *plan.ExecResult, vs []plan.VerifyResult, allOK bool) {
	for _, a := range res.Applied {
		status := "成功"
		if a.Err != nil {
			status = "失败"
		}
		fmt.Fprintf(e.stdout, "%s %s → %s：%s\n", status, a.Step.Package, a.Step.To, oneLine(a.Output))
		if a.Err != nil {
			fmt.Fprintf(e.stdout, "  原因：%s\n", a.Err)
		}
	}
	fmt.Fprintf(e.stdout, "\n复检结果：\n")
	for _, v := range vs {
		mark := "OK"
		if !v.OK {
			mark = "NG"
		}
		fmt.Fprintf(e.stdout, "  %-3s %-28s 目标 %-24s 实际 %-24s %s\n",
			mark, truncateText(v.Package, 28), v.Want, v.Got, v.Detail)
	}
	if allOK {
		fmt.Fprintln(e.stdout, "\n结论：计划内全部包已达到目标版本。")
		if kernelTouched(vs) {
			fmt.Fprintln(e.stdout, "注意：涉及内核包，需要重启主机才能让新内核生效。")
		}
	} else {
		fmt.Fprintln(e.stdout, "\n结论：仍有包未达到目标版本，不能声称已修复。")
	}
}

// kernelTouched 判断复检项里是否包含内核包。
func kernelTouched(vs []plan.VerifyResult) bool {
	for _, v := range vs {
		n := v.Package
		if strings.HasPrefix(n, "linux-image") || strings.HasPrefix(n, "kernel") ||
			strings.HasPrefix(n, "linux-kbuild") || n == "linux" {
			return true
		}
	}
	return false
}

// oneLine 取输出最后一行非空内容，用于单行汇报。
func oneLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			return truncateText(t, 100)
		}
	}
	return ""
}

// isRoot 判断当前进程是否具备升级软件包的权限。
func isRoot() bool { return os.Geteuid() == 0 }

// filterArgs 把 fix 的过滤参数转成 plan 的参数，用于「不带 --yes」时的预演。
// 只转 --package：--yes/--dry-run/--json 对 plan 没有意义或有歧义。
func filterArgs(f pkgFilter) []string {
	if len(f) == 0 {
		return nil
	}
	return []string{"--package", strings.Join(f, ",")}
}
