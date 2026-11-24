// Package matcher 把「本机装了什么」与「官方说哪个版本修了哪个 CVE」合起来，
// 产出带证据的判定结果。
//
// 三条不可妥协的规则（docs/data-model.md §3）：
//  1. 数据源没收录某个 CVE，不等于不受影响。没有证据时结论是 UNKNOWN，
//     不是 NOT_AFFECTED。
//  2. 版本比较必须用发行版原生规则（dpkg / rpm / apk / pacman），
//     禁止字符串比较或 SemVer 近似。
//  3. 弱证据（仓库当前版本）不能用来判「受影响」：它只能说明「现在装的是
//     仓库里的最新版」，不能说明「这个版本就是首次修复版本」。
package matcher

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/version"
)

// Store 提供判定所需的情报事实。
type Store interface {
	FixesForPackages(ctx context.Context, distro domain.DistroID, release string,
		names []string) ([]database.FixRow, error)
	NotAffectedForPackages(ctx context.Context, distro domain.DistroID, release string,
		names []string) ([]database.NotAffectedRow, error)
}

// Options 控制判定的边界条件。
type Options struct {
	// Lifecycle 是该 release 的生命周期状态，来自支持矩阵。
	// legacy / eol 一律不给出「可自动修复」的结论。
	Lifecycle domain.LifecycleState
	// Now 便于测试注入固定时间。
	Now func() time.Time
}

// Engine 执行一次匹配。
type Engine struct {
	Store Store
	Opts  Options
}

func (e *Engine) now() time.Time {
	if e.Opts.Now != nil {
		return e.Opts.Now()
	}
	return time.Now().UTC()
}

// Result 是一次匹配的产物。
type Result struct {
	Findings []domain.Finding
	// Evaluated 是实际参与判定的包数，用于报告里的分母。
	Evaluated int
	// NoData 是有包但库中完全没有该包任何记录的条数：这是覆盖缺口，
	// 报告必须显式说明，不能算成「无漏洞」。
	NoData int
}

// Match 对一份资产快照执行判定。
func (e *Engine) Match(ctx context.Context, inv domain.Inventory) (*Result, error) {
	if e.Store == nil {
		return nil, apperr.New(exitcode.Error, "matcher", "未配置情报存储")
	}
	if err := inv.Validate(); err != nil {
		return nil, apperr.Wrap(exitcode.Error, "matcher", "资产快照不合格，拒绝判定", err)
	}
	if inv.DistroID.Family() == domain.FamilyUnknown {
		return nil, apperr.Newf(exitcode.Unsupported, "matcher",
			"发行版 %s 未登记，禁止判定", inv.DistroID)
	}

	// 查询名必须同时包含二进制包名与源码包名。
	//
	// Debian 的公告是按**源码包**发布的（python3.13 的公告挂在 cpython 上），
	// 只按二进制包名查会漏掉大量本就存在的修复记录，把「有数据」误判成
	// 「无数据」，进而把受影响读成安全。
	names := make([]string, 0, len(inv.Packages)*2)
	for _, p := range inv.Packages {
		names = append(names, p.Ref.Name)
		if p.SourceName != "" {
			names = append(names, p.SourceName)
		}
	}

	fixes, err := e.Store.FixesForPackages(ctx, inv.DistroID, inv.Release, names)
	if err != nil {
		return nil, err
	}
	notAffected, err := e.Store.NotAffectedForPackages(ctx, inv.DistroID, inv.Release, names)
	if err != nil {
		return nil, err
	}

	// 按「包类型 + 包名」建索引：源码包记录只能由源码包名命中，
	// 二进制包记录只能由二进制包名命中，两者不可混用。
	binaryFixes := map[string][]database.FixRow{}
	sourceFixes := map[string][]database.FixRow{}
	for _, f := range fixes {
		if f.PackageKind == domain.PackageKindSource {
			sourceFixes[f.PackageName] = append(sourceFixes[f.PackageName], f)
			continue
		}
		binaryFixes[f.PackageName] = append(binaryFixes[f.PackageName], f)
	}
	binaryNA := map[string][]database.NotAffectedRow{}
	sourceNA := map[string][]database.NotAffectedRow{}
	for _, n := range notAffected {
		if n.Kind == domain.PackageKindSource {
			sourceNA[n.Package] = append(sourceNA[n.Package], n)
			continue
		}
		binaryNA[n.Package] = append(binaryNA[n.Package], n)
	}

	res := &Result{Evaluated: len(inv.Packages)}
	for _, pkg := range inv.Packages {
		rows := append([]database.FixRow(nil), binaryFixes[pkg.Ref.Name]...)
		nas := append([]database.NotAffectedRow(nil), binaryNA[pkg.Ref.Name]...)
		if pkg.SourceName != "" {
			rows = append(rows, sourceFixes[pkg.SourceName]...)
			nas = append(nas, sourceNA[pkg.SourceName]...)
		}
		if len(rows) == 0 && len(nas) == 0 {
			res.NoData++
			continue
		}
		findings, err := e.matchPackage(inv, pkg, rows, nas)
		if err != nil {
			return nil, err
		}
		if len(findings) == 0 {
			// 有记录但全部不适用于本机架构，同样是覆盖缺口。
			res.NoData++
			continue
		}
		res.Findings = append(res.Findings, findings...)
	}

	// 输出顺序必须稳定：报告与 JSON 都是给人看和给脚本比的。
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Vuln != b.Vuln {
			return a.Vuln == domain.VulnStateVulnerable
		}
		if a.CVE != b.CVE {
			return a.CVE < b.CVE
		}
		return a.Package.Name < b.Package.Name
	})
	return res, nil
}

// matchPackage 判定单个包的每个相关 CVE。
func (e *Engine) matchPackage(inv domain.Inventory, pkg domain.InstalledPackage,
	rows []database.FixRow, nas []database.NotAffectedRow) ([]domain.Finding, error) {

	byCVE := map[domain.CVEID][]database.FixRow{}
	for _, r := range rows {
		// 架构必须匹配：本机是 amd64，公告里 x86_64 / any / all 都算命中，
		// 但 aarch64 的修复版本与本机无关。
		if !domain.ArchMatches(r.Arch, pkg.Ref.Arch) {
			continue
		}
		byCVE[r.CVEID] = append(byCVE[r.CVEID], r)
	}
	naByCVE := map[domain.CVEID][]database.NotAffectedRow{}
	for _, n := range nas {
		if !domain.ArchMatches(n.Arch, pkg.Ref.Arch) {
			continue
		}
		naByCVE[n.CVEID] = append(naByCVE[n.CVEID], n)
	}

	cves := make([]string, 0, len(byCVE)+len(naByCVE))
	seen := map[domain.CVEID]bool{}
	for c := range naByCVE {
		if !seen[c] {
			seen[c] = true
			cves = append(cves, string(c))
		}
	}
	for c := range byCVE {
		if !seen[c] {
			seen[c] = true
			cves = append(cves, string(c))
		}
	}
	sort.Strings(cves)

	out := make([]domain.Finding, 0, len(cves))
	for _, cs := range cves {
		cve := domain.CVEID(cs)
		f, err := e.decide(inv, pkg, cve, byCVE[cve], naByCVE[cve])
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

// decide 综合一个 CVE 的全部证据得出结论。
func (e *Engine) decide(inv domain.Inventory, pkg domain.InstalledPackage, cve domain.CVEID,
	rows []database.FixRow, nas []database.NotAffectedRow) (domain.Finding, error) {

	f := domain.Finding{
		CVE:           cve,
		DistroID:      inv.DistroID,
		Release:       inv.Release,
		Lifecycle:     e.Opts.Lifecycle,
		Package:       pkg.Ref,
		Installed:     pkg.Ref.Version,
		OriginChannel: originChannel(pkg),
		DetectedAt:    e.now(),
	}
	f.Runtime.Reboot = domain.RebootUnknown
	if len(rows) > 0 {
		f.Severity = rows[0].Severity
		f.Title = rows[0].Title
		f.AdvisoryID = rows[0].AdvisoryID
	}

	// 显式不受影响声明优先，但它与「有修复记录」同时出现时数据自相矛盾，
	// 此时不能挑一个有利的结论，只能如实标 UNKNOWN。
	if len(nas) > 0 && len(rows) > 0 {
		return e.finish(f, domain.VulnStateUnknown, domain.RemediationUnknown,
			domain.ReasonUnknownState,
			evidenceOf(rows[0], domain.MatchCompareError,
				"同一包同时存在「不受影响声明」与「修复记录」，证据冲突"),
		)
	}
	if len(nas) > 0 {
		na := nas[0]
		f.AdvisoryID = na.AdvisoryID
		return e.finish(f, domain.VulnStateNotAffected, domain.RemediationNotApplicable,
			domain.ReasonNotVulnerable,
			domain.Evidence{
				SourceID: na.SourceID, Signature: domain.SignatureNotApplicable,
				Integrity: domain.IntegrityVerified, AdvisoryID: na.AdvisoryID, URL: na.URL,
				MatchKind: domain.MatchNotAffected, Detail: "发布方显式声明不受影响：" + string(na.Reason),
				RetrievedAt: e.now(),
			})
	}

	return e.decideByVersion(f, pkg, rows)
}

// decideByVersion 用官方固定版本与本机版本比较得出结论。
func (e *Engine) decideByVersion(f domain.Finding, pkg domain.InstalledPackage,
	rows []database.FixRow) (domain.Finding, error) {

	var (
		lowestFixed *string
		weakFixed   *string
		target      *string
		ev          domain.Evidence
		sawWeak     bool
	)

	for _, r := range rows {
		// 没有可比较的版本：官方只说「受影响」，未给出修复包。
		if strings.TrimSpace(r.FixedVersion) == "" {
			continue
		}
		cmp, err := version.Compare(pkg.Manager, pkg.Ref.Version.String(), r.FixedVersion)
		if err != nil {
			// 版本不可比：这是「不知道」，不是「不受影响」。
			return e.finish(f, domain.VulnStateUnknown, domain.RemediationUnknown,
				domain.ReasonUnknownState,
				evidenceOf(r, domain.MatchCompareError,
					fmt.Sprintf("版本无法比较：本机 %s，官方 %s",
						pkg.Ref.Version.String(), r.FixedVersion)))
		}
		if !r.Official {
			sawWeak = true
			if cmp >= 0 && (weakFixed == nil || lowerThan(pkg.Manager, r.FixedVersion, *weakFixed)) {
				v := r.FixedVersion
				weakFixed = &v
			}
			continue
		}
		if cmp >= 0 {
			// 本机版本已达到或超过该修复版本：此 CVE 已修复。
			v := r.FixedVersion
			if lowestFixed == nil || lowerThan(pkg.Manager, v, *lowestFixed) {
				lowestFixed = &v
			}
			continue
		}
		// 本机低于官方修复版本：找最小的那个作为升级目标。
		if target == nil || lowerThan(pkg.Manager, r.FixedVersion, *target) {
			v := r.FixedVersion
			target = &v
			ev = evidenceOf(r, domain.MatchFixedVersion,
				fmt.Sprintf("本机 %s 低于官方修复版本 %s",
					pkg.Ref.Version.String(), r.FixedVersion))
		}
	}

	if lowestFixed != nil {
		f.FixedVersion = versionPtr(pkg.Manager, *lowestFixed)
		ev := evidenceOf(rows[0], domain.MatchFixedVersion,
			fmt.Sprintf("本机 %s 已达到或超过官方修复版本 %s",
				pkg.Ref.Version.String(), *lowestFixed))
		return e.finish(f, domain.VulnStateFixed, domain.RemediationNotApplicable,
			domain.ReasonNotVulnerable, ev)
	}
	// 弱证据只能证明「已修复」，不能证明「受影响」。
	if weakFixed != nil {
		f.FixedVersion = versionPtr(pkg.Manager, *weakFixed)
		return e.finish(f, domain.VulnStateFixed, domain.RemediationNotApplicable,
			domain.ReasonNotVulnerable,
			evidenceOf(rows[0], domain.MatchFixedVersion,
				fmt.Sprintf("本机 %s 不低于仓库当前版本 %s（弱证据，仅用于判已修复）",
					pkg.Ref.Version.String(), *weakFixed)))
	}
	if target != nil {
		f.FixedVersion = versionPtr(pkg.Manager, *target)
		return e.finish(f, domain.VulnStateVulnerable, domain.RemediationFixAvailable, "", ev)
	}
	if sawWeak {
		// 只有弱证据且本机版本低于仓库当前版本：既不能判受影响，也不能判已修复。
		return e.finish(f, domain.VulnStateUnknown, domain.RemediationUnknown,
			domain.ReasonUnknownState,
			evidenceOf(rows[0], domain.MatchCompareError,
				"只有仓库当前版本可作参考，不足以判定是否受影响"))
	}
	// 有官方公告但没有可比较的修复版本：受影响且暂无修复包。
	return e.finish(f, domain.VulnStateVulnerable, domain.RemediationNoFix,
		domain.ReasonNoFix,
		evidenceOf(rows[0], domain.MatchFixedVersion, "官方公告未给出可比较的修复版本"))
}

// finish 统一补齐修复可行性、重启状态与校验，避免各分支各写一套。
func (e *Engine) finish(f domain.Finding, vuln domain.VulnState,
	rem domain.RemediationState, reason domain.ReasonCode,
	ev domain.Evidence) (domain.Finding, error) {

	f.Vuln = vuln
	f.Remediation = rem
	if ev.SourceID != "" {
		f.Evidence = append(f.Evidence, ev)
	}
	if reason != "" {
		f.Reasons = append(f.Reasons, reason)
	}

	// 生命周期闸门：legacy / eol 一律关闭自动修复，但不改变检测结论。
	if rem == domain.RemediationFixAvailable {
		switch f.Lifecycle {
		case domain.LifecycleEOL:
			f.Remediation = domain.RemediationBlocked
			f.Reasons = append(f.Reasons, domain.ReasonLifecycleEOL)
		case domain.LifecycleLegacy:
			f.Remediation = domain.RemediationBlocked
			f.Reasons = append(f.Reasons, domain.ReasonLifecycleLegacy)
		case domain.LifecycleUnknown:
			// 生命周期未知时不允许自动修复：不知道是否还在支持范围内的系统，
			// 升级包可能直接失去厂商支持。
			f.Remediation = domain.RemediationManualRequired
			f.Reasons = append(f.Reasons, domain.ReasonUnsupported)
		}
	}

	if err := f.Validate(); err != nil {
		return f, apperr.Wrap(exitcode.Error, "matcher",
			fmt.Sprintf("判定结果不自洽（%s / %s）", f.CVE, f.Package.Name), err)
	}
	return f, nil
}

// evidenceOf 把修复记录转成可读证据。
func evidenceOf(r database.FixRow, kind domain.MatchKind, detail string) domain.Evidence {
	return domain.Evidence{
		SourceID:    r.SourceID,
		Signature:   r.Signature,
		Integrity:   r.Integrity,
		AdvisoryID:  r.AdvisoryID,
		URL:         r.URL,
		MatchKind:   kind,
		Detail:      detail,
		RetrievedAt: r.FetchedAt,
	}
}

// lowerThan 判断 a 是否严格低于 b。
//
// 比较失败时返回 false：拿不准的时候保留已有候选，不因为解析异常
// 就把升级目标换成一个没验证过的版本。
func lowerThan(manager domain.PackageManager, a, b string) bool {
	r, err := version.Compare(manager, a, b)
	if err != nil {
		return false
	}
	return r < 0
}

// versionPtr 解析版本串；解析失败返回 nil 而不是猜一个值。
func versionPtr(manager domain.PackageManager, raw string) *domain.Version {
	v, err := version.Parse(manager, raw)
	if err != nil {
		return nil
	}
	return &v
}

// originChannel 返回本机包的来源渠道，不可证明时为 ChannelUnknown。
func originChannel(pkg domain.InstalledPackage) string {
	if pkg.OriginChannel != "" {
		return pkg.OriginChannel
	}
	// 来源渠道必须可证明；拿不到时如实记 unknown，不猜成主仓库，
	// 否则「安全仓库还没同步」这种情况会被误判成「没有修复包」。
	return domain.ChannelUnknown
}
