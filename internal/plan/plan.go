// Package plan 生成「受控修复计划」，并执行其中的升级步骤。
//
// 设计约束（docs/phase3.0-design.md §6）：
//   - 计划是纯函数产物：同样的启发事实与同一次扫描必须得到同样的计划，
//     否则用户无法预演、也无法核对「我批准的就是它将要做的」。
//   - 一个包只出现一次：多条 CVE 指向同一个包时合并成一步升级，
//     目标版本取其中最高的官方修复版本，避免来回升级。
//   - 安全闸门优先于可行性：生命周期 EOL / Legacy / 未知、渠道不可证明、
//     包管理器不受支持，任何一条命中都不进入可执行步骤。
//   - 执行后必须复检：报告「修好了」只能靠重新采集 + 重新判定，
//     不能靠升级命令的返回码。
package plan

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/support"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/version"
)

// Candidate 是一条判定结果中与修复有关的部分。
//
// 单独定义而不直接复用 database.FindingRow：计划只关心
// 「哪个包、从什么版本到什么版本、为哪些 CVE」，把存储层结构挡在外面。
type Candidate struct {
	Package     string
	Arch        string
	Installed   string
	Fixed       string
	CVE         domain.CVEID
	Severity    domain.Severity
	Vuln        domain.VulnState
	Remediation domain.RemediationState
	Lifecycle   domain.LifecycleState
	Channel     string
}

// Step 是一次包升级。
type Step struct {
	Package string
	Arch    string
	From    string
	To      string
	Manager domain.PackageManager
	CVEs    []domain.CVEID
	// Severity 是该步骤覆盖的最高严重度，用于排序与提示。
	Severity domain.Severity
	// Channel 是本机该包可证明的来源渠道；不可证明时为空。
	Channel string
}

// Skipped 是一类未进入计划的判定，按原因聚合计数。
type Skipped struct {
	Reason domain.ReasonCode
	Count  int
}

// Plan 是一次修复计划。
type Plan struct {
	Distro    domain.DistroID
	Release   string
	Manager   domain.PackageManager
	Lifecycle domain.LifecycleState
	CreatedAt time.Time

	Steps []Step
	// Blocked 表示计划整体不可执行，Reason 说明原因。
	// 被阻止不等于不显示：用户需要看到「本来会做什么、为什么不能做」。
	Blocked bool
	Reason  domain.ReasonCode
	// BlockedDetail 是给人看的一句话说明。
	BlockedDetail string

	Skipped []Skipped
	// Findings 是参与本次计划的判定条数。
	Findings int
}

// Executable 表示计划可以执行。
func (p *Plan) Executable() bool { return !p.Blocked && len(p.Steps) > 0 }

// Build 由判定结果生成计划。
//
// manager 来自本机资产采集，而不是按发行版猜：Debian 系可能装了 apt，
// 也可能只有 dpkg；猜错会让 fix 调起不存在的命令。
func Build(distro domain.DistroID, release string, manager domain.PackageManager,
	cands []Candidate, entry support.Entry, now time.Time) *Plan {

	p := &Plan{
		Distro:    distro,
		Release:   release,
		Manager:   manager,
		Lifecycle: support.Lifecycle(distro, release, now),
		CreatedAt: now,
		Findings:  len(cands),
	}

	// 整体闸门：任何一条命中都不执行，但步骤照样列出。
	switch {
	case !entry.AutoFix:
		p.Blocked = true
		p.Reason = domain.ReasonPlanBlocked
		p.BlockedDetail = "该 release 未开放自动修复（" + entry.Note + "）"
	case manager == domain.ManagerNone || !manager.Valid():
		p.Blocked = true
		p.Reason = domain.ReasonManagerUnsupported
		p.BlockedDetail = "无法确定可用的包管理器"
	case manager == domain.ManagerPacman:
		// 滚动发行版没有「固定版本」概念：升级到仓库当前版本，
		// 与官方修复版本不一定对应，因此不开放自动修复。
		p.Blocked = true
		p.Reason = domain.ReasonManagerUnsupported
		p.BlockedDetail = "滚动发行版不支持按固定版本修复"
	}

	type agg struct {
		to       string
		cves     map[domain.CVEID]bool
		severity domain.Severity
		channel  string
		from     string
	}
	byPkg := map[string]*agg{}
	skips := map[domain.ReasonCode]int{}

	for _, c := range cands {
		if c.Vuln != domain.VulnStateVulnerable {
			skips[domain.ReasonNotVulnerable]++
			continue
		}
		switch c.Remediation {
		case domain.RemediationFixAvailable:
		case domain.RemediationNoFix:
			skips[domain.ReasonNoFix]++
			continue
		case domain.RemediationPendingMirror:
			skips[domain.ReasonPendingMirror]++
			continue
		case domain.RemediationBlocked:
			// 生命周期闸门在匹配阶段已判过，这里按具体原因归类。
			if c.Lifecycle == domain.LifecycleEOL {
				skips[domain.ReasonLifecycleEOL]++
			} else {
				skips[domain.ReasonLifecycleLegacy]++
			}
			continue
		case domain.RemediationManualRequired:
			skips[domain.ReasonManualRequired]++
			continue
		default:
			skips[domain.ReasonUnknownState]++
			continue
		}
		if strings.TrimSpace(c.Fixed) == "" {
			// 有修复状态却没有目标版本：数据不自洽，不能凭猜升级。
			skips[domain.ReasonMissingFixedVersion]++
			continue
		}

		key := c.Package + "\x00" + c.Arch
		a := byPkg[key]
		if a == nil {
			a = &agg{cves: map[domain.CVEID]bool{}, from: c.Installed, channel: c.Channel}
			byPkg[key] = a
		}
		if a.to == "" || higher(manager, c.Fixed, a.to) {
			a.to = c.Fixed
		}
		a.cves[c.CVE] = true
		if severityRank(c.Severity) > severityRank(a.severity) {
			a.severity = c.Severity
		}
	}

	keys := make([]string, 0, len(byPkg))
	for k := range byPkg {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		a := byPkg[k]
		name, arch, _ := strings.Cut(k, "\x00")
		cves := make([]domain.CVEID, 0, len(a.cves))
		for c := range a.cves {
			cves = append(cves, c)
		}
		sort.Slice(cves, func(i, j int) bool { return cves[i] < cves[j] })
		p.Steps = append(p.Steps, Step{
			Package: name, Arch: arch, From: a.from, To: a.to,
			Manager: manager, CVEs: cves, Severity: a.severity, Channel: a.channel,
		})
	}
	// 严重度高的排前面：部分失败时用户先看到最要紧的。
	sort.SliceStable(p.Steps, func(i, j int) bool {
		ri, rj := severityRank(p.Steps[i].Severity), severityRank(p.Steps[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return p.Steps[i].Package < p.Steps[j].Package
	})

	for reason, n := range skips {
		p.Skipped = append(p.Skipped, Skipped{Reason: reason, Count: n})
	}
	sort.Slice(p.Skipped, func(i, j int) bool {
		if p.Skipped[i].Count != p.Skipped[j].Count {
			return p.Skipped[i].Count > p.Skipped[j].Count
		}
		return p.Skipped[i].Reason < p.Skipped[j].Reason
	})
	return p
}

// TotalCVEs 返回计划覆盖的 CVE 去重数量。
func (p *Plan) TotalCVEs() int {
	seen := map[domain.CVEID]bool{}
	for _, s := range p.Steps {
		for _, c := range s.CVEs {
			seen[c] = true
		}
	}
	return len(seen)
}

// higher 判断 a 是否高于 b（发行版原生比较规则）。
// 比较失败时返回 false：拿不准就保留已有目标，不换成没验证过的版本。
func higher(manager domain.PackageManager, a, b string) bool {
	cmp, err := version.Compare(manager, a, b)
	if err != nil {
		return false
	}
	return cmp > 0
}

// severityRank 给出严重度的排序权重。
func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityNone:
		return 1
	default:
		return 0
	}
}

// Command 返回执行该步骤所需的命令与参数。
//
// 只生成「升级到仓库里的版本」，不拼 shell：参数直接交给 exec，
// 包名来自本机 dpkg/rpm 查询结果，但仍按不可信输入对待。
func (s Step) Command() (string, []string, error) {
	switch s.Manager {
	case domain.ManagerDPKG:
		// --only-upgrade 保证不会顺手装上未安装的包；
		// 两个 -o 选项避免配置文件冲突时停住等输入。
		return "apt-get", []string{
			"install", "-y", "--only-upgrade",
			"-o", "Dpkg::Options::=--force-confdef",
			"-o", "Dpkg::Options::=--force-confold",
			s.Package,
		}, nil
	case domain.ManagerRPM:
		return "dnf", []string{"-y", "--best", "upgrade", s.Package}, nil
	case domain.ManagerAPK:
		return "apk", []string{"upgrade", "--no-progress", s.Package}, nil
	default:
		return "", nil, fmt.Errorf("plan: 包管理器 %q 不支持自动修复", s.Manager)
	}
}
