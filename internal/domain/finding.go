package domain

import "time"

// VulnState 是维度一：检测结论，只回答「这台机器现在有没有这个洞」。
type VulnState string

const (
	VulnStateVulnerable  VulnState = "VULNERABLE"
	VulnStateFixed       VulnState = "FIXED"
	VulnStateNotAffected VulnState = "NOT_AFFECTED"
	VulnStateUnknown     VulnState = "UNKNOWN"
	VulnStateUnsupported VulnState = "UNSUPPORTED"
)

// Valid 判断漏洞状态取值是否合法。
func (s VulnState) Valid() bool {
	switch s {
	case VulnStateVulnerable, VulnStateFixed, VulnStateNotAffected, VulnStateUnknown, VulnStateUnsupported:
		return true
	}
	return false
}

// RemediationState 是维度二：修复可行性，只回答「能不能修、怎么修」。
// 与 VulnState 正交，禁止合并为单一枚举。
type RemediationState string

const (
	RemediationFixAvailable   RemediationState = "FIX_AVAILABLE"
	RemediationNoFix          RemediationState = "NO_FIX"
	RemediationPendingMirror  RemediationState = "FIX_PENDING_MIRROR"
	RemediationManualRequired RemediationState = "MANUAL_REQUIRED"
	RemediationBlocked        RemediationState = "BLOCKED"
	RemediationNotApplicable  RemediationState = "NOT_APPLICABLE"
	RemediationUnknown        RemediationState = "UNKNOWN"
)

// Valid 判断修复状态取值是否合法。
func (s RemediationState) Valid() bool {
	switch s {
	case RemediationFixAvailable, RemediationNoFix, RemediationPendingMirror,
		RemediationManualRequired, RemediationBlocked, RemediationNotApplicable, RemediationUnknown:
		return true
	}
	return false
}

// RebootState 是维度三之一：是否需要重启主机。
// 由内核包版本比对得出，不依赖时间推断。
type RebootState string

const (
	RebootNotRequired RebootState = "NOT_REQUIRED"
	RebootRequired    RebootState = "REQUIRED"
	RebootUnknown     RebootState = "UNKNOWN"
)

// Valid 判断重启状态取值是否合法。
func (s RebootState) Valid() bool {
	switch s {
	case RebootNotRequired, RebootRequired, RebootUnknown:
		return true
	}
	return false
}

// Confidence 是运行时证据的可信度。
// LIKELY 只能来自时间推断，不得计入「已确认待重启」。
type Confidence string

const (
	ConfidenceConfirmed Confidence = "CONFIRMED"
	ConfidenceLikely    Confidence = "LIKELY"
	ConfidenceUnknown   Confidence = "UNKNOWN"
)

// Valid 判断可信度取值是否合法。
func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceConfirmed, ConfidenceLikely, ConfidenceUnknown:
		return true
	}
	return false
}

// ServiceRestart 是维度三之二：某个服务可能仍在使用旧包。
type ServiceRestart struct {
	Service    string
	Confidence Confidence
	Evidence   []string // 每条为可读证据，报告原样输出
}

// RuntimeState 汇总补丁生效情况。它只影响报告与提示，不阻塞修复执行。
type RuntimeState struct {
	Reboot   RebootState
	Restarts []ServiceRestart
	Notes    []string
}

// ReasonCode 解释某条 finding 为何不能自动修复。
type ReasonCode string

const (
	ReasonNotVulnerable       ReasonCode = "not_vulnerable"
	ReasonUnknownState        ReasonCode = "unknown_state"
	ReasonUnsupported         ReasonCode = "unsupported_environment"
	ReasonLifecycleLegacy     ReasonCode = "lifecycle_legacy"
	ReasonLifecycleEOL        ReasonCode = "lifecycle_eol"
	ReasonNoFix               ReasonCode = "no_fix_available"
	ReasonPendingMirror       ReasonCode = "fix_not_in_mirror"
	ReasonManualRequired      ReasonCode = "manual_required"
	ReasonPlanBlocked         ReasonCode = "plan_blocked"
	ReasonMissingFixedVersion ReasonCode = "missing_fixed_version"
	ReasonManagerUnsupported  ReasonCode = "package_manager_unsupported"
)

// Description 返回中文说明，直接用于 CLI 与报告。
func (r ReasonCode) Description() string {
	switch r {
	case ReasonNotVulnerable:
		return "当前状态无需修复"
	case ReasonUnknownState:
		return "状态未知，禁止自动修复"
	case ReasonUnsupported:
		return "当前环境不在支持范围"
	case ReasonLifecycleLegacy:
		return "系统处于 Legacy 兼容范围，关闭自动修复"
	case ReasonLifecycleEOL:
		return "系统已终止支持，关闭自动修复"
	case ReasonNoFix:
		return "官方尚未发布修复包"
	case ReasonPendingMirror:
		return "官方已发布修复包，但本机软件源尚未同步"
	case ReasonManualRequired:
		return "需要人工处理"
	case ReasonPlanBlocked:
		return "修复计划未通过安全闸门"
	case ReasonMissingFixedVersion:
		return "缺少官方固定版本，无法确定升级目标"
	case ReasonManagerUnsupported:
		return "当前包管理器不支持安全的自动修复"
	default:
		return string(r)
	}
}

// Finding 是一条「本机某包受某 CVE 影响」的完整记录。
//
// 三个状态维度独立存放：
//
//	Vuln        检测结论
//	Remediation 修复可行性
//	Runtime     补丁生效情况
type Finding struct {
	CVE          CVEID
	Severity     Severity
	Title        string
	DistroID     DistroID
	Release      string
	Lifecycle    LifecycleState
	Channel      string     // 本机该包的来源渠道
	Package      PackageRef // 本机安装的二进制包
	Installed    Version
	FixedVersion *Version // 官方固定版本，未知为 nil
	AdvisoryID   string
	Vuln         VulnState
	Remediation  RemediationState
	Runtime      RuntimeState
	Evidence     []Evidence
	Reasons      []ReasonCode
	DetectedAt   time.Time
}

// Validate 校验 finding 的自洽性。
// 这里实现的是 docs/data-model.md §3 的跨维度不变量，防止状态互相污染。
func (f Finding) Validate() error {
	if !f.CVE.Valid() {
		return domainErr("finding 的 CVE 非法: %q", f.CVE)
	}
	if f.Package.Kind != PackageKindBinary {
		return domainErr("finding 的包必须是二进制包，实际为 %q", f.Package.Kind)
	}
	if f.Package.Name == "" || f.Package.Arch == "" {
		return domainErr("finding 缺少包名或架构")
	}
	if !f.Vuln.Valid() {
		return domainErr("finding 的漏洞状态非法: %q", f.Vuln)
	}
	if !f.Remediation.Valid() {
		return domainErr("finding 的修复状态非法: %q", f.Remediation)
	}
	if !f.Runtime.Reboot.Valid() {
		return domainErr("finding 的重启状态非法: %q", f.Runtime.Reboot)
	}
	for _, r := range f.Runtime.Restarts {
		if !r.Confidence.Valid() {
			return domainErr("服务 %q 的可信度非法: %q", r.Service, r.Confidence)
		}
	}

	switch f.Vuln {
	case VulnStateFixed, VulnStateNotAffected, VulnStateUnsupported:
		// 不需要修复的状态，修复维度只能是 NOT_APPLICABLE
		if f.Remediation != RemediationNotApplicable {
			return domainErr("%s 状态的修复维度必须为 NOT_APPLICABLE，实际为 %q", f.Vuln, f.Remediation)
		}
	case VulnStateUnknown:
		// 未知状态不允许声称有修复方案
		if f.Remediation == RemediationFixAvailable {
			return domainErr("UNKNOWN 状态不得标记 FIX_AVAILABLE")
		}
	case VulnStateVulnerable:
		if f.Remediation == RemediationNotApplicable {
			return domainErr("VULNERABLE 状态的修复维度不得为 NOT_APPLICABLE")
		}
	}

	if f.Remediation == RemediationFixAvailable && (f.FixedVersion == nil || f.FixedVersion.IsZero()) {
		return domainErr("FIX_AVAILABLE 必须携带固定版本")
	}

	// 证据要求：确认类结论必须有来源；未知类结论必须给出原因码
	switch f.Vuln {
	case VulnStateVulnerable, VulnStateFixed, VulnStateNotAffected:
		if len(f.Evidence) == 0 {
			return domainErr("%s 状态的 finding 必须携带证据", f.Vuln)
		}
	}
	if f.Vuln == VulnStateUnknown && len(f.Reasons) == 0 {
		return domainErr("UNKNOWN 状态必须给出原因码")
	}
	return nil
}

// AutoFixEligible 判断该 finding 是否满足自动修复的领域条件。
//
// 只判断领域层条件；配置开关（allow_auto_fix）、包管理器能力、变更集闸门
// 由 planner 在执行链上追加判断，不得在此处放松。
func (f Finding) AutoFixEligible() (bool, []ReasonCode) {
	reasons := make([]ReasonCode, 0, 4)

	switch f.Vuln {
	case VulnStateVulnerable:
		// 继续评估
	case VulnStateUnknown:
		return false, append(reasons, ReasonUnknownState)
	case VulnStateUnsupported:
		return false, append(reasons, ReasonUnsupported)
	default:
		return false, append(reasons, ReasonNotVulnerable)
	}

	switch f.Lifecycle {
	case LifecycleActive:
		// 允许
	case LifecycleLegacy:
		reasons = append(reasons, ReasonLifecycleLegacy)
	case LifecycleEOL:
		reasons = append(reasons, ReasonLifecycleEOL)
	default:
		reasons = append(reasons, ReasonUnsupported)
	}

	switch f.Remediation {
	case RemediationFixAvailable:
		if f.FixedVersion == nil || f.FixedVersion.IsZero() {
			reasons = append(reasons, ReasonMissingFixedVersion)
		}
	case RemediationNoFix:
		reasons = append(reasons, ReasonNoFix)
	case RemediationPendingMirror:
		reasons = append(reasons, ReasonPendingMirror)
	case RemediationManualRequired:
		reasons = append(reasons, ReasonManualRequired)
	case RemediationBlocked:
		reasons = append(reasons, ReasonPlanBlocked)
	default:
		reasons = append(reasons, ReasonUnknownState)
	}

	// 去重，保持稳定顺序
	reasons = dedupeReasons(reasons)
	return len(reasons) == 0, reasons
}

// dedupeReasons 去除重复原因码，保留首次出现的顺序。
func dedupeReasons(in []ReasonCode) []ReasonCode {
	if len(in) < 2 {
		return in
	}
	seen := make(map[ReasonCode]struct{}, len(in))
	out := in[:0]
	for _, r := range in {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}
