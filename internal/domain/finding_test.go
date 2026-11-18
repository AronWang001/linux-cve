package domain

import (
	"testing"
)

// fixedV 构造固定版本指针，便于构造测试数据。
func fixedV(s string) *Version { return &Version{Raw: s} }

// baseFinding 是一条「Debian 12 + 有修复包 + 活跃支持期」的合法 finding。
func baseFinding() Finding {
	return Finding{
		CVE:       CVEID("CVE-2026-98432"),
		Severity:  SeverityHigh,
		Title:     "内核权限提升",
		DistroID:  DistroDebian,
		Release:   "12",
		Lifecycle: LifecycleActive,
		Channel:   "bookworm-security",
		Package: PackageRef{
			Kind:    PackageKindBinary,
			Name:    "linux-image-6.1.0-31-amd64",
			Arch:    "amd64",
			Version: Version{Raw: "6.1.140-1"},
		},
		Installed:    Version{Raw: "6.1.140-1"},
		FixedVersion: fixedV("6.1.145-1"),
		AdvisoryID:   "DSA-5810-1",
		Vuln:         VulnStateVulnerable,
		Remediation:  RemediationFixAvailable,
		Runtime:      RuntimeState{Reboot: RebootNotRequired},
		Evidence: []Evidence{{
			SourceID:        SourceDebianTracker,
			ValidationLevel: ValidationVerified,
			AdvisoryID:      "DSA-5810-1",
			MatchKind:       MatchFixedVersion,
			Detail:          "6.1.140-1 < 6.1.145-1",
		}},
	}
}

func TestFindingValidateAcceptsBase(t *testing.T) {
	if err := baseFinding().Validate(); err != nil {
		t.Fatalf("基准 finding 应合法: %v", err)
	}
}

func TestFindingValidateRejectsInvalid(t *testing.T) {
	cases := map[string]func(f *Finding){
		"非法CVE":   func(f *Finding) { f.CVE = "CVE-26-1" },
		"包类型非二进制": func(f *Finding) { f.Package.Kind = PackageKindSource },
		"缺包名":     func(f *Finding) { f.Package.Name = "" },
		"非法漏洞状态":  func(f *Finding) { f.Vuln = "MAYBE" },
		"非法修复状态":  func(f *Finding) { f.Remediation = "SOON" },
		"非法重启状态":  func(f *Finding) { f.Runtime.Reboot = "LATER" },
		"服务可信度非法": func(f *Finding) {
			f.Runtime.Restarts = []ServiceRestart{{Service: "nginx", Confidence: "PROBABLY"}}
		},
	}
	for name, mutate := range cases {
		f := baseFinding()
		mutate(&f)
		if err := f.Validate(); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
}

// TestFindingDimensionInvariants 固化三个状态维度之间的不变量。
func TestFindingDimensionInvariants(t *testing.T) {
	// 已修复的 finding 不得声称还有可用修复包
	f := baseFinding()
	f.Vuln = VulnStateFixed
	f.Remediation = RemediationNotApplicable
	if err := f.Validate(); err != nil {
		t.Errorf("FIXED + NOT_APPLICABLE 应合法: %v", err)
	}
	f.Remediation = RemediationFixAvailable
	if err := f.Validate(); err == nil {
		t.Error("FIXED 状态下修复维度必须是 NOT_APPLICABLE")
	}

	// UNKNOWN 不得声称 FIX_AVAILABLE
	f = baseFinding()
	f.Vuln = VulnStateUnknown
	f.Remediation = RemediationFixAvailable
	f.Reasons = []ReasonCode{ReasonUnknownState}
	if err := f.Validate(); err == nil {
		t.Error("UNKNOWN 状态不得标记 FIX_AVAILABLE")
	}

	// UNKNOWN 必须给出原因码
	f.Remediation = RemediationUnknown
	f.Reasons = nil
	if err := f.Validate(); err == nil {
		t.Error("UNKNOWN 状态必须给出原因码")
	}

	// FIX_AVAILABLE 必须携带固定版本
	f = baseFinding()
	f.FixedVersion = nil
	if err := f.Validate(); err == nil {
		t.Error("FIX_AVAILABLE 缺少固定版本应被拒绝")
	}

	// 确认类结论必须有证据
	f = baseFinding()
	f.Evidence = nil
	if err := f.Validate(); err == nil {
		t.Error("VULNERABLE 缺少证据应被拒绝")
	}
}

func TestAutoFixEligible(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(f *Finding)
		want    bool
		reasons []ReasonCode
	}{
		{
			name:   "可修复",
			mutate: func(f *Finding) {},
			want:   true,
		},
		{
			name: "未知状态",
			mutate: func(f *Finding) {
				f.Vuln = VulnStateUnknown
				f.Remediation = RemediationUnknown
				f.FixedVersion = nil
				f.Reasons = []ReasonCode{ReasonUnknownState}
			},
			want:    false,
			reasons: []ReasonCode{ReasonUnknownState},
		},
		{
			name: "不支持环境",
			mutate: func(f *Finding) {
				f.Vuln = VulnStateUnsupported
				f.Remediation = RemediationNotApplicable
				f.Evidence = nil
			},
			want:    false,
			reasons: []ReasonCode{ReasonUnsupported},
		},
		{
			name: "已修复无需处理",
			mutate: func(f *Finding) {
				f.Vuln = VulnStateFixed
				f.Remediation = RemediationNotApplicable
			},
			want:    false,
			reasons: []ReasonCode{ReasonNotVulnerable},
		},
		{
			name: "暂无修复包",
			mutate: func(f *Finding) {
				f.Remediation = RemediationNoFix
				f.FixedVersion = nil
			},
			want:    false,
			reasons: []ReasonCode{ReasonNoFix},
		},
		{
			name: "仓库未同步",
			mutate: func(f *Finding) {
				f.Remediation = RemediationPendingMirror
			},
			want:    false,
			reasons: []ReasonCode{ReasonPendingMirror},
		},
		{
			name: "需要人工",
			mutate: func(f *Finding) {
				f.Remediation = RemediationManualRequired
			},
			want:    false,
			reasons: []ReasonCode{ReasonManualRequired},
		},
		{
			name: "计划被闸门拦截",
			mutate: func(f *Finding) {
				f.Remediation = RemediationBlocked
			},
			want:    false,
			reasons: []ReasonCode{ReasonPlanBlocked},
		},
		{
			name: "Legacy 系统",
			mutate: func(f *Finding) {
				f.Lifecycle = LifecycleLegacy
			},
			want:    false,
			reasons: []ReasonCode{ReasonLifecycleLegacy},
		},
		{
			name: "已 EOL 系统",
			mutate: func(f *Finding) {
				f.Lifecycle = LifecycleEOL
			},
			want:    false,
			reasons: []ReasonCode{ReasonLifecycleEOL},
		},
		{
			name: "生命周期未知",
			mutate: func(f *Finding) {
				f.Lifecycle = LifecycleUnknown
			},
			want:    false,
			reasons: []ReasonCode{ReasonUnsupported},
		},
	}

	for _, c := range cases {
		f := baseFinding()
		c.mutate(&f)
		ok, reasons := f.AutoFixEligible()
		if ok != c.want {
			t.Errorf("%s: 期望 eligible=%v，实际 %v（原因 %v）", c.name, c.want, ok, reasons)
			continue
		}
		for _, want := range c.reasons {
			if !hasReason(reasons, want) {
				t.Errorf("%s: 原因应包含 %s，实际 %v", c.name, want, reasons)
			}
		}
		if ok && len(reasons) != 0 {
			t.Errorf("%s: 可修复时不应有阻止原因，实际 %v", c.name, reasons)
		}
	}
}

// TestAutoFixEligibleReasonsUnique 确认原因码去重且无重复项。
func TestAutoFixEligibleReasonsUnique(t *testing.T) {
	f := baseFinding()
	f.Lifecycle = LifecycleUnknown
	f.Remediation = RemediationUnknown
	_, reasons := f.AutoFixEligible()

	seen := map[ReasonCode]struct{}{}
	for _, r := range reasons {
		if _, dup := seen[r]; dup {
			t.Errorf("原因码重复: %s", r)
		}
		seen[r] = struct{}{}
	}
}

func TestReasonDescription(t *testing.T) {
	for _, r := range []ReasonCode{
		ReasonNotVulnerable, ReasonUnknownState, ReasonUnsupported, ReasonLifecycleLegacy,
		ReasonLifecycleEOL, ReasonNoFix, ReasonPendingMirror, ReasonManualRequired,
		ReasonPlanBlocked, ReasonMissingFixedVersion, ReasonManagerUnsupported,
	} {
		if desc := r.Description(); desc == "" || desc == string(r) {
			t.Errorf("原因码 %s 缺少中文说明", r)
		}
	}
}

func hasReason(list []ReasonCode, want ReasonCode) bool {
	for _, r := range list {
		if r == want {
			return true
		}
	}
	return false
}
