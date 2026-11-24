package plan

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/support"
)

func activeEntry() support.Entry {
	return support.Entry{
		Distro: domain.DistroDebian, Version: "13", Codename: "trixie",
		EOLDate: time.Date(2030, 6, 30, 0, 0, 0, 0, time.UTC),
		AutoFix: true,
	}
}

func cand(pkg, from, to string, cve string, sev domain.Severity) Candidate {
	return Candidate{
		Package: pkg, Arch: "amd64", Installed: from, Fixed: to,
		CVE: domain.CVEID(cve), Severity: sev,
		Vuln: domain.VulnStateVulnerable, Remediation: domain.RemediationFixAvailable,
		Lifecycle: domain.LifecycleActive,
	}
}

// TestBuildMergesPerPackage 同一个包的多个 CVE 必须合并成一步升级，
// 且目标版本取最高的那个：否则会出现「升级到 A 又升级到 B」的来回折腾。
func TestBuildMergesPerPackage(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	p := Build(domain.DistroDebian, "13", domain.ManagerDPKG, []Candidate{
		cand("openssl", "3.0.10-1", "3.0.11-1", "CVE-2026-0001", domain.SeverityMedium),
		cand("openssl", "3.0.10-1", "3.0.13-1", "CVE-2026-0002", domain.SeverityHigh),
		cand("bash", "5.2-1", "5.2-2", "CVE-2026-0003", domain.SeverityLow),
	}, activeEntry(), now)

	if p.Blocked {
		t.Fatalf("active + AutoFix 不应被阻止：%s", p.BlockedDetail)
	}
	if len(p.Steps) != 2 {
		t.Fatalf("应合并为 2 步，实际 %d", len(p.Steps))
	}
	// 严重度高的排前面
	if p.Steps[0].Package != "openssl" {
		t.Errorf("高危项应排在前面，实际首项 %s", p.Steps[0].Package)
	}
	if p.Steps[0].To != "3.0.13-1" {
		t.Errorf("目标版本应取最高修复版本 3.0.13-1，实际 %s", p.Steps[0].To)
	}
	if len(p.Steps[0].CVEs) != 2 {
		t.Errorf("openssl 应覆盖 2 个 CVE，实际 %d", len(p.Steps[0].CVEs))
	}
	if p.TotalCVEs() != 3 {
		t.Errorf("计划应覆盖 3 个 CVE，实际 %d", p.TotalCVEs())
	}
}

// TestBuildBlocksWhenAutoFixDisabled 未开放自动修复的 release 必须整体阻止，
// 但步骤仍要列出来：用户需要看到「本来会做什么」。
func TestBuildBlocksWhenAutoFixDisabled(t *testing.T) {
	e := activeEntry()
	e.AutoFix = false
	e.Note = "仅检测"
	p := Build(domain.DistroDebian, "11", domain.ManagerDPKG, []Candidate{
		cand("openssl", "3.0.10-1", "3.0.11-1", "CVE-2026-0001", domain.SeverityHigh),
	}, e, time.Now())

	if !p.Blocked || p.Executable() {
		t.Fatalf("未开放自动修复时必须阻止执行")
	}
	if p.Reason != domain.ReasonPlanBlocked {
		t.Errorf("阻止原因应为 plan_blocked，实际 %s", p.Reason)
	}
	if len(p.Steps) != 1 {
		t.Errorf("被阻止的计划仍应列出步骤，实际 %d", len(p.Steps))
	}
}

// TestBuildSkipsUnfixable 分类必须落到正确的跳过原因上：
// 把「无补丁」和「需人工」混成一句「不可修复」会让报告失去可操作性。
func TestBuildSkipsUnfixable(t *testing.T) {
	noFix := cand("tar", "1.34-1", "", "CVE-2026-0001", domain.SeverityLow)
	noFix.Remediation = domain.RemediationNoFix
	manual := cand("nginx", "1.24-1", "1.26-1", "CVE-2026-0002", domain.SeverityMedium)
	manual.Remediation = domain.RemediationManualRequired
	blocked := cand("glibc", "2.36-1", "2.38-1", "CVE-2026-0003", domain.SeverityHigh)
	blocked.Remediation = domain.RemediationBlocked
	blocked.Lifecycle = domain.LifecycleEOL

	p := Build(domain.DistroDebian, "13", domain.ManagerDPKG,
		[]Candidate{noFix, manual, blocked}, activeEntry(), time.Now())

	if len(p.Steps) != 0 {
		t.Fatalf("这三个都不应进入可执行步骤，实际 %d", len(p.Steps))
	}
	got := map[domain.ReasonCode]int{}
	for _, s := range p.Skipped {
		got[s.Reason] = s.Count
	}
	if got[domain.ReasonNoFix] != 1 {
		t.Errorf("无补丁应记 1 条，实际 %d", got[domain.ReasonNoFix])
	}
	if got[domain.ReasonManualRequired] != 1 {
		t.Errorf("需人工应记 1 条，实际 %d", got[domain.ReasonManualRequired])
	}
	if got[domain.ReasonLifecycleEOL] != 1 {
		t.Errorf("EOL 应记 1 条，实际 %d", got[domain.ReasonLifecycleEOL])
	}
}

// TestBuildRejectsPacman 滚动发行版没有固定版本语义，必须整体阻止。
func TestBuildRejectsPacman(t *testing.T) {
	p := Build(domain.DistroArch, "rolling", domain.ManagerPacman, []Candidate{
		cand("openssl", "3.0.10-1", "3.0.11-1", "CVE-2026-0001", domain.SeverityHigh),
	}, activeEntry(), time.Now())
	if !p.Blocked || p.Reason != domain.ReasonManagerUnsupported {
		t.Fatalf("pacman 应被阻止，实际 blocked=%v reason=%s", p.Blocked, p.Reason)
	}
}

// TestStepCommand 每条命令都必须带非交互参数：
// 修复过程中停下来等输入会让无人值守的流程挂死。
func TestStepCommand(t *testing.T) {
	cases := []struct {
		manager domain.PackageManager
		wantCmd string
		mustHas []string
	}{
		{domain.ManagerDPKG, "apt-get", []string{"-y", "--only-upgrade"}},
		{domain.ManagerRPM, "dnf", []string{"-y", "upgrade"}},
		{domain.ManagerAPK, "apk", []string{"upgrade", "--no-progress"}},
	}
	for _, c := range cases {
		s := Step{Package: "openssl", Manager: c.manager, To: "3.0.11-1"}
		name, args, err := s.Command()
		if err != nil {
			t.Fatalf("%s 生成命令失败: %v", c.manager, err)
		}
		if name != c.wantCmd {
			t.Errorf("%s 命令应为 %s，实际 %s", c.manager, c.wantCmd, name)
		}
		joined := name + " " + joinArgs(args)
		for _, m := range c.mustHas {
			if !contains(args, m) {
				t.Errorf("%s 缺少参数 %q：%s", c.manager, m, joined)
			}
		}
		if !contains(args, "openssl") {
			t.Errorf("%s 命令必须包含包名：%s", c.manager, joined)
		}
	}

	if _, _, err := (Step{Package: "x", Manager: domain.ManagerPacman}).Command(); err == nil {
		t.Error("pacman 不应生成升级命令")
	}
}

// TestVerify 复检必须按发行版原生规则比较，缺失视为失败。
func TestVerify(t *testing.T) {
	p := &Plan{Steps: []Step{
		{Package: "openssl", Arch: "amd64", To: "3.0.11-1", Manager: domain.ManagerDPKG},
		{Package: "bash", Arch: "amd64", To: "5.2-2", Manager: domain.ManagerDPKG},
		{Package: "gone", Arch: "amd64", To: "1.0-1", Manager: domain.ManagerDPKG},
	}}
	installed := map[string]string{
		"openssl\x00amd64": "3.0.11-1", // 正好达到
		"bash\x00amd64":    "5.2-1",    // 仍低
	}
	vs, ok := Verify(p, installed)
	if ok {
		t.Fatal("存在未达标项时整体不应通过")
	}
	if !vs[0].OK {
		t.Errorf("openssl 应判通过: %+v", vs[0])
	}
	if vs[1].OK {
		t.Errorf("bash 仍低于目标应判失败: %+v", vs[1])
	}
	if vs[2].OK {
		t.Errorf("复检时缺失的包不能算修好: %+v", vs[2])
	}
}

// TestExecuteStopsOnFailure 一步失败后必须停止：
// 包升级不可回滚，继续执行会把系统留在部分升级状态。
func TestExecuteStopsOnFailure(t *testing.T) {
	p := &Plan{Steps: []Step{
		{Package: "a", Manager: domain.ManagerDPKG, To: "1"},
		{Package: "b", Manager: domain.ManagerDPKG, To: "1"},
		{Package: "c", Manager: domain.ManagerDPKG, To: "1"},
	}}
	r := &fakeRunner{failAt: "b"}
	res, err := Execute(context.Background(), p, r, nil)
	if err != nil {
		t.Fatalf("执行返回错误: %v", err)
	}
	if res.Failed == nil || res.Failed.Step.Package != "b" {
		t.Fatalf("失败点应为 b，实际 %+v", res.Failed)
	}
	if len(res.Applied) != 2 {
		t.Errorf("失败后不应继续执行，实际执行了 %d 步", len(res.Applied))
	}
	if r.calls != 2 {
		t.Errorf("命令调用次数应为 2，实际 %d", r.calls)
	}
}

func TestExecuteRejectsBlockedPlan(t *testing.T) {
	p := &Plan{Blocked: true, BlockedDetail: "x"}
	if _, err := Execute(context.Background(), p, &fakeRunner{}, nil); err == nil {
		t.Fatal("被阻止的计划不得执行")
	}
}

type fakeRunner struct {
	calls  int
	failAt string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls++
	for _, a := range args {
		if a == f.failAt {
			return []byte("boom"), errors.New("模拟失败")
		}
	}
	return []byte("ok"), nil
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func joinArgs(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += " "
		}
		out += x
	}
	return out
}
