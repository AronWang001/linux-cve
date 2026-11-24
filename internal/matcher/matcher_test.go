package matcher

import (
	"context"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/database"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// fakeStore 是内存版情报存储，测试不依赖数据库。
type fakeStore struct {
	fixes []database.FixRow
	nas   []database.NotAffectedRow
	err   error
}

func (f *fakeStore) FixesForPackages(context.Context, domain.DistroID, string,
	[]string) ([]database.FixRow, error) {
	return f.fixes, f.err
}

func (f *fakeStore) NotAffectedForPackages(context.Context, domain.DistroID, string,
	[]string) ([]database.NotAffectedRow, error) {
	return f.nas, f.err
}

// debianPkg 构造一个 Debian 安装包。
func debianPkg(name, ver string) domain.InstalledPackage {
	return domain.InstalledPackage{
		Ref: domain.PackageRef{
			Kind: domain.PackageKindBinary, Name: name, Arch: "amd64",
			Version: domain.Version{Raw: ver},
		},
		Manager: domain.ManagerDPKG,
		// 领域模型要求「声明了渠道就必须给出证明」，这里给出测试用的证明。
		OriginChannel:  "bookworm-security",
		OriginEvidence: "dpkg-query -W -f=${Package} ${Version} ${Status}（测试构造）",
	}
}

func debianInv(pkgs ...domain.InstalledPackage) domain.Inventory {
	inv := domain.Inventory{
		DistroID: domain.DistroDebian, Release: "12", Codename: "bookworm", Arch: "amd64",
		Packages: pkgs, CollectedAt: time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	inv.Hash = inv.ComputeHash()
	return inv
}

func fix(cve, pkg, fixed string, official bool) database.FixRow {
	return database.FixRow{
		SourceID: domain.SourceDebianTracker, AdvisoryID: cve + "/" + pkg + "/12",
		CVEID: domain.CVEID(cve), Severity: domain.SeverityHigh, Title: "t",
		URL: "https://example.invalid/" + cve, Channel: "bookworm-security",
		PackageKind: domain.PackageKindBinary, PackageName: pkg, Arch: domain.ArchAny,
		FixedVersion: fixed, Official: official,
		Signature: domain.SignatureNotApplicable, Integrity: domain.IntegrityVerified,
		FetchedAt: time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
}

func newEngine(t *testing.T, store Store, lifecycle domain.LifecycleState) *Engine {
	t.Helper()
	return &Engine{Store: store, Opts: Options{
		Lifecycle: lifecycle,
		Now:       func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) },
	}}
}

func only(t *testing.T, res *Result) domain.Finding {
	t.Helper()
	if len(res.Findings) != 1 {
		t.Fatalf("应恰好一条 finding，实际 %d", len(res.Findings))
	}
	return res.Findings[0]
}

func TestVulnerableWhenInstalledBelowFixed(t *testing.T) {
	store := &fakeStore{fixes: []database.FixRow{fix("CVE-2026-0001", "openssl", "3.0.11-1~deb12u2", true)}}
	eng := newEngine(t, store, domain.LifecycleActive)

	res, err := eng.Match(context.Background(), debianInv(debianPkg("openssl", "3.0.11-1~deb12u1")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	f := only(t, res)
	if f.Vuln != domain.VulnStateVulnerable {
		t.Errorf("应判受影响，实际 %s", f.Vuln)
	}
	if f.Remediation != domain.RemediationFixAvailable {
		t.Errorf("应可修复，实际 %s", f.Remediation)
	}
	if f.FixedVersion == nil || f.FixedVersion.String() != "3.0.11-1~deb12u2" {
		t.Errorf("修复版本错误: %v", f.FixedVersion)
	}
	if len(f.Evidence) != 1 || f.Evidence[0].MatchKind != domain.MatchFixedVersion {
		t.Errorf("证据缺失或类型错误: %+v", f.Evidence)
	}
}

func TestFixedWhenInstalledAtOrAbove(t *testing.T) {
	store := &fakeStore{fixes: []database.FixRow{fix("CVE-2026-0001", "openssl", "3.0.11-1~deb12u2", true)}}
	eng := newEngine(t, store, domain.LifecycleActive)

	// 版本比较必须走 dpkg 规则：u2 严格高于 u1，但字符串比较会判错。
	res, err := eng.Match(context.Background(), debianInv(debianPkg("openssl", "3.0.11-1~deb12u10")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	f := only(t, res)
	if f.Vuln != domain.VulnStateFixed {
		t.Errorf("已超过修复版本应判 FIXED，实际 %s", f.Vuln)
	}
	if f.Remediation != domain.RemediationNotApplicable {
		t.Errorf("已修复时修复维度必须为 NOT_APPLICABLE，实际 %s", f.Remediation)
	}
}

func TestTildeIsLowerThan(t *testing.T) {
	// 6.12.113-1~deb12u1 < 6.12.113-1 —— dpkg 的 tilde 回移语义，
	// 用字符串比较会得到相反结论。
	store := &fakeStore{fixes: []database.FixRow{fix("CVE-2026-0002", "linux", "6.12.113-1", true)}}
	eng := newEngine(t, store, domain.LifecycleActive)
	res, err := eng.Match(context.Background(), debianInv(debianPkg("linux", "6.12.113-1~deb12u1")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if f := only(t, res); f.Vuln != domain.VulnStateVulnerable {
		t.Errorf("tilde 版本应判受影响，实际 %s", f.Vuln)
	}
}

func TestNoFixWhenNoComparableVersion(t *testing.T) {
	row := fix("CVE-2026-0003", "foo", "", true)
	row.FixedVersion = ""
	store := &fakeStore{fixes: []database.FixRow{row}}
	eng := newEngine(t, store, domain.LifecycleActive)

	res, err := eng.Match(context.Background(), debianInv(debianPkg("foo", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	f := only(t, res)
	if f.Vuln != domain.VulnStateVulnerable || f.Remediation != domain.RemediationNoFix {
		t.Errorf("无修复版本应判 受影响/无修复，实际 %s/%s", f.Vuln, f.Remediation)
	}
	if len(f.Reasons) == 0 || f.Reasons[0] != domain.ReasonNoFix {
		t.Errorf("应给出 no_fix_available 原因，实际 %v", f.Reasons)
	}
}

func TestWeakEvidenceNeverClaimsVulnerable(t *testing.T) {
	// 只有「仓库当前版本」这类弱证据时，本机版本低于它也不能判受影响：
	// 那只能说明仓库里有个更新的版本，不能说明那是首次修复版本。
	store := &fakeStore{fixes: []database.FixRow{fix("CVE-2026-0004", "bar", "2.0", false)}}
	eng := newEngine(t, store, domain.LifecycleActive)

	res, err := eng.Match(context.Background(), debianInv(debianPkg("bar", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	f := only(t, res)
	if f.Vuln == domain.VulnStateVulnerable {
		t.Error("弱证据不得判定为受影响")
	}
	if f.Vuln != domain.VulnStateUnknown {
		t.Errorf("弱证据应判 UNKNOWN，实际 %s", f.Vuln)
	}
}

func TestWeakEvidenceCanConfirmFixed(t *testing.T) {
	// 反过来，本机版本 ≥ 仓库版本时「已修复」是安全结论。
	store := &fakeStore{fixes: []database.FixRow{fix("CVE-2026-0005", "baz", "2.0", false)}}
	eng := newEngine(t, store, domain.LifecycleActive)
	res, err := eng.Match(context.Background(), debianInv(debianPkg("baz", "2.1")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if f := only(t, res); f.Vuln != domain.VulnStateFixed {
		t.Errorf("应判已修复，实际 %s", f.Vuln)
	}
}

func TestExplicitNotAffected(t *testing.T) {
	store := &fakeStore{nas: []database.NotAffectedRow{{
		SourceID: domain.SourceArchTracker, AdvisoryID: "AVG-1/CVE-2026-0006",
		CVEID: "CVE-2026-0006", Package: "qux", Arch: "any",
		Reason: domain.NotAffectedDeclared, URL: "https://example.invalid/AVG-1",
	}}}
	eng := newEngine(t, store, domain.LifecycleActive)
	res, err := eng.Match(context.Background(), debianInv(debianPkg("qux", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	f := only(t, res)
	if f.Vuln != domain.VulnStateNotAffected || f.Remediation != domain.RemediationNotApplicable {
		t.Errorf("应判不受影响，实际 %s/%s", f.Vuln, f.Remediation)
	}
}

func TestConflictingEvidenceIsUnknown(t *testing.T) {
	// 同一包同一 CVE 既有「不受影响」又有「修复记录」：数据自相矛盾，
	// 不能挑有利的结论，只能标 UNKNOWN 并说明冲突。
	store := &fakeStore{
		fixes: []database.FixRow{fix("CVE-2026-0007", "dup", "2.0", true)},
		nas: []database.NotAffectedRow{{
			SourceID: domain.SourceDebianTracker, AdvisoryID: "x", CVEID: "CVE-2026-0007",
			Package: "dup", Arch: "any", Reason: domain.NotAffectedDeclared,
		}},
	}
	eng := newEngine(t, store, domain.LifecycleActive)
	res, err := eng.Match(context.Background(), debianInv(debianPkg("dup", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	f := only(t, res)
	if f.Vuln != domain.VulnStateUnknown {
		t.Errorf("证据冲突应判 UNKNOWN，实际 %s", f.Vuln)
	}
	if len(f.Evidence) == 0 || f.Evidence[0].MatchKind != domain.MatchCompareError {
		t.Errorf("应给出冲突证据，实际 %+v", f.Evidence)
	}
}

func TestArchMismatchIgnored(t *testing.T) {
	row := fix("CVE-2026-0008", "lib", "2.0", true)
	row.Arch = "arm64" // 公告只针对 arm64，本机是 amd64
	store := &fakeStore{fixes: []database.FixRow{row}}
	eng := newEngine(t, store, domain.LifecycleActive)

	res, err := eng.Match(context.Background(), debianInv(debianPkg("lib", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("架构不匹配不应产出判定，实际 %+v", res.Findings)
	}
	if res.NoData != 1 {
		t.Errorf("应计入无数据包，实际 %d", res.NoData)
	}
}

func TestLifecycleGates(t *testing.T) {
	cases := []struct {
		lifecycle domain.LifecycleState
		want      domain.RemediationState
		reason    domain.ReasonCode
	}{
		{domain.LifecycleEOL, domain.RemediationBlocked, domain.ReasonLifecycleEOL},
		{domain.LifecycleLegacy, domain.RemediationBlocked, domain.ReasonLifecycleLegacy},
		{domain.LifecycleUnknown, domain.RemediationManualRequired, domain.ReasonUnsupported},
		{domain.LifecycleActive, domain.RemediationFixAvailable, ""},
	}
	for _, c := range cases {
		store := &fakeStore{fixes: []database.FixRow{fix("CVE-2026-0009", "pkg", "2.0", true)}}
		eng := newEngine(t, store, c.lifecycle)
		res, err := eng.Match(context.Background(), debianInv(debianPkg("pkg", "1.0")))
		if err != nil {
			t.Fatalf("%s: 判定失败: %v", c.lifecycle, err)
		}
		f := only(t, res)
		if f.Vuln != domain.VulnStateVulnerable {
			t.Errorf("%s: 检测结论不应被生命周期改变，实际 %s", c.lifecycle, f.Vuln)
		}
		if f.Remediation != c.want {
			t.Errorf("%s: 修复维度应为 %s，实际 %s", c.lifecycle, c.want, f.Remediation)
		}
		if c.reason != "" {
			found := false
			for _, r := range f.Reasons {
				if r == c.reason {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: 缺少原因 %s，实际 %v", c.lifecycle, c.reason, f.Reasons)
			}
		}
	}
}

func TestNoDataIsNotNotAffected(t *testing.T) {
	// 库中完全没有这个包的任何记录：这是覆盖缺口，绝不能算成「不受影响」。
	eng := newEngine(t, &fakeStore{}, domain.LifecycleActive)
	res, err := eng.Match(context.Background(), debianInv(debianPkg("unknown-pkg", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("无数据不应产出 finding，实际 %d", len(res.Findings))
	}
	if res.NoData != 1 || res.Evaluated != 1 {
		t.Errorf("统计错误: NoData=%d Evaluated=%d", res.NoData, res.Evaluated)
	}
}

func TestSortingBySeverity(t *testing.T) {
	crit := fix("CVE-2026-0100", "a", "2.0", true)
	crit.Severity = domain.SeverityCritical
	low := fix("CVE-2026-0101", "b", "2.0", true)
	low.Severity = domain.SeverityLow
	store := &fakeStore{fixes: []database.FixRow{low, crit}}
	eng := newEngine(t, store, domain.LifecycleActive)

	res, err := eng.Match(context.Background(), debianInv(debianPkg("a", "1.0"), debianPkg("b", "1.0")))
	if err != nil {
		t.Fatalf("判定失败: %v", err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("应有两条，实际 %d", len(res.Findings))
	}
	if res.Findings[0].Severity != domain.SeverityCritical {
		t.Error("严重程度高的应排在前")
	}
}

func TestRejectsUnregisteredDistro(t *testing.T) {
	eng := newEngine(t, &fakeStore{}, domain.LifecycleActive)
	inv := domain.Inventory{
		DistroID: "gentoo", Release: "1", Arch: "amd64",
		Packages: []domain.InstalledPackage{debianPkg("x", "1")},
	}
	if _, err := eng.Match(context.Background(), inv); err == nil {
		t.Fatal("未登记发行版必须拒绝判定")
	}
}
