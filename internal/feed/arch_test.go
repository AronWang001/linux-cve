package feed

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// archFixture 覆盖四种 status 与多包场景，字段形态取自真实数据。
const archFixture = `[
  {"name": "AVG-0001", "packages": ["openssl"], "status": "Fixed", "severity": "High",
   "type": "denial of service", "affected": "3.0.0-1", "fixed": "3.0.1-1",
   "ticket": null, "issues": ["CVE-2024-0001", "CVE-2024-0002"], "advisories": ["ASA-202401-1"]},
  {"name": "AVG-0002", "packages": ["poppler", "poppler-glib"], "status": "Fixed",
   "severity": "Unknown", "type": "unknown", "affected": "22.08.0-1", "fixed": "22.08.0-2",
   "ticket": null, "issues": ["CVE-2024-0003"], "advisories": []},
  {"name": "AVG-0003", "packages": ["couchdb"], "status": "Not affected", "severity": "Critical",
   "type": "privilege escalation", "affected": "3.2.1-1", "fixed": "3.2.2-2",
   "ticket": null, "issues": ["CVE-2024-0004"], "advisories": []},
  {"name": "AVG-0004", "packages": ["pam"], "status": "Vulnerable", "severity": "High",
   "type": "arbitrary filesystem access", "affected": "1.7.0-2", "fixed": null,
   "ticket": null, "issues": ["CVE-2024-0005"], "advisories": []},
  {"name": "AVG-0005", "packages": ["vim"], "status": "Unknown", "severity": "Unknown",
   "type": "unknown", "affected": "9.0.1224-1", "fixed": "9.0.1225-1",
   "ticket": null, "issues": ["CVE-2024-0006", "NOT-A-CVE"], "advisories": []}
]`

func archInput(t *testing.T, body string) ParseInput {
	t.Helper()
	return ParseInput{
		Source:      mustSource(t, domain.SourceArchTracker),
		ArtifactSHA: HashBytes([]byte(body)),
		Body:        []byte(body),
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
}

func TestArchParseStatusMapping(t *testing.T) {
	in := archInput(t, archFixture)
	res, err := ArchParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 公告：AVG-0001 两条 CVE、AVG-0002 一条、AVG-0003 一条、
	// AVG-0004 一条、AVG-0005 一条（NOT-A-CVE 跳过），共 6 条。
	if got, want := len(res.Advisories), 6; got != want {
		t.Fatalf("公告数应为 %d，实际 %d: %v", want, got, advisoryIDs(res.Advisories))
	}
	if res.Skipped != 1 {
		t.Errorf("应跳过 1 条非 CVE 编号，实际 %d", res.Skipped)
	}

	// 修复记录只来自 Fixed：AVG-0001 两条 CVE × 1 包 = 2，
	// AVG-0002 一条 CVE × 2 包 = 2，共 4。
	// Not affected / Vulnerable / Unknown 一律不产出修复记录。
	if got, want := len(res.Fixes), 4; got != want {
		t.Fatalf("修复记录数应为 %d，实际 %d", want, got)
	}
	for _, f := range res.Fixes {
		if f.Release != ArchRelease || f.Channel != ArchChannel {
			t.Errorf("修复记录坐标错误: release=%q channel=%q", f.Release, f.Channel)
		}
		if !f.IsOfficial() {
			t.Error("追踪器的 fixed 字段是发布方声明，应标记为 official")
		}
		if f.FixedVersion == "" {
			t.Error("修复记录缺少版本")
		}
	}

	// Not affected 必须产出不受影响声明，且绝不能带修复版本。
	if len(res.NotAffected) != 1 {
		t.Fatalf("应产出 1 条不受影响声明，实际 %d", len(res.NotAffected))
	}
	na := res.NotAffected[0]
	if na.Ref.Name != "couchdb" || na.CVEID != "CVE-2024-0004" {
		t.Errorf("不受影响声明身份错误: %+v", na)
	}
	if na.Reason != domain.NotAffectedDeclared {
		t.Errorf("原因应为官方声明，实际 %q", na.Reason)
	}
	for _, f := range res.Fixes {
		if f.Ref.Name == "couchdb" {
			t.Error("Not affected 的条目即使带 fixed 版本也不得产出修复记录")
		}
		if f.Ref.Name == "vim" {
			t.Error("Unknown 的条目不得产出修复记录")
		}
	}

	// 多包 AVG 必须按包展开。
	var poppler int
	for _, f := range res.Fixes {
		if f.Ref.Name == "poppler" || f.Ref.Name == "poppler-glib" {
			poppler++
		}
	}
	if poppler != 2 {
		t.Errorf("多包 AVG 应按包展开为 2 条修复记录，实际 %d", poppler)
	}
}

func TestArchVendorStatusPreserved(t *testing.T) {
	in := archInput(t, archFixture)
	res, err := ArchParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	want := map[string]string{
		"AVG-0001/CVE-2024-0001": "Fixed",
		"AVG-0003/CVE-2024-0004": "Not affected",
		"AVG-0004/CVE-2024-0005": "Vulnerable",
		"AVG-0005/CVE-2024-0006": "Unknown",
	}
	for _, a := range res.Advisories {
		if w, ok := want[a.AdvisoryID]; ok && a.VendorStatus != w {
			t.Errorf("%s 的 vendor_status 应为 %q，实际 %q", a.AdvisoryID, w, a.VendorStatus)
		}
		if a.URL == "" || !strings.Contains(a.URL, "security.archlinux.org/") {
			t.Errorf("%s 的证据链接缺失: %q", a.AdvisoryID, a.URL)
		}
		if a.SeveritySource != "arch-avg" {
			t.Errorf("%s 的严重程度来源应为 arch-avg，实际 %q", a.AdvisoryID, a.SeveritySource)
		}
	}
}

func TestArchSeverityAndTitle(t *testing.T) {
	cases := map[string]domain.Severity{
		"Critical": domain.SeverityCritical,
		"High":     domain.SeverityHigh,
		"Medium":   domain.SeverityMedium,
		"Low":      domain.SeverityLow,
		"Unknown":  domain.SeverityUnknown,
		"":         domain.SeverityUnknown,
	}
	for in, want := range cases {
		if got := archSeverity(in); got != want {
			t.Errorf("archSeverity(%q) = %q，期望 %q", in, got, want)
		}
	}
	if archTitle("unknown") != "" {
		t.Error("unknown 类型不应作为标题")
	}
	if archTitle("denial of service") != "denial of service" {
		t.Error("漏洞类型应原样作为标题")
	}
}

func TestArchRejectsEmptyArray(t *testing.T) {
	// 空数组意味着「一条漏洞都没有」，用它覆盖已有情报会把库清空。
	in := archInput(t, "[]")
	if _, err := (ArchParser{}).Parse(context.Background(), in); err == nil {
		t.Fatal("空数组必须被拒绝")
	}
}

func TestArchSkipsEntriesWithoutPackagesOrIssues(t *testing.T) {
	// 三条异常记录，外加十条正常记录：样本太小时异常比例没有统计意义，
	// 这里刻意让正常记录占多数，才测得到「逐条跳过」而不是整批拒绝。
	var sb strings.Builder
	sb.WriteString(`[
      {"name": "AVG-1000", "packages": [], "status": "Fixed", "severity": "High",
       "type": "x", "affected": "1", "fixed": "2", "ticket": null, "issues": ["CVE-2024-1000"], "advisories": []},
      {"name": "AVG-1001", "packages": ["pkg"], "status": "Fixed", "severity": "High",
       "type": "x", "affected": "1", "fixed": "2", "ticket": null, "issues": [], "advisories": []},
      {"name": "AVG-1002", "packages": ["pkg2"], "status": "Fixed", "severity": "High",
       "type": "x", "affected": "1", "fixed": "", "ticket": null, "issues": ["CVE-2024-1002"], "advisories": []}`)
	for i := 0; i < 10; i++ {
		sb.WriteString(fmt.Sprintf(`,
      {"name": "AVG-2%03d", "packages": ["pkg%d"], "status": "Fixed", "severity": "Low",
       "type": "x", "affected": "1.0-1", "fixed": "1.1-1", "ticket": null,
       "issues": ["CVE-2024-2%03d"], "advisories": []}`, i, i, i))
	}
	sb.WriteString("\n    ]")

	res, err := ArchParser{}.Parse(context.Background(), archInput(t, sb.String()))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Fixes) != 10 {
		t.Errorf("异常条目都不应产出修复记录，正常条目应有 10 条，实际 %d", len(res.Fixes))
	}
	if res.Skipped != 3 {
		t.Errorf("应跳过 3 条，实际 %d（警告：%v）", res.Skipped, res.Warnings)
	}
}

func TestArchDeterministic(t *testing.T) {
	in := archInput(t, archFixture)
	a, err := ArchParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	b, err := ArchParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if h1, h2 := digestResult(a), digestResult(b); h1 != h2 {
		t.Fatalf("同一输入两次解析结果不一致: %s vs %s", h1[:12], h2[:12])
	}
}

// TestArchParseRealDataset 用真实 all.json 验证解析器。
//
//	curl -o /tmp/arch-all.json https://security.archlinux.org/issues/all.json
//	ARCH_TRACKER_JSON=/tmp/arch-all.json go test ./internal/feed/ -run ArchReal -v
func TestArchParseRealDataset(t *testing.T) {
	path := os.Getenv("ARCH_TRACKER_JSON")
	if path == "" {
		t.Skip("未设置 ARCH_TRACKER_JSON，跳过真实数据集验证")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取真实数据集失败: %v", err)
	}

	in := ParseInput{
		Source:      mustSource(t, domain.SourceArchTracker),
		ArtifactSHA: HashBytes(body),
		Body:        body,
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	start := time.Now()
	res, err := ArchParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析真实数据集失败: %v", err)
	}
	t.Logf("解析耗时 %v；公告 %d，修复 %d，不受影响 %d，跳过 %d，最大嵌套 %d",
		time.Since(start), len(res.Advisories), len(res.Fixes),
		len(res.NotAffected), res.Skipped, res.Guard.MaxDepth)

	if len(res.Advisories) < 2000 {
		t.Errorf("公告数量异常偏低: %d", len(res.Advisories))
	}
	if len(res.Fixes) < 2000 {
		t.Errorf("修复记录异常偏低: %d", len(res.Fixes))
	}
	if len(res.NotAffected) < 100 {
		t.Errorf("不受影响声明异常偏低: %d", len(res.NotAffected))
	}
	if res.Skipped > 50 {
		t.Errorf("跳过记录过多: %d，疑似格式漂移", res.Skipped)
	}

	res2, err := ArchParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if h1, h2 := digestResult(res), digestResult(res2); h1 != h2 {
		t.Fatalf("真实数据两次解析结果不一致: %s vs %s", h1[:12], h2[:12])
	}
}
