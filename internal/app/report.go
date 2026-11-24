package app

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/feed"
)

// renderReport 生成 Markdown 报告。
//
// 报告的硬要求（docs/cli.md）：结论必须自带证据与覆盖范围。
// 只写「受影响 N 条」而不写「哪些源没数据、数据多旧」，读者会把
// 覆盖缺口当成安全结论。
func renderReport(scan database.ScanRow, rows []database.FindingRow,
	advisories, fixes int, sources []database.SourceStatus) string {

	var b strings.Builder
	counts := map[domain.VulnState]int{}
	for _, r := range rows {
		counts[r.Vuln]++
	}

	fmt.Fprintf(&b, "# Linux CVE 扫描报告\n\n")
	fmt.Fprintf(&b, "- 生成时间：%s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- 扫描编号：`%s`\n", scan.ID)
	fmt.Fprintf(&b, "- 目标系统：%s %s（%s）\n", scan.DistroID, scan.Release, scan.Arch)
	fmt.Fprintf(&b, "- 扫描时间：%s\n", scan.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- 情报库：公告 %d 条、修复记录 %d 条\n\n", advisories, fixes)

	b.WriteString("## 1. 结论\n\n")
	fmt.Fprintf(&b, "| 检测结论 | 条数 |\n|---|---|\n")
	for _, st := range []domain.VulnState{
		domain.VulnStateVulnerable, domain.VulnStateFixed,
		domain.VulnStateNotAffected, domain.VulnStateUnknown,
	} {
		fmt.Fprintf(&b, "| %s | %d |\n", st, counts[st])
	}
	fmt.Fprintf(&b, "| 合计 | %d |\n\n", len(rows))

	b.WriteString("## 2. 覆盖范围\n\n")
	fmt.Fprintf(&b, "整体覆盖：**%s**\n\n", orDash(scan.Coverage))
	if scan.CoverageDetail != "" {
		fmt.Fprintf(&b, "%s\n\n", scan.CoverageDetail)
	}

	b.WriteString("| 情报源 | 信任等级 | 状态 | 最近成功 | 说明 |\n|---|---|---|---|---|\n")
	sorted := append([]database.SourceStatus(nil), sources...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, s := range sorted {
		last := "从未"
		if s.LastSuccessAt != nil {
			last = s.LastSuccessAt.UTC().Format("2006-01-02 15:04")
		}
		note := ""
		src, known := feed.SourceByID(s.ID)
		switch {
		case known && !src.AppliesTo(domain.DistroID(scan.DistroID)):
			note = "与目标发行版无关，不参与覆盖判定"
		case known:
			if _, reason := feed.ParserReady(src); reason != "" {
				note = "解析器未就绪：" + reason
			} else if s.LastError != "" {
				note = "最近错误：" + truncateText(s.LastError, 60)
			}
		case s.LastError != "":
			note = "最近错误：" + truncateText(s.LastError, 60)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n",
			s.ID, s.TrustLevel, orDash(s.Status), last, note)
	}
	b.WriteString("\n> 未接入或未同步的情报源意味着该发行版的部分漏洞**未被检查**，不能据此判断系统安全。\n\n")

	vulns := filterRows(rows, domain.VulnStateVulnerable)
	b.WriteString("## 3. 受影响明细\n\n")
	if len(vulns) == 0 {
		b.WriteString("本次扫描没有判定为受影响的包。\n\n")
	} else {
		b.WriteString("| 严重度 | CVE | 包 | 本机版本 | 修复版本 | 修复可行性 | 公告 |\n")
		b.WriteString("|---|---|---|---|---|---|---|\n")
		for _, f := range vulns {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
				f.Severity, f.CVEID, f.Package, f.Installed, orDash(f.Fixed),
				f.Remediation, orDash(f.AdvisoryID))
		}
		b.WriteString("\n")
	}

	b.WriteString("## 4. 未知项说明\n\n")
	unknown := filterRows(rows, domain.VulnStateUnknown)
	if len(unknown) == 0 {
		b.WriteString("没有状态未知的条目。\n\n")
	} else {
		fmt.Fprintf(&b, "共 %d 条，原因分布如下（这些条目**不能**视为安全）：\n\n", len(unknown))
		reasons := map[string]int{}
		for _, f := range unknown {
			reasons[truncateText(f.Evidence, 120)]++
		}
		keys := make([]string, 0, len(reasons))
		for k := range reasons {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("| 原因 | 条数 |\n|---|---|\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "| %s | %d |\n", k, reasons[k])
		}
		b.WriteString("\n")
	}

	b.WriteString("## 5. 方法与限制\n\n")
	b.WriteString("- 版本比较使用目标发行版的原生规则（dpkg / rpm / apk / pacman），不使用语义化版本近似。\n")
	b.WriteString("- 「数据源未收录」不等于「不受影响」：没有证据时结论为 UNKNOWN。\n")
	b.WriteString("- 「已修复」仅表示本机版本不低于官方声明的修复版本；是否真正生效取决于服务重启与主机重启。\n")
	b.WriteString("- 情报的完整性与签名状态分列记录，HTTPS 传输与哈希校验都不等同于厂商数字签名。\n")
	return b.String()
}

// filterRows 按漏洞状态过滤。
func filterRows(rows []database.FindingRow, st domain.VulnState) []database.FindingRow {
	out := make([]database.FindingRow, 0, len(rows))
	for _, r := range rows {
		if r.Vuln == st {
			out = append(out, r)
		}
	}
	return out
}

// writeFile 写入报告，自动创建父目录。
func writeFile(path, content string) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return apperr.Wrap(exitcode.Error, "cli.report", "创建报告目录失败", err)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		return apperr.Wrap(exitcode.Error, "cli.report", "写入报告失败", err)
	}
	return nil
}
