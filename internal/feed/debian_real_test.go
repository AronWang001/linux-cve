package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// TestDebianParseRealDataset 用真实全量 Tracker 数据验证解析器。
//
// 默认跳过：89MB 文件不进仓库，也不该让普通单测依赖网络。
// 需要真实验证时：
//
//	curl -o /tmp/debian.json https://security-tracker.debian.org/tracker/data/json
//	DEBIAN_TRACKER_JSON=/tmp/debian.json go test ./internal/feed/ -run Real -v
func TestDebianParseRealDataset(t *testing.T) {
	path := os.Getenv("DEBIAN_TRACKER_JSON")
	if path == "" {
		t.Skip("未设置 DEBIAN_TRACKER_JSON，跳过真实数据集验证")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取真实数据集失败: %v", err)
	}
	t.Logf("数据集大小 %.1f MB", float64(len(body))/1024/1024)

	in := ParseInput{
		Source:      mustSource(t, domain.SourceDebianTracker),
		ArtifactSHA: HashBytes(body),
		Body:        body,
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}

	start := time.Now()
	res, err := DebianParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析真实数据集失败: %v", err)
	}
	elapsed := time.Since(start)
	t.Logf("解析耗时 %v；公告 %d，修复记录 %d，release 坐标 %d，跳过 %d，最大嵌套 %d",
		elapsed, len(res.Advisories), len(res.Fixes), len(res.Releases), res.Skipped, res.Guard.MaxDepth)

	// 规模断言：与实测基线同量级（允许数据增长，不允许塌缩）。
	if len(res.Advisories) < 100000 {
		t.Errorf("公告数量异常偏低: %d（预期十万量级）", len(res.Advisories))
	}
	if len(res.Fixes) < 100000 {
		t.Errorf("修复记录数量异常偏低: %d", len(res.Fixes))
	}
	if res.Skipped > 1000 {
		t.Errorf("跳过记录过多: %d，疑似格式漂移", res.Skipped)
	}

	// 目标 CVE 必须在，且结论与官方一致。
	var target []domain.Advisory
	var targetFixes []domain.AdvisoryFix
	for _, a := range res.Advisories {
		if a.CVEID == "CVE-2026-98432" && a.AdvisoryID == "CVE-2026-98432/linux/13" {
			target = append(target, a)
		}
	}
	for _, f := range res.Fixes {
		if f.CVEID == "CVE-2026-98432" && f.AdvisoryID == "CVE-2026-98432/linux/13" {
			targetFixes = append(targetFixes, f)
		}
	}
	if len(target) != 1 {
		t.Fatalf("目标 CVE 的 linux/13 公告应恰好一条，实际 %d", len(target))
	}
	if target[0].VendorStatus != "resolved" {
		t.Errorf("目标 CVE 在 Debian 13 上状态应为 resolved，实际 %q", target[0].VendorStatus)
	}
	if len(targetFixes) != 1 {
		t.Fatalf("目标 CVE 在 Debian 13 上应恰好一条修复记录，实际 %d", len(targetFixes))
	}
	if got := targetFixes[0].FixedVersion; got != "6.12.113-1" {
		t.Errorf("目标 CVE 的 Debian 13 修复版本应为 6.12.113-1，实际 %q", got)
	}
	if !targetFixes[0].IsOfficial() {
		t.Error("该修复版本来自官方 fixed_version，应标记为 official")
	}
	if targetFixes[0].Channel != "trixie-security" {
		t.Errorf("应优先选择安全仓库渠道，实际 %q", targetFixes[0].Channel)
	}

	// 溯源完整性：每条公告都必须能指回原始记录。
	for i, a := range res.Advisories {
		if a.ArtifactSHA256 != in.ArtifactSHA {
			t.Fatalf("第 %d 条公告未携带 Artifact 哈希", i+1)
		}
		if a.RawLocator == "" || a.RawRecordHash == "" || a.ParserVersion == "" {
			t.Fatalf("第 %d 条公告溯源字段不完整: %+v", i+1, a)
		}
		if i > 1000 {
			break
		}
	}

	// 确定性：同一输入两次解析必须产出完全相同的序列。
	// 否则快照内容哈希会漂移，「内容没变」永远判不出来。
	res2, err := DebianParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if h1, h2 := digestResult(res), digestResult(res2); h1 != h2 {
		t.Fatalf("同一输入两次解析结果不一致: %s vs %s", h1[:12], h2[:12])
	}
}

// digestResult 对解析产物做顺序敏感摘要，用于验证确定性。
func digestResult(r *ParseResult) string {
	h := sha256.New()
	for _, a := range r.Advisories {
		h.Write([]byte(a.UID))
		h.Write([]byte(a.RawRecordHash))
	}
	for _, f := range r.Fixes {
		h.Write([]byte(f.AdvisoryID))
		h.Write([]byte(f.Ref.Name))
		h.Write([]byte(f.Channel))
		h.Write([]byte(f.FixedVersion))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// mustSource 取源配置，缺失直接失败。
func mustSource(t *testing.T, id domain.SourceID) Source {
	t.Helper()
	s, ok := SourceByID(id)
	if !ok {
		t.Fatalf("找不到情报源配置: %s", id)
	}
	return s
}
