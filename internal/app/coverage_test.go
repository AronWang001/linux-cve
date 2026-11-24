package app

import (
	"strings"
	"testing"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/feed"
)

// TestAggregateCoverage 固定「整体覆盖」的聚合语义。
//
// 这层判断直接决定 scan 的退出码：OVERed → 0，PARTIAL/UNKNOWN → 9。
// 把边界写死，避免以后改文案时顺手把语义改掉。
func TestAggregateCoverage(t *testing.T) {
	cases := []struct {
		name  string
		cov   []feed.Coverage
		state string
	}{
		{
			name:  "没有任何相关源",
			cov:   nil,
			state: feed.CoverageUnknown,
		},
		{
			name: "全部已同步",
			cov: []feed.Coverage{
				{SourceID: "debian-tracker", State: feed.CoverageCovered},
			},
			state: feed.CoverageCovered,
		},
		{
			name: "一个源过期即整体部分覆盖",
			cov: []feed.Coverage{
				{SourceID: "debian-tracker", State: feed.CoverageCovered},
				{SourceID: "ubuntu-oval", State: feed.CoveragePartial, Reason: "情报已过期"},
			},
			state: feed.CoveragePartial,
		},
		{
			name: "有源可用但另一个从未同步仍需告警",
			cov: []feed.Coverage{
				{SourceID: "rhel-csaf", State: feed.CoverageCovered},
				{SourceID: "suse-csaf", State: feed.CoverageUnknown, Reason: "从未成功同步"},
			},
			state: feed.CoveragePartial,
		},
		{
			name: "全部不可用",
			cov: []feed.Coverage{
				{SourceID: "debian-tracker", State: feed.CoverageUnknown, Reason: "从未成功同步"},
			},
			state: feed.CoverageUnknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, detail := aggregateCoverage(c.cov)
			if got != c.state {
				t.Errorf("aggregateCoverage = %s，期望 %s（detail=%q）", got, c.state, detail)
			}
			if detail == "" {
				t.Error("覆盖说明不能为空：用户需要知道为什么覆盖不足")
			}
		})
	}
}

// TestAggregateCoverageDetailListsEveryGap 确认覆盖说明列出了每个缺口。
func TestAggregateCoverageDetailListsEveryGap(t *testing.T) {
	_, detail := aggregateCoverage([]feed.Coverage{
		{SourceID: "debian-tracker", State: feed.CoverageCovered},
		{SourceID: "ubuntu-oval", State: feed.CoverageUnknown, Reason: "从未成功同步"},
	})
	if detail == "" || !strings.Contains(detail, "ubuntu-oval") {
		t.Errorf("覆盖说明应点名缺口源，实际 %q", detail)
	}
	if strings.Contains(detail, "debian-tracker") {
		t.Errorf("已同步的源不应出现在缺口说明里，实际 %q", detail)
	}
}
