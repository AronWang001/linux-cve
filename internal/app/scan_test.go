package app

import (
	"testing"

	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/feed"
)

// TestScanExitCode 退出码必须让脚本能分清三种结局：
// 有洞、没洞但没数据、没洞且有数据。
//
// 第三种才是真正的「安全」；把第二种混进 0，等于让 CI 在没检查的情况下放行。
func TestScanExitCode(t *testing.T) {
	cases := []struct {
		name     string
		counts   map[domain.VulnState]int
		coverage string
		want     exitcode.Code
	}{
		{
			name:     "有受影响项且覆盖完整",
			counts:   map[domain.VulnState]int{domain.VulnStateVulnerable: 3},
			coverage: feed.CoverageCovered,
			want:     exitcode.Findings,
		},
		{
			// 有洞时覆盖不足不能让退出码退化成 9：洞是更具体、更可操作的信息
			name:     "有受影响项但覆盖不足",
			counts:   map[domain.VulnState]int{domain.VulnStateVulnerable: 1},
			coverage: feed.CoverageUnknown,
			want:     exitcode.Findings,
		},
		{
			name:     "无受影响项且覆盖完整",
			counts:   map[domain.VulnState]int{domain.VulnStateFixed: 10},
			coverage: feed.CoverageCovered,
			want:     exitcode.OK,
		},
		{
			name:     "无受影响项但覆盖未知",
			counts:   map[domain.VulnState]int{},
			coverage: feed.CoverageUnknown,
			want:     exitcode.Coverage,
		},
		{
			name:     "无受影响项但覆盖部分",
			counts:   map[domain.VulnState]int{domain.VulnStateUnknown: 7},
			coverage: feed.CoveragePartial,
			want:     exitcode.Coverage,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := scanExitCode(c.counts, c.coverage); got != c.want {
				t.Errorf("scanExitCode = %d(%s)，期望 %d(%s)",
					got.Int(), got, c.want.Int(), c.want)
			}
		})
	}
}
