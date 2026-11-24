package feed

import (
	"testing"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// TestEverySourceDeclaresDistros 保证每个源都声明了自己覆盖的发行版。
//
// 漏填的后果不是报错而是静默失效：覆盖判定按 Distros 过滤，
// 没有发行版的源永远不会参与判定，那台机器上的扫描会显示「不需要任何情报」，
// 直接拿到 COVERED。这类静默错误只能在表里拦住。
func TestEverySourceDeclaresDistros(t *testing.T) {
	for _, s := range Sources() {
		if len(s.Distros) == 0 {
			t.Errorf("情报源 %s 没有声明 Distros，覆盖判定会把它当成与任何发行版无关", s.ID)
			continue
		}
		for _, d := range s.Distros {
			if d == "" {
				t.Errorf("情报源 %s 的 Distros 含空值", s.ID)
			}
		}
	}
}

// TestSourceAppliesTo 验证发行版过滤的方向性。
func TestSourceAppliesTo(t *testing.T) {
	cases := []struct {
		name   string
		source domain.SourceID
		distro domain.DistroID
		want   bool
	}{
		{"Debian 源对 Debian 生效", domain.SourceDebianTracker, domain.DistroDebian, true},
		{"Debian 源对 Ubuntu 不生效", domain.SourceDebianTracker, domain.DistroUbuntu, false},
		{"RHEL 源对 Rocky 不生效（各自有独立数据）", domain.SourceRHELCSAF, domain.DistroRocky, false},
		{"SUSE 源对 SLES 生效", domain.SourceSUSECSAF, domain.DistroSLES, true},
		{"SUSE 源对 openSUSE Leap 生效", domain.SourceSUSECSAF, domain.DistroOpenSUSE, true},
		{"SUSE 源对 RHEL 不生效", domain.SourceSUSECSAF, domain.DistroRHEL, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src, ok := SourceByID(c.source)
			if !ok {
				t.Fatalf("找不到情报源 %s", c.source)
			}
			if got := src.AppliesTo(c.distro); got != c.want {
				t.Errorf("%s.AppliesTo(%s) = %v，期望 %v", c.source, c.distro, got, c.want)
			}
		})
	}
}

// TestEmptyDistrosAppliesToNothing 确认没声明发行版的源不会「对谁都适用」。
func TestEmptyDistrosAppliesToNothing(t *testing.T) {
	s := Source{ID: "x"}
	if s.AppliesTo(domain.DistroDebian) {
		t.Error("未声明 Distros 的源不应适用于任何发行版")
	}
}

// TestParserReadyForDocumentSources 确认按文档发布的 CSAF 源被判为就绪。
//
// 这是曾经真实出错的地方：用单文件解析器表判断，RHEL/SUSE 已被接入
// 却显示「解析器未实现」，报告的覆盖章节因此把已有数据说成没有。
func TestParserReadyForDocumentSources(t *testing.T) {
	for _, id := range []domain.SourceID{domain.SourceRHELCSAF, domain.SourceSUSECSAF} {
		src, ok := SourceByID(id)
		if !ok {
			t.Fatalf("找不到情报源 %s", id)
		}
		if !src.DocumentSet {
			t.Fatalf("%s 应为按文档发布的源", id)
		}
		if ready, reason := ParserReady(src); !ready {
			t.Errorf("%s 的解析器应就绪，实际原因：%s", id, reason)
		}
		// 走 ParserFor 会得到「未实现」，这正是必须避免的入口。
		if _, reason := ParserFor(id); reason == "" {
			t.Errorf("%s 不应出现在单文件解析器表中", id)
		}
	}
}
