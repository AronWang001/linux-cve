package feed

import (
	"context"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// debianStatusFixture 覆盖 Debian Tracker 的三种 release 状态。
//
// 关键在 open：它表示「发布方确认受影响，但没有修复版本」。
// 这种记录没有版本号可比，但绝不能丢——丢了它，这个包在扫描里就是
// 「无数据」，而事实是「有洞且无补丁」，结论正好说反。
const debianStatusFixture = `{
  "openssl": {
    "CVE-2024-1111": {
      "description": "open, no fix",
      "scope": "local",
      "releases": {
        "bookworm": {"status": "open", "urgency": "high",
                     "repositories": {}, "fixed_version": "0"}
      }
    },
    "CVE-2024-2222": {
      "description": "undetermined",
      "scope": "local",
      "releases": {
        "bookworm": {"status": "undetermined", "urgency": "low",
                     "repositories": {}, "fixed_version": "0"}
      }
    },
    "CVE-2024-3333": {
      "description": "resolved with real version",
      "scope": "local",
      "releases": {
        "bookworm": {"status": "resolved", "urgency": "medium",
                     "repositories": {"bookworm-security": "3.0.11-1~deb12u2"},
                     "fixed_version": "3.0.11-1~deb12u2"}
      }
    }
  }
}`

func TestDebianReleaseStatusMapping(t *testing.T) {
	in := ParseInput{
		Source:      mustSource(t, domain.SourceDebianTracker),
		ArtifactSHA: HashBytes([]byte(debianStatusFixture)),
		Body:        []byte(debianStatusFixture),
		FetchedAt:   time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	res, err := DebianParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// 三条 CVE 在 bookworm 上都要产出公告：状态本身就是证据，
	// 即使没有修复版本也不能让记录消失。
	if len(res.Advisories) != 3 {
		t.Fatalf("应产出 3 条公告，实际 %d", len(res.Advisories))
	}

	byCVE := map[domain.CVEID]domain.Advisory{}
	for _, a := range res.Advisories {
		byCVE[a.CVEID] = a
	}
	if got := byCVE["CVE-2024-1111"].VendorStatus; got != "open" {
		t.Errorf("vendor_status 应逐字保留为 open，实际 %q", got)
	}
	if got := byCVE["CVE-2024-2222"].VendorStatus; got != "undetermined" {
		t.Errorf("vendor_status 应逐字保留为 undetermined，实际 %q", got)
	}

	// open → 一条空版本记录；undetermined → 不产出记录（尚未判定，不能当受影响）。
	var (
		openFixes     int
		undetFixes    int
		resolvedFixes int
	)
	for _, f := range res.Fixes {
		switch f.CVEID {
		case "CVE-2024-1111":
			openFixes++
			if !f.IsAffectedNoFix() {
				t.Errorf("open 记录版本应为空，实际 %q", f.FixedVersion)
			}
			if f.Channel != "bookworm" {
				t.Errorf("open 记录没有仓库信息时渠道应回退为 codename，实际 %q", f.Channel)
			}
		case "CVE-2024-2222":
			undetFixes++
		case "CVE-2024-3333":
			resolvedFixes++
			if f.FixedVersion != "3.0.11-1~deb12u2" {
				t.Errorf("resolved 记录版本应为官方声明值，实际 %q", f.FixedVersion)
			}
			if !f.IsOfficial() {
				t.Error("官方声明的修复版本应标记为 official")
			}
		}
	}
	if openFixes != 1 {
		t.Errorf("open 应产出 1 条无修复版本记录，实际 %d", openFixes)
	}
	if undetFixes != 0 {
		t.Errorf("undetermined 不应产出修复记录（尚未判定），实际 %d", undetFixes)
	}
	if resolvedFixes != 1 {
		t.Errorf("resolved 应产出 1 条修复记录，实际 %d", resolvedFixes)
	}
}
