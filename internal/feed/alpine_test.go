package feed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// alpineMain 是最小合法 main.json。
const alpineMain = `{
  "apkurl": "{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk",
  "archs": ["x86_64"],
  "reponame": "main",
  "urlprefix": "https://dl-cdn.alpinelinux.org/alpine",
  "distroversion": "v3.20",
  "packages": [
    {"pkg": {"name": "aom", "secfixes": {"3.1.1-r0": ["CVE-2021-30473", "CVE-2021-30474"], "3.9.1-r0": ["CVE-2024-5171"]}}},
    {"pkg": {"name": "openssl", "secfixes": {"3.3.2-r0": ["CVE-2024-9143", "GHSA-abcd-efgh-ijkl", "CVE-2024-9143"]}}},
    {"pkg": {"name": "unfixed-pkg", "secfixes": {"": ["CVE-2020-0001"]}}},
    {"pkg": {"name": "clean-pkg", "secfixes": {}}}
  ]
}`

// alpineCommunity 是最小合法 community.json。
const alpineCommunity = `{
  "archs": ["x86_64"],
  "reponame": "community",
  "distroversion": "v3.20",
  "packages": [
    {"pkg": {"name": "aom", "secfixes": {"3.1.1-r0": ["CVE-2021-30473"]}}}
  ]
}`

func alpineInput(t *testing.T, release string, files map[string]string) ParseInput {
	t.Helper()
	raw := map[string][]byte{}
	for k, v := range files {
		raw[k] = []byte(v)
	}
	return ParseInput{
		Source:    mustSource(t, domain.SourceAlpineSecDB),
		Release:   release,
		Files:     raw,
		FetchedAt: time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
}

func TestAlpineParseBasics(t *testing.T) {
	in := alpineInput(t, "3.20", map[string]string{"main": alpineMain, "community": alpineCommunity})
	res, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	// aom/main 三条、openssl/main 一条（重复的 CVE-2024-9143 只产出一条）、
	// unfixed-pkg/main 一条、aom/community 一条，共 6 条。
	if got, want := len(res.Advisories), 6; got != want {
		t.Fatalf("公告数应为 %d，实际 %d: %v", want, got, advisoryIDs(res.Advisories))
	}
	ids := advisoryIDs(res.Advisories)
	for _, want := range []string{
		"CVE-2021-30473/aom/3.20/main",
		"CVE-2021-30474/aom/3.20/main",
		"CVE-2024-5171/aom/3.20/main",
		"CVE-2021-30473/aom/3.20/community",
	} {
		if !contains(ids, want) {
			t.Errorf("缺少公告 %s，实际 %v", want, ids)
		}
	}

	// 修复记录：aom main 3 条 + aom community 1 条 + openssl 1 条 = 5。
	// unfixed-pkg 的空版本键不产出修复记录。
	if got, want := len(res.Fixes), 5; got != want {
		t.Fatalf("修复记录数应为 %d，实际 %d", want, len(res.Fixes))
	}
	for _, f := range res.Fixes {
		if f.DistroID != domain.DistroAlpine || f.Release != "3.20" {
			t.Errorf("发行版坐标错误: %s/%s", f.DistroID, f.Release)
		}
		if f.Ref.Kind != domain.PackageKindBinary {
			t.Errorf("secdb 记录的是二进制包，实际 Kind=%s", f.Ref.Kind)
		}
		if f.Ref.Arch != domain.ArchAny {
			t.Errorf("secdb 版本对所有架构生效，Arch 应为 any，实际 %s", f.Ref.Arch)
		}
		if !f.IsOfficial() {
			t.Error("secfixes 的版本是发布方声明，应标记为 official")
		}
	}

	// 非 CVE 编号（GHSA-）记入跳过，不得伪装成 CVE。
	if res.Skipped != 1 {
		t.Errorf("应跳过 1 条非 CVE 编号，实际 %d（警告：%v）", res.Skipped, res.Warnings)
	}

	var unfixed *domain.Advisory
	for i := range res.Advisories {
		if res.Advisories[i].CVEID == "CVE-2020-0001" {
			unfixed = &res.Advisories[i]
		}
	}
	if unfixed == nil {
		t.Fatal("空版本键的 CVE 应产出公告")
	}
	if unfixed.VendorStatus != "affected-unfixed" {
		t.Errorf("空版本键应记为 affected-unfixed，实际 %q", unfixed.VendorStatus)
	}

	// 覆盖坐标只有一个 release。
	if len(res.Releases) != 1 || res.Releases[0].DistroID != domain.DistroAlpine || res.Releases[0].Release != "3.20" {
		t.Errorf("release 坐标错误: %+v", res.Releases)
	}
}

func TestAlpineArtifactScopePerFile(t *testing.T) {
	in := alpineInput(t, "3.20", map[string]string{"main": alpineMain, "community": alpineCommunity})
	res, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}

	mainSHA := HashBytes([]byte(alpineMain))
	communitySHA := HashBytes([]byte(alpineCommunity))

	for _, a := range res.Advisories {
		switch {
		case strings.HasSuffix(a.AdvisoryID, "/main"):
			if a.ArtifactSHA256 != mainSHA {
				t.Errorf("%s 的 Artifact 应指向 main.json", a.AdvisoryID)
			}
		case strings.HasSuffix(a.AdvisoryID, "/community"):
			if a.ArtifactSHA256 != communitySHA {
				t.Errorf("%s 的 Artifact 应指向 community.json", a.AdvisoryID)
			}
		default:
			t.Fatalf("不可识别的公告编号: %s", a.AdvisoryID)
		}
	}
}

func TestAlpineCompositeIDKeepsCVE(t *testing.T) {
	// 实测 341 条形如 "CVE-2021-27219 GHSL-2021-045"：
	// 首段是标准 CVE，必须保留，不能因为整串非法就丢掉记录。
	body := `{
      "reponame": "main", "distroversion": "v3.20",
      "packages": [
        {"pkg": {"name": "glib", "secfixes": {"2.66.7-r0": ["CVE-2021-27219 GHSL-2021-045"]}}},
        {"pkg": {"name": "x", "secfixes": {"1-r0": ["GHSA-abcd-efgh-ijkl", "ALPINE-1"]}}}
      ]
    }`
	in := alpineInput(t, "3.20", map[string]string{"main": body})
	res, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Fixes) != 1 {
		t.Fatalf("复合编号应产出 1 条修复记录，实际 %d", len(res.Fixes))
	}
	if res.Fixes[0].CVEID != "CVE-2021-27219" {
		t.Errorf("应取首段 CVE，实际 %q", res.Fixes[0].CVEID)
	}
	if res.Skipped != 2 {
		t.Errorf("两条无 CVE 的编号应计为跳过，实际 %d", res.Skipped)
	}
}

func TestAlpineRejectsVersionMismatch(t *testing.T) {
	// 请求 3.19，服务端返回 v3.20：必须报错，不能把别的版本写进库。
	in := alpineInput(t, "3.19", map[string]string{"main": alpineMain, "community": alpineCommunity})
	if _, err := (AlpineParser{}).Parse(context.Background(), in); err == nil {
		t.Fatal("版本不符时必须失败")
	} else if !strings.Contains(err.Error(), "不符") {
		t.Errorf("错误信息应说明版本不符，实际: %v", err)
	}
}

func TestAlpineRejectsRepoMismatch(t *testing.T) {
	// 把 community 的内容放在 main 键下，reponame 自证不符。
	in := alpineInput(t, "3.20", map[string]string{"main": alpineCommunity})
	if _, err := (AlpineParser{}).Parse(context.Background(), in); err == nil {
		t.Fatal("仓库名不符时必须失败")
	}
}

func TestAlpineRequiresRelease(t *testing.T) {
	in := alpineInput(t, "", map[string]string{"main": alpineMain})
	if _, err := (AlpineParser{}).Parse(context.Background(), in); err == nil {
		t.Fatal("缺少 release 时必须失败")
	}
}

func TestAlpineDeterministic(t *testing.T) {
	in := alpineInput(t, "3.20", map[string]string{"main": alpineMain, "community": alpineCommunity})
	a, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	b, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if h1, h2 := digestResult(a), digestResult(b); h1 != h2 {
		t.Fatalf("同一输入两次解析结果不一致: %s vs %s", h1[:12], h2[:12])
	}
}

func TestAlpineReleaseKey(t *testing.T) {
	cases := map[string]string{
		"3.20.3":  "3.20",
		"3.19":    "3.19",
		" 3.22.0": "3.22",
		"":        "",
		"edge":    "edge",
		"3":       "3",
	}
	for in, want := range cases {
		if got := AlpineReleaseKey(in); got != want {
			t.Errorf("AlpineReleaseKey(%q) = %q，期望 %q", in, got, want)
		}
	}
}

// TestAlpineParseRealDataset 用真实 secdb 验证解析器。
//
// 默认跳过。需要真实验证时：
//
//	mkdir -p /tmp/alpine && for r in main community; do
//	  curl -o /tmp/alpine/$r.json https://secdb.alpinelinux.org/v3.20/$r.json; done
//	ALPINE_SECDB_DIR=/tmp/alpine ALPINE_SECDB_RELEASE=3.20 go test ./internal/feed/ -run AlpineReal -v
func TestAlpineParseRealDataset(t *testing.T) {
	dir := os.Getenv("ALPINE_SECDB_DIR")
	if dir == "" {
		t.Skip("未设置 ALPINE_SECDB_DIR，跳过真实数据集验证")
	}
	release := os.Getenv("ALPINE_SECDB_RELEASE")
	if release == "" {
		release = "3.20"
	}
	files := map[string][]byte{}
	for _, repo := range []string{"main", "community"} {
		body, err := os.ReadFile(filepath.Join(dir, repo+".json"))
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", repo, err)
		}
		files[repo] = body
	}

	in := ParseInput{
		Source:    mustSource(t, domain.SourceAlpineSecDB),
		Release:   release,
		Files:     files,
		FetchedAt: time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC),
	}
	start := time.Now()
	res, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("解析真实数据集失败: %v", err)
	}
	t.Logf("解析耗时 %v；公告 %d，修复 %d，跳过 %d，最大嵌套 %d",
		time.Since(start), len(res.Advisories), len(res.Fixes), res.Skipped, res.Guard.MaxDepth)

	if len(res.Advisories) < 5000 {
		t.Errorf("公告数量异常偏低: %d", len(res.Advisories))
	}
	if len(res.Fixes) < 5000 {
		t.Errorf("修复记录异常偏低: %d", len(res.Fixes))
	}
	// 实测非 CVE 编号约 25 条，超过 200 条说明格式漂移。
	if res.Skipped > 200 {
		t.Errorf("跳过记录过多: %d，疑似格式漂移", res.Skipped)
	}

	// 目标：aom 在 3.9.1-r0 修掉 CVE-2024-5171（2026-11-24 实测）。
	var found bool
	for _, f := range res.Fixes {
		if f.Ref.Name == "aom" && f.CVEID == "CVE-2024-5171" && f.FixedVersion == "3.9.1-r0" {
			found = true
			if f.Channel != "main" {
				t.Errorf("aom 属于 main 仓库，实际渠道 %q", f.Channel)
			}
		}
	}
	if !found {
		t.Error("未找到 aom 在 3.9.1-r0 修复 CVE-2024-5171 的记录")
	}

	// 溯源完整性。
	for i, a := range res.Advisories {
		if a.ArtifactSHA256 == "" || a.RawLocator == "" || a.RawRecordHash == "" || a.ParserVersion == "" {
			t.Fatalf("第 %d 条公告溯源字段不完整: %+v", i+1, a)
		}
		if i > 2000 {
			break
		}
	}

	res2, err := AlpineParser{}.Parse(context.Background(), in)
	if err != nil {
		t.Fatalf("二次解析失败: %v", err)
	}
	if h1, h2 := digestResult(res), digestResult(res2); h1 != h2 {
		t.Fatalf("真实数据两次解析结果不一致: %s vs %s", h1[:12], h2[:12])
	}
}

func advisoryIDs(as []domain.Advisory) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.AdvisoryID)
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
