package inventory

import (
	"errors"
	"testing"
)

// TestCollectAPKWithoutManifest 覆盖 apk-tools 2.x 的回退路径。
//
// Alpine 3.20 自带的 apk-tools 2.14 没有 --manifest（"unrecognized option"），
// 没有回退时整次采集直接失败——CI 在 alpine:3.20 容器里实测到过这个后果。
// 回退必须做到两件事：不丢包，且包名里的连字符不能被错切。
func TestCollectAPKWithoutManifest(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "x86_64", nil)
	m.set("uname", []string{"-r"}, "6.6.30-0-lts", nil)
	m.set("apk", []string{"list", "--manifest"}, "",
		errors.New("exit status 1")) // 老版本 apk-tools：no such option
	m.set("apk", []string{"list", "--installed", "-v"},
		// SYNTHETIC 夹具（app_list.c -v 格式）
		"musl-1.2.5-r0 x86_64 {musl} (MIT) [installed]\n"+
			"font-noto-1.0-r0 x86_64 {font-noto} (OFL) [installed]\n"+
			"py3-typing-extensions-4.12.2-r0 noarch {py3-typing-extensions} (MIT) [installed]\n", nil)

	res := collectWith(t, m, "/tmp/nope-apk", []byte("ID=alpine\nVERSION_ID=3.20.3\n"))
	if len(res.Inventory.Packages) != 3 {
		t.Fatalf("应采 3 个包，实际 %d: %+v", len(res.Inventory.Packages), res.Inventory.Packages)
	}

	p, ok := res.Inventory.FindPackage("font-noto", "x86_64")
	if !ok || p.Ref.Version.String() != "1.0-r0" {
		t.Errorf("含连字符包名解析失败: %+v ok=%v", p, ok)
	}
	if p.SourceName != "font-noto" {
		t.Errorf("{origin} 未取到: %q", p.SourceName)
	}

	// 包名与版本都含连字符与数字：只有「右侧是合法版本」的切分点才对。
	p2, ok := res.Inventory.FindPackage("py3-typing-extensions", "noarch")
	if !ok || p2.Ref.Version.String() != "4.12.2-r0" {
		t.Errorf("多连字符包名解析失败: %+v ok=%v", p2, ok)
	}

	// 回退必须留下痕迹：用户有权知道包清单是从哪种输出解析来的。
	found := false
	for _, w := range res.Warnings {
		if contains(w, "--manifest") {
			found = true
		}
	}
	if !found {
		t.Errorf("回退时应产生警告，实际 %v", res.Warnings)
	}
}

// TestSplitAPKNameVersion 验证切分只接受「右侧是合法 apk 版本」的位置。
func TestSplitAPKNameVersion(t *testing.T) {
	cases := []struct {
		full string
		name string
		ver  string
		ok   bool
	}{
		{"musl-1.2.5-r0", "musl", "1.2.5-r0", true},
		{"font-noto-1.0-r0", "font-noto", "1.0-r0", true},
		{"py3-typing-extensions-4.12.2-r0", "py3-typing-extensions", "4.12.2-r0", true},
		{"linux-lts-6.6.63-r0", "linux-lts", "6.6.63-r0", true},
		// 没有可解析的版本段：不得硬切
		{"no-version-here", "", "", false},
		{"", "", "", false},
		{"-1.0-r0", "", "", false},
	}
	for _, c := range cases {
		name, ver, ok := splitAPKNameVersion(c.full)
		if ok != c.ok || name != c.name || ver != c.ver {
			t.Errorf("splitAPKNameVersion(%q) = (%q,%q,%v)，期望 (%q,%q,%v)",
				c.full, name, ver, ok, c.name, c.ver, c.ok)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
