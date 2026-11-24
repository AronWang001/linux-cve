package version

import (
	"testing"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// ---- Debian（dpkg 语义）----

func TestParseDebian(t *testing.T) {
	cases := []struct {
		raw               string
		epoch             int
		upstream, release string
		wantErr           bool
	}{
		{raw: "1.0", upstream: "1.0"},
		{raw: "1:1.0-2", epoch: 1, upstream: "1.0", release: "2"},
		// 回移：tilde 在 revision 中
		{raw: "6.12.113-1~deb12u1", upstream: "6.12.113", release: "1~deb12u1"},
		// Policy：在最后一个连字符处切分
		{raw: "1.0-rc1", upstream: "1.0", release: "rc1"},
		{raw: "1.0-rc1-2", upstream: "1.0-rc1", release: "2"},
		{raw: "20201116-1", upstream: "20201116", release: "1"},
		{raw: "0:0.9", upstream: "0.9"},
		// 非法
		{raw: "", wantErr: true},
		{raw: "1.0-", wantErr: true},
		{raw: ":1.0", wantErr: true},
		{raw: "a:1.0", wantErr: true},
		{raw: "1.0 2", wantErr: true},
		{raw: "1.0-1_2", wantErr: true}, // revision 不允许 '_'
		{raw: "1.0-a/b", wantErr: true},
		{raw: "-1.0", wantErr: true}, // upstream 为空
	}
	for _, c := range cases {
		v, err := ParseDebian(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseDebian(%q) 期望错误，实际通过: %+v", c.raw, v)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseDebian(%q) 不应报错: %v", c.raw, err)
			continue
		}
		if v.Raw != c.raw || v.Epoch != c.epoch || v.Upstream != c.upstream || v.Release != c.release {
			t.Errorf("ParseDebian(%q) = {%d,%q,%q}，期望 {%d,%q,%q}",
				c.raw, v.Epoch, v.Upstream, v.Release, c.epoch, c.upstream, c.release)
		}
	}
}

func TestCompareDebian(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0", "1.0-0", 0}, // 缺失 revision ≡ revision 0
		{"1.0-1", "1.0-1", 0},
		{"1.0~rc1", "1.0", -1}, // tilde 早于一切
		{"1.0", "1.0~rc1", 1},
		{"6.12.113-1~deb12u1", "6.12.113-1", -1}, // 回移补丁更旧
		{"1.0-1~deb12u1", "1.0-1", -1},
		{"1:1.0", "2.0", 1}, // epoch 优先
		{"2:1.0", "1:2.0", 1},
		{"1.0-2", "1.0-1", 1},
		{"1.0", "1.0.0", -1}, // 尾部剩余者新
		{"2.0", "10.0", -1},  // 数字按值比较，非字符串
		{"1.0a", "1.0", 1},   // dpkg：尾部 alpha 更新（与 libalpm 相反）
		{"1.0a", "1.0+a", -1},
		// dpkg 数字段去前导零后按值比较：01 == 1（与 apk 的串比较怪癖不同）
		{"1.01", "1.1", 0},
		{"1.010", "1.1", 1}, // 010 → 10 > 1
		{"1.0-0.1", "1.0-0.2", -1},
		{"3.0.0-1", "3.0-1", 1},
	}
	for _, c := range cases {
		got, err := CompareDebian(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareDebian(%q,%q) 报错: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareDebian(%q,%q) = %d，期望 %d", c.a, c.b, got, c.want)
		}
		// 反向比较必须对称
		rev, err := CompareDebian(c.b, c.a)
		if err != nil {
			t.Fatalf("CompareDebian(%q,%q) 报错: %v", c.b, c.a, err)
		}
		if rev != -c.want && !(c.want == 0 && rev == 0) {
			t.Errorf("CompareDebian(%q,%q) = %d，反向不对称（正向 %d）", c.b, c.a, rev, c.want)
		}
	}
}

func TestCompareDebianInvalid(t *testing.T) {
	for _, pair := range [][2]string{
		{"", "1.0"}, {"1.0", ""}, {"1.0-", "1.0"}, {"1.0 2", "1.0"}, {"a b", "1.0"},
	} {
		if _, err := CompareDebian(pair[0], pair[1]); err == nil {
			t.Errorf("CompareDebian(%q,%q) 非法版本必须报错", pair[0], pair[1])
		}
	}
}

// ---- RPM（rpmvercmp.cc 语义）----

func TestParseRPM(t *testing.T) {
	cases := []struct {
		raw               string
		epoch             int
		upstream, release string
		wantErr           bool
	}{
		{raw: "3.0.7-2.el9", upstream: "3.0.7", release: "2.el9"},
		{raw: "1:2.3-4", epoch: 1, upstream: "2.3", release: "4"},
		{raw: "1.0", upstream: "1.0"},
		{raw: "5.14.0-427.13.1.el9_4", upstream: "5.14.0", release: "427.13.1.el9_4"},
		{raw: "", wantErr: true},
		{raw: "1.0-", wantErr: true},
		{raw: ":1.0", wantErr: true},
		{raw: "1.0 1", wantErr: true},
		{raw: "x:1.0", wantErr: true},
	}
	for _, c := range cases {
		v, err := ParseRPM(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseRPM(%q) 期望错误，实际通过", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseRPM(%q) 不应报错: %v", c.raw, err)
			continue
		}
		if v.Raw != c.raw || v.Epoch != c.epoch || v.Upstream != c.upstream || v.Release != c.release {
			t.Errorf("ParseRPM(%q) = {%d,%q,%q}，期望 {%d,%q,%q}",
				c.raw, v.Epoch, v.Upstream, v.Release, c.epoch, c.upstream, c.release)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		{"1.0~rc1", "1.0", -1},    // tilde 早于一切
		{"1.0", "1.0^git1", -1},   // caret 晚于串尾
		{"1.0^git1", "1.0.1", -1}, // caret 早于字母数字
		{"1.0^git1", "1.0^git2", -1},
		{"1.0", "1.0-1", -1}, // 缺 release 按空串
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1},
		{"2.0", "10.0", -1},
		{"1.0a", "1.0", 1}, // 现代 rpm：尾部 alpha 更新（与 libalpm 相反）
		{"1.0", "1.0.0", -1},
		{"3.0.7-2.el9", "3.0.7-1.el9", 1},
		{"1.0-1", "1.0-1", 0},
		{"1.0~rc1", "1.0~rc2", -1},
	}
	for _, c := range cases {
		got, err := CompareRPM(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareRPM(%q,%q) 报错: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareRPM(%q,%q) = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRPMVerccmpQuirks(t *testing.T) {
	// 数字段与字母段类型不一致：数字更新（bugzilla #50977 语义）
	if got := rpmvercmp("1.01", "1.0a"); got != 1 {
		t.Errorf("rpmvercmp(1.01,1.0a) = %d，期望 1", got)
	}
	// 数字段去前导零后按位数比较
	if got := rpmvercmp("1.0010", "1.9"); got != 1 {
		t.Errorf("rpmvercmp(1.0010,1.9) = %d，期望 1（0010 → 10 > 9）", got)
	}
}

func TestCompareRPMInvalid(t *testing.T) {
	if _, err := CompareRPM("", "1.0"); err == nil {
		t.Error("空版本必须报错")
	}
	if _, err := CompareRPM("1.0-", "1.0"); err == nil {
		t.Error("空 release 必须报错")
	}
}

// ---- Pacman（libalpm 语义，含怪癖）----

func TestParsePacman(t *testing.T) {
	cases := []struct {
		raw               string
		epoch             int
		upstream, release string
		wantErr           bool
	}{
		{raw: "6.9.1-1", upstream: "6.9.1", release: "1"},
		{raw: "1:2.4.1-2", epoch: 1, upstream: "2.4.1", release: "2"},
		{raw: "1.0", upstream: "1.0"},
		{raw: "1.2.3-1-2", upstream: "1.2.3-1", release: "2"}, // 取最后一个 '-'
		{raw: "", wantErr: true},
		{raw: "1.0 2", wantErr: true},
		{raw: "1/2", wantErr: true},
		{raw: ":1.0", wantErr: true},
		{raw: "1:2:3", wantErr: true},
	}
	for _, c := range cases {
		v, err := ParsePacman(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePacman(%q) 期望错误，实际通过", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePacman(%q) 不应报错: %v", c.raw, err)
			continue
		}
		if v.Raw != c.raw || v.Epoch != c.epoch || v.Upstream != c.upstream || v.Release != c.release {
			t.Errorf("ParsePacman(%q) = {%d,%q,%q}，期望 {%d,%q,%q}",
				c.raw, v.Epoch, v.Upstream, v.Release, c.epoch, c.upstream, c.release)
		}
	}
}

func TestComparePacman(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0", 0},
		// libalpm 怪癖：仅一侧有 release 视为相等（保留不"修复"）
		{"1.0-1", "1.0", 0},
		{"1.0", "1.0-1", 0},
		{"1.0-2", "1.0-1", 1}, // 两侧都有 release 才比较
		// libalpm 怪癖：尾部 alpha 更旧（现代 rpm 相反）
		{"1.0a", "1.0", -1},
		{"1.0", "1.0a", 1},
		{"1.0", "1.0.0", -1},
		{"2.0", "10.0", -1},
		{"1:1.0", "2.0", 1},
		{"1:1.0", "1:1.0", 0},
		{"6.9.1-1", "6.9.2-1", -1},
		// 分隔符长度怪癖：短分隔符更旧
		{"1.0", "1..0", -1},
	}
	for _, c := range cases {
		got, err := ComparePacman(c.a, c.b)
		if err != nil {
			t.Fatalf("ComparePacman(%q,%q) 报错: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("ComparePacman(%q,%q) = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestComparePacmanInvalid(t *testing.T) {
	if _, err := ComparePacman("", "1.0"); err == nil {
		t.Error("空版本必须报错")
	}
	if _, err := ComparePacman("1.0 2", "1.0"); err == nil {
		t.Error("含空白必须报错")
	}
}

// ---- Alpine（apk 语法）----

func TestParseAPK(t *testing.T) {
	cases := []struct {
		raw               string
		upstream, release string
		wantErr           bool
	}{
		{raw: "1.2.5-r0", upstream: "1.2.5", release: "r0"},
		{raw: "1.2.3_rc1-r2", upstream: "1.2.3_rc1", release: "r2"},
		{raw: "2.0.0_p20240101-r0", upstream: "2.0.0_p20240101", release: "r0"},
		{raw: "1.2.3", upstream: "1.2.3"},
		{raw: "1.0~20dead-r0", upstream: "1.0~20dead", release: "r0"},
		// 非法
		{raw: "", wantErr: true},
		{raw: "1.2.3-1", wantErr: true}, // '-' 只能引出 -rN
		{raw: "1.2.3:", wantErr: true},  // 无 epoch
		{raw: "2:1.2.3-r0", wantErr: true},
		{raw: "abc", wantErr: true},      // 必须以数字开头
		{raw: "1.", wantErr: true},       // 数字段不能为空
		{raw: "1.0_gitX", wantErr: true}, // 后缀后不能直接跟大写字母
		{raw: "1.0~g123", wantErr: true}, // ~ 后必须是十六进制
		{raw: "1.0_xyz", wantErr: true},  // 未知后缀
		{raw: "1.0-r", wantErr: true},    // -r 后必须是数字
	}
	for _, c := range cases {
		v, err := ParseAPK(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseAPK(%q) 期望错误，实际通过", c.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAPK(%q) 不应报错: %v", c.raw, err)
			continue
		}
		if v.Raw != c.raw || v.Upstream != c.upstream || v.Release != c.release || v.Epoch != 0 {
			t.Errorf("ParseAPK(%q) = {0,%q,%q}，期望 {0,%q,%q}",
				c.raw, v.Upstream, v.Release, c.upstream, c.release)
		}
	}
}

func TestCompareAPK(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.5-r0", "1.2.5-r0", 0},
		{"1.2.5-r0", "1.2.5-r1", -1},
		{"1.2.3", "1.2.3-r0", -1},        // 修订号使其更新
		{"1.2.3_rc1-r0", "1.2.3-r0", -1}, // 预发布后缀更旧
		{"1.2.3_alpha1-r0", "1.2.3_beta1-r0", -1},
		{"1.2.3_p1-r0", "1.2.3-r0", 1}, // 补丁后缀更新
		{"1.2.3_git20230101-r0", "1.2.3-r0", 1},
		{"2.0-r0", "10.0-r0", -1},
		{"1.01-r0", "1.1-r0", -1}, // 前导零 → 串比较怪癖（Gentoo 风格）
		{"1.2.3_rc1-r0", "1.2.3_rc2-r0", -1},
		// 上游终局规则（token 种类数值大者落败）：COMMIT_HASH 侧胜过 -rN 与空
		{"1.0~20dead-r0", "1.0-r0", 1},
		{"1.0~20dead-r0", "1.0", 1},
	}
	for _, c := range cases {
		got, err := CompareAPK(c.a, c.b)
		if err != nil {
			t.Fatalf("CompareAPK(%q,%q) 报错: %v", c.a, c.b, err)
		}
		if got != c.want {
			t.Errorf("CompareAPK(%q,%q) = %d，期望 %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareAPKInvalid(t *testing.T) {
	if _, err := CompareAPK("", "1.0"); err == nil {
		t.Error("空版本必须报错")
	}
	if _, err := CompareAPK("1.0-1", "1.0"); err == nil {
		t.Error("非法语法必须报错而不是猜测比较")
	}
}

// ---- 分发与跨管理器约束 ----

func TestCompareDispatch(t *testing.T) {
	if _, err := Compare(domain.ManagerDPKG, "1.0", "1.0"); err != nil {
		t.Errorf("dpkg 分发失败: %v", err)
	}
	if _, err := Compare(domain.ManagerRPM, "1.0", "1.0"); err != nil {
		t.Errorf("rpm 分发失败: %v", err)
	}
	if _, err := Compare(domain.ManagerAPK, "1.0-r0", "1.0-r0"); err != nil {
		t.Errorf("apk 分发失败: %v", err)
	}
	if _, err := Compare(domain.ManagerPacman, "1.0-1", "1.0-1"); err != nil {
		t.Errorf("pacman 分发失败: %v", err)
	}
	// 未知/缺失管理器必须拒绝
	if _, err := Compare(domain.ManagerNone, "1.0", "1.0"); err == nil {
		t.Error("ManagerNone 必须拒绝比较")
	}
	if _, err := Compare("weird", "1.0", "1.0"); err == nil {
		t.Error("未登记管理器必须拒绝比较")
	}
}

func TestParseDispatch(t *testing.T) {
	v, err := Parse(domain.ManagerDPKG, "1:2.3-4~deb12u1")
	if err != nil {
		t.Fatalf("Parse 分发失败: %v", err)
	}
	if v.Epoch != 1 || v.String() != "1:2.3-4~deb12u1" {
		t.Errorf("解析结果异常: %+v", v)
	}
	if _, err := Parse(domain.ManagerNone, "1.0"); err == nil {
		t.Error("ManagerNone 必须拒绝解析")
	}
}

func TestCrossManagerSemanticsDiffer(t *testing.T) {
	// 同一对版本在不同管理器下结论不同 —— 证明没有共用字符串比较
	a, b := "1.0a", "1.0"
	d, err := CompareDebian(a, b)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ComparePacman(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if d != 1 || p != -1 {
		t.Errorf("管理器语义应不同（dpkg=1 alpm=-1），实际 dpkg=%d alpm=%d", d, p)
	}
}
