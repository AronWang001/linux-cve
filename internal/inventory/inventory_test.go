package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// mockRunner 按命令名与参数返回预置输出，模拟只读查询工具。
type mockRunner struct {
	responses map[string][]byte
	errs      map[string]error
	calls     []string
}

func newMock() *mockRunner {
	return &mockRunner{responses: map[string][]byte{}, errs: map[string]error{}}
}

func (m *mockRunner) set(name string, args []string, out string, err error) {
	key := name + "\x00" + strings.Join(args, "\x00")
	m.responses[key] = []byte(out)
	if err != nil {
		m.errs[key] = err
	}
}

func (m *mockRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + "\x00" + strings.Join(args, "\x00")
	m.calls = append(m.calls, name+" "+strings.Join(args, " "))
	if err, ok := m.errs[key]; ok {
		return nil, err
	}
	if out, ok := m.responses[key]; ok {
		return out, nil
	}
	return nil, errors.New("mock: 未预置命令 " + key)
}

// ---- /etc/os-release 解析 ----
// 夹具为 SYNTHETIC（按 freedesktop 规范构造），非实机采集样本。

func TestParseOSRelease(t *testing.T) {
	data := []byte(`# comment
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
ID_LIKE=  debian  
EMPTY=
BROKEN LINE NO EQUALS
QUOTED='single'
`)
	kv := ParseOSRelease(data)
	cases := map[string]string{
		"NAME": "Debian GNU/Linux", "VERSION_ID": "12", "VERSION": "12 (bookworm)",
		"VERSION_CODENAME": "bookworm", "ID": "debian", "ID_LIKE": "debian",
		"EMPTY": "", "QUOTED": "single",
	}
	for k, want := range cases {
		if got := kv[k]; got != want {
			t.Errorf("os-release %s = %q，期望 %q", k, got, want)
		}
	}
	if _, ok := kv["BROKEN LINE NO EQUALS"]; ok {
		t.Error("无等号行不应产生键")
	}
}

func TestParseOSReleaseEdge(t *testing.T) {
	if kv := ParseOSRelease(nil); len(kv) != 0 {
		t.Errorf("空输入应得空表，实际 %v", kv)
	}
	if kv := ParseOSRelease([]byte("\n\n# only comments\n")); len(kv) != 0 {
		t.Errorf("纯注释应得空表，实际 %v", kv)
	}
	// 未闭合引号保持原值，不崩溃
	kv := ParseOSRelease([]byte(`ID="debian`))
	if kv["ID"] != `"debian` {
		t.Errorf("未闭合引号应原样保留，实际 %q", kv["ID"])
	}
}

// ---- 系统识别 ----

func TestDetectSystemDebian(t *testing.T) {
	osr := []byte("ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\nNAME=\"Debian GNU/Linux\"\nID_LIKE=debian\n")
	sys, err := DetectSystem(osr, "x86_64", "6.1.0-37-amd64")
	if err != nil {
		t.Fatalf("不应报错: %v", err)
	}
	if sys.DistroID != domain.DistroDebian || sys.Release != "12" || sys.Codename != "bookworm" ||
		sys.Arch != "x86_64" || sys.Kernel != "6.1.0-37-amd64" || sys.Manager != domain.ManagerDPKG {
		t.Errorf("识别结果异常: %+v", sys)
	}
	if sys.Unsupported {
		t.Error("debian 不应标记 unsupported")
	}
}

func TestDetectSystemUnknownDistro(t *testing.T) {
	osr := []byte("ID=weirdos\nVERSION_ID=\"1\"\nID_LIKE=\"debian ubuntu\"\n")
	sys, err := DetectSystem(osr, "riscv64", "6.6.0")
	if err != nil {
		t.Fatalf("未登记发行版应返回事实快照而非硬错误: %v", err)
	}
	if !sys.Unsupported || sys.DistroID != "" || sys.Manager != domain.ManagerNone {
		t.Errorf("未知发行版处理异常: %+v", sys)
	}
	if len(sys.IDLike) != 2 || sys.IDLike[0] != "debian" {
		t.Errorf("ID_LIKE 应记录而非用于匹配: %v", sys.IDLike)
	}
}

func TestDetectSystemMissingFields(t *testing.T) {
	if _, err := DetectSystem([]byte("NAME=NoID\n"), "x86_64", "6.1"); err == nil {
		t.Error("缺 ID 必须报错")
	}
	// 缺 VERSION_ID/VERSION
	if _, err := DetectSystem([]byte("ID=debian\n"), "x86_64", "6.1"); err == nil {
		t.Error("缺 release 必须报错")
	}
	// VERSION 退化
	sys, err := DetectSystem([]byte("ID=debian\nVERSION=\"12 (bookworm)\"\n"), "x86_64", "6.1")
	if err != nil || sys.Release != "12" {
		t.Errorf("VERSION 应退化出 release，实际 %+v err=%v", sys, err)
	}
	// 缺 uname
	if _, err := DetectSystem([]byte("ID=debian\nVERSION_ID=12\n"), "", "6.1"); err == nil {
		t.Error("缺架构必须报错")
	}
}

func TestManagerOf(t *testing.T) {
	cases := map[domain.DistroID]domain.PackageManager{
		domain.DistroDebian:  domain.ManagerDPKG,
		domain.DistroUbuntu:  domain.ManagerDPKG,
		domain.DistroRHEL:    domain.ManagerRPM,
		domain.DistroAmazon:  domain.ManagerRPM,
		domain.DistroSLES:    domain.ManagerRPM, // SUSE 走 rpm 查询
		domain.DistroAlpine:  domain.ManagerAPK,
		domain.DistroArch:    domain.ManagerPacman,
		domain.DistroID("x"): domain.ManagerNone,
	}
	for d, want := range cases {
		if got := managerOf(d); got != want {
			t.Errorf("managerOf(%s) = %s，期望 %s", d, got, want)
		}
	}
}

// ---- 内核映射（仅精确证据）----

func TestMapKernelDPKG(t *testing.T) {
	sys := SystemInfo{Kernel: "6.1.0-37-amd64", Manager: domain.ManagerDPKG}
	pkgs := []domain.InstalledPackage{
		{Ref: domain.PackageRef{Name: "linux-image-6.1.0-37-amd64", Arch: "amd64",
			Version: domain.Version{Raw: "6.1.140-1"}}},
		{Ref: domain.PackageRef{Name: "bash", Arch: "amd64", Version: domain.Version{Raw: "5.2.15-2"}}},
	}
	kf := mapKernel(sys, pkgs)
	if kf.Package != "linux-image-6.1.0-37-amd64" || kf.PackageVerRaw != "6.1.140-1" {
		t.Errorf("映射失败: %+v", kf)
	}
	if kf.Evidence == "" {
		t.Error("必须附带证据说明")
	}
}

func TestMapKernelRPM(t *testing.T) {
	sys := SystemInfo{Kernel: "5.14.0-427.13.1.el9_4.x86_64", Manager: domain.ManagerRPM}
	pkgs := []domain.InstalledPackage{
		{Ref: domain.PackageRef{Name: "kernel", Arch: "x86_64",
			Version: domain.Version{Raw: "5.14.0-427.13.1.el9_4"}}},
	}
	kf := mapKernel(sys, pkgs)
	if kf.Package != "kernel" {
		t.Errorf("RPM 内核映射失败: %+v", kf)
	}
	// 版本不匹配则不映射
	sys2 := SystemInfo{Kernel: "9.9.9-1.el9.x86_64", Manager: domain.ManagerRPM}
	if kf2 := mapKernel(sys2, pkgs); kf2.Package != "" {
		t.Errorf("不精确匹配不得映射: %+v", kf2)
	}
}

func TestMapKernelNoEvidence(t *testing.T) {
	// Arch/Alpine 不做无证据映射
	sys := SystemInfo{Kernel: "6.9.1-arch1-1", Manager: domain.ManagerPacman}
	if kf := mapKernel(sys, nil); kf.Package != "" {
		t.Errorf("无证据必须留空: %+v", kf)
	}
	sys2 := SystemInfo{Kernel: "6.6.30-0-lts", Manager: domain.ManagerAPK}
	if kf := mapKernel(sys2, nil); kf.Package != "" {
		t.Errorf("无证据必须留空: %+v", kf)
	}
}

// ---- 采集编排（mock 执行器）----
// 命令输出夹具为 SYNTHETIC：按各工具 man page/上游源码格式构造，非实机采集。

func TestCollectDebianEndToEnd(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "x86_64", nil)
	m.set("uname", []string{"-r"}, "6.1.0-37-amd64", nil)
	m.set("dpkg-query", []string{"-W", "-f=" + dpkgQueryFormat},
		// SYNTHETIC 夹具
		"bash\t5.2.15-2+b7\tamd64\tbash\t5.2.15-2\tGNU\tinstall ok installed\n"+
			"libc6:amd64\t2.36-9+deb12u4\tamd64\tglibc\t2.36-9\tGNU\tinstall ok installed\n"+
			"linux-image-6.1.0-37-amd64\t6.1.140-1\tamd64\tlinux\t6.1.140-1\tLinux\tinstall ok installed\n"+
			"oldpkg\t1.0\tall\t\t\t\tdeinstall ok config-files\n", // 非安装态，应过滤
		nil)

	res := collectWith(t, m, "/tmp/nope-os-release-debian", []byte("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"))
	if res.System.Manager != domain.ManagerDPKG {
		t.Fatalf("manager 错误: %+v", res.System)
	}
	if len(res.Inventory.Packages) != 3 {
		t.Fatalf("应采 3 个包（过滤 config-files），实际 %d", len(res.Inventory.Packages))
	}
	// multiarch 限定符剥离
	if p, ok := res.Inventory.FindPackage("libc6", "amd64"); !ok || p.SourceName != "glibc" {
		t.Errorf("libc6 解析异常: %+v ok=%v", p, ok)
	}
	// 内核映射
	if res.Inventory.KernelPackage != "linux-image-6.1.0-37-amd64" {
		t.Errorf("内核映射失败: %+v", res.Inventory)
	}
	// 来源渠道不可证明
	for _, p := range res.Inventory.Packages {
		if p.OriginChannel != domain.ChannelUnknown {
			t.Errorf("dpkg-query 无法证明来源，应为 ChannelUnknown: %s", p.OriginChannel)
		}
	}
}

func TestCollectDebianSourceMissing(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "amd64", nil)
	m.set("uname", []string{"-r"}, "6.1.0", nil)
	m.set("dpkg-query", []string{"-W", "-f=" + dpkgQueryFormat},
		"weirdpkg\t1.0\tamd64\t\t\t\tinstall ok installed\n", nil)
	res := collectWith(t, m, "/tmp/nope-src", []byte("ID=debian\nVERSION_ID=12\n"))
	p := res.Inventory.Packages[0]
	if p.SourceName != "" {
		t.Errorf("Source 字段为空必须桥接失败留空，实际 %q", p.SourceName)
	}
}

func TestCollectRPMEndToEnd(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "x86_64", nil)
	m.set("uname", []string{"-r"}, "5.14.0-427.13.1.el9_4.x86_64", nil)
	m.set("rpm", []string{"-qa", "--qf", rpmQueryFormat},
		// SYNTHETIC 夹具
		"openssl\t(none)\t3.0.7\t2.el9\tx86_64\topenssl-3.0.7-2.el9.src.rpm\tRed Hat\t1717000000\n"+
			"kernel\t(none)\t5.14.0\t427.13.1.el9_4\tx86_64\tkernel-5.14.0-427.13.1.el9_4.src.rpm\tRed Hat\t1717000001\n"+
			"epochpkg\t2\t1.0\t1\tx86_64\t(none)\t(none)\tnotatime\n",
		nil)
	res := collectWith(t, m, "/tmp/nope-rpm", []byte("ID=rhel\nVERSION_ID=9.4\n"))
	if len(res.Inventory.Packages) != 3 {
		t.Fatalf("应采 3 个包，实际 %d", len(res.Inventory.Packages))
	}
	p, ok := res.Inventory.FindPackage("openssl", "x86_64")
	if !ok || p.SourceName != "openssl" {
		t.Errorf("SOURCERPM 解析失败: %+v", p)
	}
	if p.InstallTime.IsZero() {
		t.Error("INSTALLTIME 应解析")
	}
	ep, ok := res.Inventory.FindPackage("epochpkg", "x86_64")
	if !ok || ep.SourceName != "" {
		t.Errorf("SOURCERPM=(none) 必须桥接失败: %+v", ep)
	}
	if ep.Ref.Version.Epoch != 2 || ep.Ref.Version.String() != "2:1.0-1" {
		t.Errorf("epoch 解析失败: %+v", ep.Ref.Version)
	}
	if res.Inventory.KernelPackage != "kernel" {
		t.Errorf("RPM 内核映射失败: %q", res.Inventory.KernelPackage)
	}
}

func TestCollectAPKEndToEnd(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "x86_64", nil)
	m.set("uname", []string{"-r"}, "6.6.30-0-lts", nil)
	m.set("apk", []string{"list", "--manifest"},
		// SYNTHETIC 夹具（app_list.c manifest 格式："name version"）
		"musl 1.2.5-r0\nfont-noto 1.0-r0\n", nil)
	m.set("apk", []string{"list", "--installed", "-v"},
		// SYNTHETIC 夹具（app_list.c -v 格式）
		"musl-1.2.5-r0 x86_64 {musl} (MIT) [installed]\n"+
			"font-noto-1.0-r0 x86_64 {font-noto} (OFL) [installed]\n", nil)
	res := collectWith(t, m, "/tmp/nope-apk", []byte("ID=alpine\nVERSION_ID=3.20.3\n"))
	if len(res.Inventory.Packages) != 2 {
		t.Fatalf("应采 2 个包，实际 %d: %+v", len(res.Inventory.Packages), res.Inventory.Packages)
	}
	// 含连字符包名不得被错切
	p, ok := res.Inventory.FindPackage("font-noto", "x86_64")
	if !ok || p.Ref.Version.String() != "1.0-r0" || p.SourceName != "font-noto" {
		t.Errorf("font-noto 解析失败: %+v ok=%v", p, ok)
	}
}

func TestCollectPacmanEndToEnd(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "x86_64", nil)
	m.set("uname", []string{"-r"}, "6.9.1-arch1-1", nil)
	m.set("pacman", []string{"-Qi"},
		// SYNTHETIC 夹具（pacman -Qi 块格式）
		"Name            : bash\n"+
			"Version         : 5.2.037-1\n"+
			"Architecture    : x86_64\n"+
			"Packager        : Christian Heusel <gromit@example.org>\n"+
			"Install Date    : Tue 14 May 2024 09:21:33 AM UTC\n"+
			"\n"+
			"Name            : linux\n"+
			"Version         : 6.9.1.arch1-1\n"+
			"Architecture    : x86_64\n"+
			"Packager        : Build Bot\n"+
			"Install Date    : not-a-date\n"+
			"\n", nil)
	res := collectWith(t, m, "/tmp/nope-pacman", []byte("ID=arch\nVERSION_ID=rolling\n"))
	if len(res.Inventory.Packages) != 2 {
		t.Fatalf("应采 2 个包，实际 %d", len(res.Inventory.Packages))
	}
	b := res.Inventory.Packages[0]
	if b.Ref.Name != "bash" || b.SourceName != "" {
		t.Errorf("pacman 无 pkgbase 证据必须留空 SourceName: %+v", b)
	}
	if b.InstallTime.IsZero() {
		t.Error("Install Date 应解析")
	}
	if !res.Inventory.Packages[1].InstallTime.IsZero() {
		t.Error("非法日期应落零值而非猜测")
	}
}

func TestCollectUnknownDistro(t *testing.T) {
	m := newMock()
	m.set("uname", []string{"-m"}, "riscv64", nil)
	m.set("uname", []string{"-r"}, "6.6.0", nil)
	c := &Collector{
		Runner: m,
		OSPath: "/tmp/nope-unknown",
		ReadFile: func(string) ([]byte, error) {
			return []byte("ID=weirdos\nVERSION_ID=1\n"), nil
		},
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	res, err := c.Collect(context.Background())
	if err == nil || res == nil {
		t.Fatal("未登记发行版必须报 Unsupported")
	}
	if !res.System.Unsupported {
		t.Error("应保留已识别事实")
	}
	for _, call := range m.calls {
		if strings.Contains(call, "dpkg") || strings.Contains(call, "rpm") ||
			strings.Contains(call, "apk") || strings.Contains(call, "pacman") {
			t.Errorf("未知发行版不得调用包管理器: %s", call)
		}
	}
}

func TestCollectHashStable(t *testing.T) {
	mk := func(order int) *Result {
		m := newMock()
		m.set("uname", []string{"-m"}, "x86_64", nil)
		m.set("uname", []string{"-r"}, "6.1.0", nil)
		lines := "a\t1.0\tamd64\ta\t1.0\tv\tinstall ok installed\n" +
			"b\t2.0\tamd64\tb\t2.0\tv\tinstall ok installed\n" +
			"c\t3.0\tall\tc\t3.0\tv\tinstall ok installed\n"
		if order == 1 {
			lines = "c\t3.0\tall\tc\t3.0\tv\tinstall ok installed\n" +
				"a\t1.0\tamd64\ta\t1.0\tv\tinstall ok installed\n" +
				"b\t2.0\tamd64\tb\t2.0\tv\tinstall ok installed\n"
		}
		m.set("dpkg-query", []string{"-W", "-f=" + dpkgQueryFormat}, lines, nil)
		return collectWith(t, m, "/tmp/nope-hash", []byte("ID=debian\nVERSION_ID=12\n"))
	}
	r1, r2 := mk(0), mk(1)
	if r1.Inventory.Hash == "" || r1.Inventory.Hash != r2.Inventory.Hash {
		t.Errorf("同批资产顺序不同哈希必须一致: %s vs %s", r1.Inventory.Hash, r2.Inventory.Hash)
	}
}

// collectWith 用给定 mock 与 os-release 内容执行一次采集。
func collectWith(t *testing.T, m *mockRunner, osPath string, osRelease []byte) *Result {
	t.Helper()
	c := &Collector{
		Runner: m,
		OSPath: osPath,
		ReadFile: func(string) ([]byte, error) {
			return osRelease, nil
		},
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
	}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 失败: %v", err)
	}
	return res
}

// ---- Runner 真实执行器：超时/不存在/非零退出/输出上限 ----

func TestExecRunnerCommandNotFound(t *testing.T) {
	_, err := ExecRunner{Timeout: 5 * time.Second}.Run(context.Background(),
		"definitely-not-a-real-cmd-linux-cve-test")
	if err == nil {
		t.Error("命令不存在必须报错")
	}
}

func TestExecRunnerNonZeroExit(t *testing.T) {
	// 本机 bash 存在；用退出码非零的命令验证错误包装
	_, err := ExecRunner{Timeout: 5 * time.Second}.Run(context.Background(), "bash", "-c", "exit 3")
	if err == nil {
		t.Error("非零退出必须报错")
	}
	if !strings.Contains(err.Error(), "非零退出") {
		t.Errorf("错误应含非零退出说明: %v", err)
	}
}

func TestExecRunnerTimeout(t *testing.T) {
	_, err := ExecRunner{Timeout: 200 * time.Millisecond}.Run(context.Background(),
		"bash", "-c", "sleep 5")
	if err == nil {
		t.Error("超时必须报错")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Errorf("错误应含超时说明: %v", err)
	}
}

func TestExecRunnerOutputLimit(t *testing.T) {
	_, err := ExecRunner{Timeout: 5 * time.Second, MaxOutput: 1024}.
		Run(context.Background(), "bash", "-c", "printf 'x%.0s' {1..100000}")
	if err == nil {
		t.Error("输出超限必须报错")
	}
	if !strings.Contains(err.Error(), "上限") {
		t.Errorf("错误应含上限说明: %v", err)
	}
}

// TestCollectRealFile 用真实临时文件验证 ReadFile 通路（非 mock）。
func TestCollectRealFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	if err := os.WriteFile(p, []byte("ID=debian\nVERSION_ID=12\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newMock()
	m.set("uname", []string{"-m"}, "amd64", nil)
	m.set("uname", []string{"-r"}, "6.1.0", nil)
	m.set("dpkg-query", []string{"-W", "-f=" + dpkgQueryFormat},
		"x\t1.0\tamd64\tx\t1.0\tv\tinstall ok installed\n", nil)
	c := &Collector{Runner: m, OSPath: p, ReadFile: os.ReadFile,
		Now: func() time.Time { return time.Now().UTC() }}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 失败: %v", err)
	}
	if len(res.Inventory.Packages) != 1 {
		t.Errorf("应采 1 包，实际 %d", len(res.Inventory.Packages))
	}
}
