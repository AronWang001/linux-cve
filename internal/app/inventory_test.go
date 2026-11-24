package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/inventory"
)

// cliMockRunner 是 app 包内的只读命令模拟器，用于 CLI inventory 测试。
// 与 inventory 包内的 mockRunner 独立：CLI 测试只关心命令分发与输出，不重复测试采集逻辑。
type cliMockRunner struct {
	responses map[string]string
	errs      map[string]error
}

func newCLIMock() *cliMockRunner {
	return &cliMockRunner{responses: map[string]string{}, errs: map[string]error{}}
}

func (m *cliMockRunner) set(name string, args []string, out string) {
	m.responses[name+"\x00"+strings.Join(args, "\x00")] = out
}

func (m *cliMockRunner) setErr(name string, args []string, err error) {
	m.errs[name+"\x00"+strings.Join(args, "\x00")] = err
}

func (m *cliMockRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + "\x00" + strings.Join(args, "\x00")
	if err, ok := m.errs[key]; ok {
		return nil, err
	}
	if out, ok := m.responses[key]; ok {
		return []byte(out), nil
	}
	return nil, errors.New("mock: 未预置命令 " + name)
}

// synthDebianCollector 构造一个采集 Debian 合成夹具的采集器。
// SYNTHETIC：命令输出按 dpkg-query 格式手工构造，非实机采集。
func synthDebianCollector(m *cliMockRunner) func() *inventory.Collector {
	m.set("uname", []string{"-m"}, "x86_64")
	m.set("uname", []string{"-r"}, "6.1.0-37-amd64")
	// SYNTHETIC 夹具：dpkg-query 7 字段输出
	m.set("dpkg-query", []string{"-W", "-f=" + dpkgFormatForTest},
		"bash\t5.2.15-2+b7\tamd64\tbash\t5.2.15-2\tGNU\tinstall ok installed\n"+
			"linux-image-6.1.0-37-amd64\t6.1.140-1\tamd64\tlinux\t6.1.140-1\tLinux\tinstall ok installed\n")
	return func() *inventory.Collector {
		return &inventory.Collector{
			Runner: m,
			OSPath: "/tmp/synth-os-release",
			ReadFile: func(string) ([]byte, error) {
				return []byte("ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n"), nil
			},
			Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		}
	}
}

// dpkgFormatForTest 与 internal/inventory 的 dpkgQueryFormat 保持一致。
const dpkgFormatForTest = "${binary:Package}\t${Version}\t${Architecture}\t${Source}\t${source:Version}\t${Vendor}\t${Status}\n"

// rpmQueryFormatForTest 与 internal/inventory 的 rpmQueryFormat 保持一致（8 字段）。
const rpmQueryFormatForTest = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\t%{INSTALLTIME}\n"

// runCLIWithCollector 通过真实 Main 入口（mainWithEnv）执行 CLI，仅注入采集器工厂。
// 不复制 Main 的退出码/输出逻辑，保证与生产入口一致。
func runCLIWithCollector(t *testing.T, factory func() *inventory.Collector, args ...string) (exitcode.Code, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	e := &env{
		stdout:       &out,
		stderr:       &errOut,
		getenv:       func(string) string { return "" },
		newCollector: factory,
	}
	code := mainWithEnv(context.Background(), e, args)
	return code, out.String(), errOut.String()
}

// ---- CLI inventory 测试 ----

func TestInventoryCommandText(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	code, out, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory")
	if code != exitcode.OK {
		t.Fatalf("inventory 退出码应为 0，实际 %d（stderr: %s）", code, errOut)
	}
	for _, want := range []string{"distro", "release", "arch", "kernel", "packages", "hash"} {
		if !strings.Contains(out, want) {
			t.Errorf("文本输出应包含 %q，实际 %q", want, out)
		}
	}
	if !strings.Contains(out, "debian") {
		t.Errorf("输出应含发行版 debian，实际 %q", out)
	}
}

func TestInventoryCommandJSON(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	code, out, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")
	if code != exitcode.OK {
		t.Fatalf("inventory --json 退出码应为 0，实际 %d（stderr: %s）", code, errOut)
	}
	var parsed struct {
		SchemaVersion int    `json:"schema_version"`
		CollectedAt   string `json:"collected_at"`
		Distro        struct {
			ID string `json:"id"`
		} `json:"distro"`
		Packages []struct {
			Name string `json:"name"`
		} `json:"packages"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("JSON 输出无法解析: %v（原始 %q）", err, out)
	}
	if parsed.SchemaVersion != inventorySchemaVersion {
		t.Errorf("schema_version 应为 %d，实际 %d", inventorySchemaVersion, parsed.SchemaVersion)
	}
	if parsed.Distro.ID != "debian" {
		t.Errorf("distro.id 应为 debian，实际 %q", parsed.Distro.ID)
	}
	if len(parsed.Packages) != 2 {
		t.Errorf("JSON 应含 2 个包，实际 %d", len(parsed.Packages))
	}
	// 空 warnings 应为 [] 而非 null
	if parsed.Warnings == nil {
		t.Errorf("warnings 应为空数组 []，实际 null")
	}
}

func TestInventoryCommandSave(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()

	// 先迁移数据库
	code, _, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "db", "migrate")
	if code != exitcode.OK {
		t.Fatalf("迁移失败: %d（%s）", code, errOut)
	}

	// 保存资产
	code, out, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--save")
	if code != exitcode.OK {
		t.Fatalf("inventory --save 退出码应为 0，实际 %d（stderr: %s）", code, errOut)
	}
	if !strings.Contains(out, "saved") {
		t.Errorf("保存输出应含 saved，实际 %q", out)
	}

	// 从数据库读取并核对
	d, err := database.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	defer func() { _ = d.Close() }()

	overview, err := d.InventoryOverview(context.Background())
	if err != nil {
		t.Fatalf("读取资产概览失败: %v", err)
	}
	if overview.Inventories != 1 {
		t.Errorf("应保存 1 个快照，实际 %d", overview.Inventories)
	}
	if overview.Packages != 2 {
		t.Errorf("应保存 2 个包，实际 %d", overview.Packages)
	}
}

func TestInventoryCommandUnsupportedDistro(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	m.set("uname", []string{"-m"}, "x86_64")
	m.set("uname", []string{"-r"}, "6.1.0")
	factory := func() *inventory.Collector {
		return &inventory.Collector{
			Runner: m,
			OSPath: "/tmp/synth-unsupported",
			ReadFile: func(string) ([]byte, error) {
				return []byte("ID=notarealos\nVERSION_ID=1\n"), nil
			},
			Now: func() time.Time { return time.Now().UTC() },
		}
	}
	code, _, errOut := runCLIWithCollector(t, factory,
		"--config", cfgPath, "--db", dbPath, "inventory")
	if code != exitcode.Unsupported {
		t.Errorf("未知发行版退出码应为 4，实际 %d", code)
	}
	if !strings.Contains(errOut, "未登记发行版") {
		t.Errorf("应说明未登记发行版，实际 %q", errOut)
	}
}

func TestInventoryCommandBadFlag(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	code, _, _ := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--nonsense")
	if code != exitcode.Usage {
		t.Errorf("非法参数退出码应为 2，实际 %d", code)
	}
}

func TestInventoryCommandCollectError(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	// uname 命令失败 → 采集报错，不得静默成功
	m.setErr("uname", []string{"-m"}, errors.New("boom"))
	factory := func() *inventory.Collector {
		return &inventory.Collector{
			Runner: m,
			OSPath: "/tmp/synth-err",
			ReadFile: func(string) ([]byte, error) {
				return []byte("ID=debian\nVERSION_ID=12\n"), nil
			},
			Now: func() time.Time { return time.Now().UTC() },
		}
	}
	code, _, errOut := runCLIWithCollector(t, factory,
		"--config", cfgPath, "--db", dbPath, "inventory")
	if code == exitcode.OK {
		t.Error("采集失败不得返回成功")
	}
	if errOut == "" {
		t.Error("采集失败应向 stderr 输出错误")
	}
}

func TestInventoryCommandSaveToUninitializedDB(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	// 未迁移数据库直接 --save：SaveInventory 应报错（表不存在）
	code, _, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--save")
	if code == exitcode.OK {
		t.Error("未初始化数据库 --save 不得返回成功")
	}
	if errOut == "" {
		t.Error("数据库异常应向 stderr 输出错误")
	}
}

// TestInventoryCommandJSONSave 验证 --json --save 组合：stdout 必须是纯 JSON，
// 保存状态经 saved_inventory_id 字段表达，不得污染 JSON 输出。
func TestInventoryCommandJSONSave(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	// 先迁移
	code, _, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "db", "migrate")
	if code != exitcode.OK {
		t.Fatalf("迁移失败: %d（%s）", code, errOut)
	}

	code, out, errOut := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json", "--save")
	if code != exitcode.OK {
		t.Fatalf("inventory --json --save 退出码应为 0，实际 %d（stderr: %s）", code, errOut)
	}

	// 整个 stdout 必须能作为单个 JSON 对象解析（首字符应为 '{'，不能有前导文本）
	trimmed := strings.TrimSpace(out)
	if !strings.HasPrefix(trimmed, "{") {
		t.Errorf("--json --save 的 stdout 应以 JSON 开头，实际 %q", out)
	}
	var parsed struct {
		SavedInventoryID *int64 `json:"saved_inventory_id"`
	}
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		t.Fatalf("--json --save 的 stdout 应能整体解析为 JSON: %v（原始 %q）", err, out)
	}
	if parsed.SavedInventoryID == nil || *parsed.SavedInventoryID <= 0 {
		t.Errorf("saved_inventory_id 应为正整数，实际 %v", parsed.SavedInventoryID)
	}
}

// ---- CLI inventory JSON DTO 专项测试 ----

// TestInventoryJSONFieldNames 验证 JSON 字段全部为 snake_case，
// 且不含 domain 模型的 PascalCase 字段名。
func TestInventoryJSONFieldNames(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	_, out, _ := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")

	// 不应出现 Go 默认 PascalCase 字段名
	for _, bad := range []string{"\"DistroID\"", "\"Packages\"", "\"CollectedAt\"", "\"Ref\"", "\"SourceName\"", "\"EntryHash\"", "\"SchemaVersion\""} {
		if strings.Contains(out, bad) {
			t.Errorf("JSON 不应含 PascalCase 字段 %s，实际 %q", bad, out)
		}
	}
	// 应出现 snake_case 字段
	for _, want := range []string{"\"schema_version\"", "\"collected_at\"", "\"distro\"", "\"packages\"", "\"source_name\"", "\"entry_hash\"", "\"origin_channel\""} {
		if !strings.Contains(out, want) {
			t.Errorf("JSON 应含字段 %s，实际 %q", want, out)
		}
	}
}

// TestInventoryJSONEmptyFields 验证空字段与空数组的表达方式。
func TestInventoryJSONEmptyFields(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	// 单包夹具：无源码包名、vendor 空、install time 零值 → 校验空字段输出
	m.set("uname", []string{"-m"}, "x86_64")
	m.set("uname", []string{"-r"}, "6.1.0-37-amd64")
	m.set("dpkg-query", []string{"-W", "-f=" + dpkgFormatForTest},
		"foo\t1.0\tamd64\t\t\t\tinstall ok installed\n")
	factory := func() *inventory.Collector {
		return &inventory.Collector{
			Runner: m,
			OSPath: "/tmp/synth-empty",
			ReadFile: func(string) ([]byte, error) {
				return []byte("ID=debian\nVERSION_ID=12\n"), nil
			},
			Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		}
	}
	_, out, _ := runCLIWithCollector(t, factory,
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	pkgs := raw["packages"].([]interface{})
	if len(pkgs) != 1 {
		t.Fatalf("应含 1 个包，实际 %d", len(pkgs))
	}
	pkg := pkgs[0].(map[string]interface{})
	// 空字符串应显式输出 ""，非省略
	if pkg["source_name"] != "" {
		t.Errorf("source_name 应为空串，实际 %v", pkg["source_name"])
	}
	if pkg["vendor"] != "" {
		t.Errorf("vendor 应为空串，实际 %v", pkg["vendor"])
	}
	if pkg["install_time"] != "" {
		t.Errorf("install_time 零值应为空串，实际 %v", pkg["install_time"])
	}
	// warnings 应为 [] 而非 null
	if raw["warnings"] == nil {
		t.Errorf("warnings 应为空数组，实际 null")
	}
}

// TestInventoryJSONStableOutput 验证输出顺序稳定（同输入两次输出逐字节一致）。
func TestInventoryJSONStableOutput(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m1 := newCLIMock()
	_, out1, _ := runCLIWithCollector(t, synthDebianCollector(m1),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")
	m2 := newCLIMock()
	_, out2, _ := runCLIWithCollector(t, synthDebianCollector(m2),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")
	if out1 != out2 {
		t.Errorf("同输入 JSON 输出应稳定一致")
	}
}

// TestInventoryJSONTimeUTC 验证时间字段为 UTC RFC3339。
func TestInventoryJSONTimeUTC(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	_, out, _ := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")
	var parsed struct {
		CollectedAt string `json:"collected_at"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	// synthDebianCollector 的 Now 固定为 2026-01-01T00:00:00Z
	if parsed.CollectedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("collected_at 应为 UTC RFC3339，实际 %q", parsed.CollectedAt)
	}
}

// TestInventoryJSONSchemaVersion 验证 schema_version 存在且为预期常量。
func TestInventoryJSONSchemaVersion(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	_, out, _ := runCLIWithCollector(t, synthDebianCollector(m),
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")
	var parsed struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	if parsed.SchemaVersion != inventorySchemaVersion {
		t.Errorf("schema_version 应为 %d，实际 %d", inventorySchemaVersion, parsed.SchemaVersion)
	}
}

// TestInventoryJSONArchCanonical 验证 JSON 输出规范化架构名：
// 采集层保留原始标识（rpm 的 x86_64 / aarch64），CLI 对外统一 amd64 / arm64。
func TestInventoryJSONArchCanonical(t *testing.T) {
	cfgPath, dbPath := isolatedArgs(t)
	m := newCLIMock()
	// rpm 系：uname -m 返回 x86_64，包架构也用 x86_64
	m.set("uname", []string{"-m"}, "x86_64")
	m.set("uname", []string{"-r"}, "4.18.0-553.el8_10")
	// rpm 8 字段：NAME/EPOCHNUM/VERSION/RELEASE/ARCH/SOURCERPM/VENDOR/INSTALLTIME
	m.set("rpm", []string{"-qa", "--qf", rpmQueryFormatForTest},
		"kernel\t0\t4.18.0\t553.182.1.el8_10\tx86_64\tkernel-4.18.0-553.182.1.el8_10.src.rpm\tRed Hat, Inc.\t1760000000\n")
	factory := func() *inventory.Collector {
		return &inventory.Collector{
			Runner: m,
			OSPath: "/tmp/synth-rpm",
			ReadFile: func(string) ([]byte, error) {
				return []byte("ID=rhel\nVERSION_ID=8.10\n"), nil
			},
			Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		}
	}
	_, out, _ := runCLIWithCollector(t, factory,
		"--config", cfgPath, "--db", dbPath, "inventory", "--json")

	var raw struct {
		Distro struct {
			Arch string `json:"arch"`
		} `json:"distro"`
		Packages []struct {
			Arch string `json:"arch"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("JSON 解析失败: %v", err)
	}
	if raw.Distro.Arch != "amd64" {
		t.Errorf("distro.arch 应规范化为 amd64，实际 %q", raw.Distro.Arch)
	}
	if len(raw.Packages) != 1 || raw.Packages[0].Arch != "amd64" {
		t.Errorf("packages[0].arch 应规范化为 amd64，实际 %+v", raw.Packages)
	}
}
