package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/database"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/inventory"
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

// runCLIWithCollector 以注入的采集器工厂执行 CLI，便于测试替换。
func runCLIWithCollector(t *testing.T, factory func() *inventory.Collector, args ...string) (exitcode.Code, string, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	e := &env{
		stdout:       &out,
		stderr:       &errOut,
		getenv:       func(string) string { return "" },
		newCollector: factory,
	}
	code, err := e.run(context.Background(), args)
	if err != nil {
		// 复刻 Main 的退出码优先逻辑与 stderr 输出
		_, _ = errOut.WriteString("error: " + err.Error() + "\n")
		if c := apperr.CodeOf(err); c != exitcode.OK {
			code = c
		}
	}
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
		Inventory struct {
			DistroID string `json:"DistroID"`
			Packages []struct {
				Ref struct {
					Name string `json:"Name"`
				} `json:"Ref"`
			} `json:"Packages"`
		} `json:"inventory"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("JSON 输出无法解析: %v（原始 %q）", err, out)
	}
	if parsed.Inventory.DistroID != "debian" {
		t.Errorf("JSON DistroID 应为 debian，实际 %q", parsed.Inventory.DistroID)
	}
	if len(parsed.Inventory.Packages) != 2 {
		t.Errorf("JSON 应含 2 个包，实际 %d", len(parsed.Inventory.Packages))
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
