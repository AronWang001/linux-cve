package inventory

import (
	"context"
	"os"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// OSReleasePath 是 os-release 的标准位置，可注入便于测试。
const OSReleasePath = "/etc/os-release"

// Result 是一次资产采集的完整结果。
type Result struct {
	Inventory domain.Inventory
	System    SystemInfo
	Warnings  []string // 非致命问题（解析降级、跳过行等），如实上报
}

// Collector 执行一次只读资产采集。
type Collector struct {
	Runner   Runner // 命令执行器，注入模拟器用于测试
	OSPath   string // 默认 /etc/os-release
	Now      func() time.Time
	ReadFile func(string) ([]byte, error)
}

// New 返回使用真实执行器的采集器。
func New() *Collector {
	return &Collector{
		Runner:   ExecRunner{},
		OSPath:   OSReleasePath,
		Now:      func() time.Time { return time.Now().UTC() },
		ReadFile: os.ReadFile,
	}
}

// Collect 采集系统事实与软件包清单，产出可入库的 Inventory 快照。
//
// 只读约束：只执行查询命令与读文件；绝不刷新软件源、安装卸载或改配置。
// 未登记发行版返回 ExitUnsupported 错误（含已识别事实于 System 中），
// 不得用 ID_LIKE/NAME 模糊匹配伪装支持。
func (c *Collector) Collect(ctx context.Context) (*Result, error) {
	if c.Runner == nil || c.ReadFile == nil || c.Now == nil {
		return nil, apperr.New(exitcode.Error, "inventory.collect", "采集器未完整初始化")
	}
	osPath := c.OSPath
	if osPath == "" {
		osPath = OSReleasePath
	}

	osRelease, err := c.ReadFile(osPath)
	if err != nil {
		return nil, apperr.Wrap(exitcode.Error, "inventory.collect",
			"读取 "+osPath+" 失败", err)
	}
	unameM, err := c.Runner.Run(ctx, "uname", "-m")
	if err != nil {
		return nil, err
	}
	unameR, err := c.Runner.Run(ctx, "uname", "-r")
	if err != nil {
		return nil, err
	}

	sys, err := DetectSystem(osRelease, string(unameM), string(unameR))
	if err != nil {
		return nil, err
	}
	if sys.Unsupported {
		return &Result{System: sys}, apperr.Newf(exitcode.Unsupported, "inventory.collect",
			"未登记发行版 %q（ID_LIKE=%v），仅支持 docs/support-matrix.md 中列出的发行版",
			sys.OSID, sys.IDLike)
	}

	pkgs, warns, err := collectPackages(ctx, c.Runner, sys.Manager)
	if err != nil {
		return nil, err
	}
	for i := range pkgs {
		pkgs[i].EntryHash = pkgs[i].ComputeEntryHash()
	}

	kf := mapKernel(sys, pkgs)

	inv := domain.Inventory{
		DistroID:       sys.DistroID,
		Release:        sys.Release,
		Codename:       sys.Codename,
		Arch:           sys.Arch,
		KernelRunning:  sys.Kernel,
		KernelPackage:  kf.Package,
		KernelVersion:  kf.PackageVerRaw,
		KernelEvidence: kf.Evidence,
		Packages:       pkgs,
		CollectedAt:    c.Now(),
	}
	if err := inv.Validate(); err != nil {
		return nil, apperr.Wrap(exitcode.Error, "inventory.collect", "采集结果未通过校验", err)
	}
	inv.Hash = inv.ComputeHash()

	return &Result{
		Inventory: inv,
		System:    sys,
		Warnings:  warns,
	}, nil
}
