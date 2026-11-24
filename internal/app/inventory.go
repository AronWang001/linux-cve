package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/inventory"
)

// collector 返回资产采集器；测试可注入合成夹具，默认真实采集。
func (e *env) collector() *inventory.Collector {
	if e.newCollector != nil {
		return e.newCollector()
	}
	return inventory.New()
}

// runInventory 执行资产采集并输出结果。
//
// 用法：linux-cve inventory [--json] [--save]
//
// 只读约束：采集阶段只执行查询命令，绝不刷新软件源或修改系统状态。
// 未登记发行版返回退出码 4（exitcode.Unsupported）。
func (e *env) runInventory(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON, save bool
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出采集结果")
	fs.BoolVar(&save, "save", false, "将采集结果持久化到数据库")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}

	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}

	c := e.collector()
	result, err := c.Collect(ctx)
	if err != nil {
		// 未登记发行版：结果中携带已识别事实，但命令以退出码 4 失败
		if code := apperr.CodeOf(err); code == exitcode.Unsupported {
			return code, err
		}
		return apperr.CodeOf(err), err
	}

	// --save 持久化到数据库
	var savedID *int64
	if save {
		d, err := database.Open(ctx, e.cfg.General.DBPath)
		if err != nil {
			return exitcode.Error, err
		}
		defer func() { _ = d.Close() }()

		invID, err := d.SaveInventory(ctx, &result.Inventory)
		if err != nil {
			return apperr.CodeOf(err), err
		}
		savedID = &invID
	}

	// 输出结果
	if asJSON {
		// 保存状态经 saved_inventory_id 字段表达，保证 stdout 始终是纯 JSON
		dto := buildInventoryJSON(result, savedID)
		b, err := json.MarshalIndent(dto, "", "  ")
		if err != nil {
			return exitcode.Error, apperr.Wrap(exitcode.Error, "inventory", "序列化采集结果失败", err)
		}
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}

	if savedID != nil {
		fmt.Fprintf(e.stdout, "inventory saved (id=%d)\n", *savedID)
	}

	// 人类可读文本输出
	e.printInventoryText(result)
	return exitcode.OK, nil
}

// printInventoryText 输出人类可读的资产摘要。
func (e *env) printInventoryText(result *inventory.Result) {
	inv := result.Inventory
	fmt.Fprintf(e.stdout, "distro       : %s\n", inv.DistroID)
	fmt.Fprintf(e.stdout, "release      : %s\n", inv.Release)
	if inv.Codename != "" {
		fmt.Fprintf(e.stdout, "codename     : %s\n", inv.Codename)
	}
	fmt.Fprintf(e.stdout, "arch         : %s\n", inv.Arch)
	fmt.Fprintf(e.stdout, "kernel       : %s\n", inv.KernelRunning)
	if inv.KernelPackage != "" {
		fmt.Fprintf(e.stdout, "kernel pkg   : %s (%s)\n", inv.KernelPackage, inv.KernelVersion)
	}
	fmt.Fprintf(e.stdout, "packages     : %d\n", len(inv.Packages))
	fmt.Fprintf(e.stdout, "collected at : %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(e.stdout, "hash         : %s\n", inv.Hash)

	if len(result.Warnings) > 0 {
		fmt.Fprintf(e.stdout, "\nwarnings:\n")
		for _, w := range result.Warnings {
			fmt.Fprintf(e.stdout, "  - %s\n", w)
		}
	}
}
