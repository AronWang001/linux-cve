package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/buildinfo"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// SaveInventory 在单事务内持久化一次资产快照，返回快照行 ID。
//
// 与操作系统只读采集严格分离：本函数只写数据库，不做任何系统调用；
// 调用方（CLI --save）必须先完成采集再显式落库。
func (d *DB) SaveInventory(ctx context.Context, inv *domain.Inventory) (int64, error) {
	if err := inv.Validate(); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "快照未通过校验", err)
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "开启事务失败", err)
	}
	defer func() { _ = tx.Rollback() }()

	hash := inv.Hash
	if hash == "" {
		hash = inv.ComputeHash()
	}

	res, err := tx.ExecContext(ctx, `
		INSERT INTO inventories
		  (distro_id, release, codename, arch, kernel_running,
		   package_manager, package_count, collected_at, hash, collector_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		string(inv.DistroID), inv.Release, inv.Codename, inv.Arch, inv.KernelRunning,
		managerOfInventory(inv), len(inv.Packages),
		inv.CollectedAt.UTC().Format(time.RFC3339), hash, buildinfo.Version)
	if err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "写入快照失败", err)
	}
	invID, err := res.LastInsertId()
	if err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "读取快照 ID 失败", err)
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO inventory_packages
		  (inventory_id, package_kind, name, arch,
		   version_raw, version_epoch, version_upstream, version_release,
		   source_name, source_version_raw, manager,
		   origin_channel, origin_evidence, vendor, install_time, entry_hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "预编译包插入失败", err)
	}
	defer func() { _ = stmt.Close() }()

	for _, p := range inv.Packages {
		srcVer := ""
		if p.SourceVersion != nil {
			srcVer = p.SourceVersion.String()
		}
		var installTime any
		if !p.InstallTime.IsZero() {
			installTime = p.InstallTime.UTC().Format(time.RFC3339)
		}
		if _, err := stmt.ExecContext(ctx,
			invID, string(p.Ref.Kind), p.Ref.Name, p.Ref.Arch,
			p.Ref.Version.Raw, p.Ref.Version.Epoch, p.Ref.Version.Upstream, p.Ref.Version.Release,
			p.SourceName, srcVer, string(p.Manager),
			p.OriginChannel, p.OriginEvidence, p.Vendor, installTime, p.EntryHash,
		); err != nil {
			return 0, apperr.Wrap(exitcode.Error, "database.save_inventory",
				fmt.Sprintf("写入包 %s 失败", p.Ref.Name), err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO kernel_state
		  (inventory_id, running_version, kernel_package, package_version_raw, mapping_evidence)
		VALUES (?, ?, ?, ?, ?)`,
		invID, inv.KernelRunning, inv.KernelPackage, inv.KernelVersion,
		inv.KernelEvidence,
	); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "写入内核状态失败", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, apperr.Wrap(exitcode.Error, "database.save_inventory", "提交事务失败", err)
	}
	return invID, nil
}

// InventoryStats 是快照的计数概览。
type InventoryStats struct {
	Inventories int
	Packages    int
}

// InventoryOverview 读取快照计数（只读）。
func (d *DB) InventoryOverview(ctx context.Context) (InventoryStats, error) {
	var st InventoryStats
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM inventories`).Scan(&st.Inventories); err != nil {
		if err == sql.ErrNoRows {
			return st, nil
		}
		return st, apperr.Wrap(exitcode.Error, "database.inventory_overview", "读取快照数失败", err)
	}
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM inventory_packages`).Scan(&st.Packages); err != nil {
		return st, apperr.Wrap(exitcode.Error, "database.inventory_overview", "读取包数失败", err)
	}
	return st, nil
}

// managerOfInventory 从包清单推导管理器（空清单时落 none）。
func managerOfInventory(inv *domain.Inventory) string {
	if len(inv.Packages) > 0 {
		return string(inv.Packages[0].Manager)
	}
	return string(domain.ManagerNone)
}
