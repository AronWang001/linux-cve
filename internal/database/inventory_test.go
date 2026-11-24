package database

import (
	"context"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// sampleInventory 构造一个合法快照（含内核映射证据）。
func sampleInventory() *domain.Inventory {
	return &domain.Inventory{
		DistroID:       domain.DistroDebian,
		Release:        "12",
		Codename:       "bookworm",
		Arch:           "x86_64",
		KernelRunning:  "6.1.0-37-amd64",
		KernelPackage:  "linux-image-6.1.0-37-amd64",
		KernelVersion:  "6.1.140-1",
		KernelEvidence: "包名与 linux-image-<uname -r> 精确一致",
		Packages: []domain.InstalledPackage{
			{
				Ref: domain.PackageRef{
					Kind:    domain.PackageKindBinary,
					Name:    "bash",
					Arch:    "amd64",
					Version: domain.Version{Raw: "5.2.15-2+b7", Upstream: "5.2.15", Release: "2+b7"},
				},
				SourceName:    "bash",
				Manager:       domain.ManagerDPKG,
				OriginChannel: domain.ChannelUnknown,
			},
			{
				Ref: domain.PackageRef{
					Kind:    domain.PackageKindBinary,
					Name:    "libc6",
					Arch:    "amd64",
					Version: domain.Version{Raw: "2.36-9", Epoch: 0, Upstream: "2.36", Release: "9"},
				},
				SourceName:    "glibc",
				Manager:       domain.ManagerDPKG,
				OriginChannel: domain.ChannelUnknown,
				InstallTime:   time.Date(2024, 5, 14, 9, 21, 33, 0, time.UTC),
			},
		},
		CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestMigrate0002Upgrade(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)

	n, err := d.Migrate(ctx)
	if err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	want := wantMigrationCount(t)
	if n != want {
		t.Errorf("空库应应用 %d 个迁移（含 0001+0002），实际 %d", want, n)
	}
	st, err := d.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.SchemaVersion != want {
		t.Errorf("schema 版本应为 %d，实际 %d", want, st.SchemaVersion)
	}
	if len(st.Pending) != 0 {
		t.Errorf("不应有 pending: %+v", st.Pending)
	}

	// 0002 三张表存在
	for _, tbl := range []string{"inventories", "inventory_packages", "kernel_state"} {
		if ok, err := d.hasTable(ctx, tbl); err != nil || !ok {
			t.Errorf("表 %s 应存在 (ok=%v err=%v)", tbl, ok, err)
		}
	}

	// 幂等：重复迁移 0 条
	n2, err := d.Migrate(ctx)
	if err != nil || n2 != 0 {
		t.Errorf("重复迁移应幂等，实际 n=%d err=%v", n2, err)
	}
}

func TestSaveInventoryRoundtrip(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	inv := sampleInventory()
	inv.Hash = inv.ComputeHash()
	id, err := d.SaveInventory(ctx, inv)
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if id <= 0 {
		t.Fatalf("快照 ID 非法: %d", id)
	}

	var pkgCount int
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM inventory_packages WHERE inventory_id = ?`, id).Scan(&pkgCount); err != nil {
		t.Fatal(err)
	}
	if pkgCount != 2 {
		t.Errorf("应存 2 个包，实际 %d", pkgCount)
	}

	var kernelPkg, evidence string
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT kernel_package, mapping_evidence FROM kernel_state WHERE inventory_id = ?`, id).
		Scan(&kernelPkg, &evidence); err != nil {
		t.Fatal(err)
	}
	if kernelPkg != "linux-image-6.1.0-37-amd64" || evidence == "" {
		t.Errorf("内核状态异常: pkg=%q evidence=%q", kernelPkg, evidence)
	}

	ov, err := d.InventoryOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Inventories != 1 || ov.Packages != 2 {
		t.Errorf("概览异常: %+v", ov)
	}
}

func TestInventoryPackagesFK(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// 不存在的 inventory_id 必须被外键拒绝
	_, err := d.SQL().ExecContext(ctx, `
		INSERT INTO inventory_packages
		  (inventory_id, package_kind, name, arch, version_raw, manager, origin_channel)
		VALUES (999, 'binary', 'x', 'amd64', '1.0', 'dpkg', 'unknown')`)
	if err == nil {
		t.Error("悬空 inventory_id 必须被外键拒绝")
	}
}

func TestInventoryCascadeDelete(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	inv := sampleInventory()
	id, err := d.SaveInventory(ctx, inv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SQL().ExecContext(ctx, `DELETE FROM inventories WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM inventory_packages WHERE inventory_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("级联删除应清掉包记录，剩余 %d", n)
	}
	if err := d.SQL().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kernel_state WHERE inventory_id = ?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("级联删除应清掉内核状态，剩余 %d", n)
	}
}

func TestInventoryPackageUnique(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	inv := sampleInventory()
	id, err := d.SaveInventory(ctx, inv)
	if err != nil {
		t.Fatal(err)
	}
	// 同快照同身份重复必须拒绝
	_, err = d.SQL().ExecContext(ctx, `
		INSERT INTO inventory_packages
		  (inventory_id, package_kind, name, arch, version_raw, manager, origin_channel)
		VALUES (?, 'binary', 'bash', 'amd64', '1.0', 'dpkg', 'unknown')`, id)
	if err == nil {
		t.Error("重复包身份必须被 UNIQUE 拒绝")
	}
}

func TestSaveInventoryRollback(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// 用临时触发器让第二个包写入时失败，制造「事务中途出错」，
	// 验证快照行与已写入的包一起整体回滚。
	if _, err := d.SQL().ExecContext(ctx, `
		CREATE TRIGGER force_fail BEFORE INSERT ON inventory_packages
		WHEN NEW.name = 'libc6'
		BEGIN SELECT RAISE(ABORT, 'forced failure'); END`); err != nil {
		t.Fatal(err)
	}
	inv := sampleInventory()
	if _, err := d.SaveInventory(ctx, inv); err == nil {
		t.Fatal("触发器强制失败时保存必须报错")
	}
	// 快照与包都不得留残余 —— 事务整体回滚
	ov, err := d.InventoryOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Inventories != 0 || ov.Packages != 0 {
		t.Errorf("失败保存不得留残余: %+v", ov)
	}
}

func TestSaveInventoryRejectsInvalid(t *testing.T) {
	ctx := context.Background()
	d := newTestDB(t)
	if _, err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	inv := sampleInventory()
	inv.Packages[0].Manager = "weird-manager" // domain 校验先行拒绝
	if _, err := d.SaveInventory(ctx, inv); err == nil {
		t.Error("非法 manager 必须在入库前被拒绝")
	}
	ov, err := d.InventoryOverview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ov.Inventories != 0 {
		t.Error("被拒绝的保存不得写入任何行")
	}
}
