package app

import (
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/inventory"
)

// inventorySchemaVersion 是 inventory --json 输出的结构版本号。
// 与数据库 schema 版本解耦：JSON 协议可独立演进。
// 变更规则（见 docs/cli.md §3.1）：
//   - 新增可选字段：向后兼容，可不递增（但本轮 saved_inventory_id 属 v1 首次冻结前新增，故直接定版为 2）。
//   - 新增必填字段 / 字段改名 / 删除字段 / 类型变更：必须递增。
const inventorySchemaVersion = 2

// inventoryJSON 是 CLI inventory --json 的对外契约。
//
// 独立于 domain 模型：domain 结构体不定义 JSON tag，其字段名与 Go 默认
// 序列化（PascalCase）不构成稳定协议。这里用显式 snake_case tag 固定字段名、
// 顺序（struct 声明顺序即输出顺序）与空值语义，避免下游解析受内部模型重构影响。
type inventoryJSON struct {
	SchemaVersion    int             `json:"schema_version"`
	CollectedAt      string          `json:"collected_at"`                 // UTC RFC3339
	SavedInventoryID *int64          `json:"saved_inventory_id,omitempty"` // 仅 --save 时有值
	Distro           inventoryDistro `json:"distro"`
	Kernel           inventoryKernel `json:"kernel"`
	Packages         []inventoryPkg  `json:"packages"`
	Hash             string          `json:"hash"`
	Warnings         []string        `json:"warnings"`
}

// inventoryDistro 是发行版坐标。
type inventoryDistro struct {
	ID       string `json:"id"`    // domain.DistroID 规范值
	OSID     string `json:"os_id"` // /etc/os-release 的 ID 原值
	Name     string `json:"name"`
	Release  string `json:"release"`
	Codename string `json:"codename"`
	Arch     string `json:"arch"`
	Manager  string `json:"manager"`
}

// inventoryKernel 是内核相关信息，仅含可证明的事实。
type inventoryKernel struct {
	Running  string `json:"running"`  // uname -r 原值
	Package  string `json:"package"`  // 精确证据映射的包名，否则空
	Version  string `json:"version"`  // 该包版本，否则空
	Evidence string `json:"evidence"` // 映射依据，Package 为空时也为空
}

// inventoryPkg 是单个已安装包。版本原始串无损保留。
type inventoryPkg struct {
	Kind          string `json:"kind"` // 恒为 "binary"
	Name          string `json:"name"`
	Arch          string `json:"arch"`
	Version       string `json:"version"`        // 原始版本串，逐字保留
	SourceName    string `json:"source_name"`    // 源码包桥接名；不可证明时为空
	SourceVersion string `json:"source_version"` // 源码包版本；不可证明时为空
	Manager       string `json:"manager"`
	OriginChannel string `json:"origin_channel"` // 可证明来源，否则 "unknown"
	Vendor        string `json:"vendor"`
	InstallTime   string `json:"install_time"` // UTC RFC3339；未知时为空串
	EntryHash     string `json:"entry_hash"`
}

// buildInventoryJSON 把采集结果转换为稳定 JSON 契约。
// savedID 非 nil 时写入 saved_inventory_id（仅在 --save 时）。
// 空切片统一为 []（非 null），空字符串显式输出 ""，时间为 UTC RFC3339。
func buildInventoryJSON(r *inventory.Result, savedID *int64) inventoryJSON {
	inv := r.Inventory

	distro := inventoryDistro{
		ID:       string(inv.DistroID),
		OSID:     r.System.OSID,
		Name:     r.System.Name,
		Release:  inv.Release,
		Codename: inv.Codename,
		Arch:     canonicalArchOrKeep(inv.Arch),
		Manager:  string(r.System.Manager),
	}

	kernel := inventoryKernel{
		Running:  inv.KernelRunning,
		Package:  inv.KernelPackage,
		Version:  inv.KernelVersion,
		Evidence: inv.KernelEvidence,
	}

	pkgs := make([]inventoryPkg, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		pkgs = append(pkgs, inventoryPkg{
			Kind:          string(p.Ref.Kind),
			Name:          p.Ref.Name,
			Arch:          canonicalArchOrKeep(p.Ref.Arch),
			Version:       p.Ref.Version.String(),
			SourceName:    p.SourceName,
			SourceVersion: sourceVersionString(p.SourceVersion),
			Manager:       string(p.Manager),
			OriginChannel: p.OriginChannel,
			Vendor:        p.Vendor,
			InstallTime:   formatTime(p.InstallTime),
			EntryHash:     p.EntryHash,
		})
	}

	warnings := r.Warnings
	if warnings == nil {
		warnings = []string{}
	}

	return inventoryJSON{
		SchemaVersion:    inventorySchemaVersion,
		CollectedAt:      formatTime(inv.CollectedAt),
		SavedInventoryID: savedID,
		Distro:           distro,
		Kernel:           kernel,
		Packages:         pkgs,
		Hash:             inv.Hash,
		Warnings:         warnings,
	}
}

// sourceVersionString 返回源码包版本原始串；未解析时返回空串。
func sourceVersionString(v *domain.Version) string {
	if v == nil {
		return ""
	}
	return v.String()
}

// canonicalArchOrKeep 输出规范化架构名；无法识别的架构保留原值，不丢信息。
// 领域模型 PackageRef.Arch / Inventory.Arch 保存原始标识（dpkg=amd64、rpm=x86_64），
// CLI JSON 对外统一规范化名（x86_64→amd64、aarch64→arm64），供下游稳定匹配。
func canonicalArchOrKeep(s string) string {
	if c, ok := domain.CanonicalArch(s); ok {
		return c
	}
	return s
}

// formatTime 输出 UTC RFC3339；零值返回空串（表达"未知"而非伪造时间）。
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
