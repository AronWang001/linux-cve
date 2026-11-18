package domain

import "time"

// Family 是包管理体系族，决定版本比较规则与包管理器实现。
type Family string

const (
	FamilyDebian  Family = "debian"  // dpkg / apt
	FamilyRPM     Family = "rpm"     // rpm / dnf / yum / zypper
	FamilySUSE    Family = "suse"    // rpm + zypper，版本比较与 RHEL 系有差异
	FamilyAlpine  Family = "alpine"  // apk
	FamilyArch    Family = "arch"    // pacman
	FamilyUnknown Family = "unknown" // 未识别，禁止任何自动修复
)

// DistroID 是发行版稳定标识，取值与 /etc/os-release 的 ID 对齐。
type DistroID string

const (
	DistroDebian     DistroID = "debian"
	DistroUbuntu     DistroID = "ubuntu"
	DistroRHEL       DistroID = "rhel"
	DistroRocky      DistroID = "rocky"
	DistroAlmaLinux  DistroID = "almalinux"
	DistroOracle     DistroID = "ol"
	DistroAmazon     DistroID = "amzn"
	DistroSLES       DistroID = "sles"
	DistroOpenSUSE   DistroID = "opensuse-leap"
	DistroAlpine     DistroID = "alpine"
	DistroArch       DistroID = "arch"
	DistroFedora     DistroID = "fedora"
	DistroCloudLinux DistroID = "cloudlinux"
)

// distroFamilies 同时充当「已登记发行版」白名单。
// 未登记的发行版一律视为未知，不得进入自动修复流程。
var distroFamilies = map[DistroID]Family{
	DistroDebian:     FamilyDebian,
	DistroUbuntu:     FamilyDebian,
	DistroRHEL:       FamilyRPM,
	DistroRocky:      FamilyRPM,
	DistroAlmaLinux:  FamilyRPM,
	DistroOracle:     FamilyRPM,
	DistroAmazon:     FamilyRPM,
	DistroFedora:     FamilyRPM,
	DistroCloudLinux: FamilyRPM,
	DistroSLES:       FamilySUSE,
	DistroOpenSUSE:   FamilySUSE,
	DistroAlpine:     FamilyAlpine,
	DistroArch:       FamilyArch,
}

// Valid 判断发行版是否已登记。
func (d DistroID) Valid() bool {
	_, ok := distroFamilies[d]
	return ok
}

// Family 返回所属包管理体系；未登记返回 FamilyUnknown。
func (d DistroID) Family() Family {
	if f, ok := distroFamilies[d]; ok {
		return f
	}
	return FamilyUnknown
}

// LifecycleState 是发行版 release 的生命周期状态。
// legacy / eol 一律不开放自动修复（见 docs/support-matrix.md §2）。
type LifecycleState string

const (
	LifecycleActive  LifecycleState = "active"
	LifecycleLegacy  LifecycleState = "legacy"
	LifecycleEOL     LifecycleState = "eol"
	LifecycleUnknown LifecycleState = "unknown"
)

// Valid 判断生命周期取值是否合法。
func (l LifecycleState) Valid() bool {
	switch l {
	case LifecycleActive, LifecycleLegacy, LifecycleEOL, LifecycleUnknown:
		return true
	}
	return false
}

// Release 是「发行版 + 版本」的精确坐标。
// 漏洞判定与版本比较必须锚定到此坐标，禁止跨 release 比较。
type Release struct {
	ID        string // 形如 debian:12 / ubuntu:24.04 / amzn:2023
	Distro    DistroID
	Version   string // 12 / 24.04 / 2023
	Codename  string // bookworm / noble / 空
	Lifecycle LifecycleState
	EOLDate   *time.Time // 结束支持日期，未知为 nil
}

// SupportsAutoFix 判断该 release 是否允许自动修复。
// 只有 active 生命周期才可能通过后续闸门。
func (r Release) SupportsAutoFix() bool {
	return r.Distro.Valid() && r.Lifecycle == LifecycleActive
}

// Validate 校验 release 坐标的完整性。
func (r Release) Validate() error {
	if r.ID == "" {
		return domainErr("release.id 不能为空")
	}
	if !r.Distro.Valid() {
		return domainErr("未登记的发行版: %q", r.Distro)
	}
	if r.Version == "" {
		return domainErr("release.version 不能为空")
	}
	if !r.Lifecycle.Valid() {
		return domainErr("非法的生命周期状态: %q", r.Lifecycle)
	}
	return nil
}
