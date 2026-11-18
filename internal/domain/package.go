package domain

import (
	"fmt"
	"strings"
	"time"
)

// PackageKind 区分源码包与二进制包。
// 发行版公告粒度不同（Debian 按源码包，RHEL OVAL 按二进制包），
// 入库时必须保留各自的 Kind，不在导入时强行统一。
type PackageKind string

const (
	PackageKindSource PackageKind = "source"
	PackageKindBinary PackageKind = "binary"
)

// Valid 判断 Kind 取值是否合法。
func (k PackageKind) Valid() bool {
	return k == PackageKindSource || k == PackageKindBinary
}

// ParsePackageKind 解析并校验 Kind 字符串。
func ParsePackageKind(s string) (PackageKind, error) {
	k := PackageKind(s)
	if !k.Valid() {
		return "", domainErr("非法包类型: %q", s)
	}
	return k, nil
}

// PackageManager 是包管理器类型。
type PackageManager string

const (
	ManagerDPKG   PackageManager = "dpkg"
	ManagerRPM    PackageManager = "rpm"
	ManagerAPK    PackageManager = "apk"
	ManagerPacman PackageManager = "pacman"
	ManagerNone   PackageManager = "none"
)

// Valid 判断包管理器是否已知。
func (m PackageManager) Valid() bool {
	switch m {
	case ManagerDPKG, ManagerRPM, ManagerAPK, ManagerPacman, ManagerNone:
		return true
	}
	return false
}

// ArchAny 是架构通配声明：公告未限定架构时使用，是唯一可匹配一切已知架构的值。
const ArchAny = "any"

// ArchAll 表示与架构无关的包（dpkg 的 all、rpm 的 noarch）。
const ArchAll = "all"

// ChannelUnknown 是来源渠道的哨兵值：无法用本机证据证明已安装包来自哪个仓库时使用。
// 禁止猜测渠道。渠道不明不影响「是否受影响」判定，但修复计划必须另行核实候选仓库。
const ChannelUnknown = "unknown"

// PackageRef 是包身份与版本组成的坐标，匹配与计划都以它为唯一键。
type PackageRef struct {
	Kind    PackageKind
	Name    string
	Arch    string
	Version Version
}

// IdentityKey 返回不含版本的身份键，用于去重与快照比对。
func (r PackageRef) IdentityKey() string {
	return fmt.Sprintf("%s:%s:%s", r.Kind, r.Name, r.Arch)
}

// String 返回可读表示，含版本。
func (r PackageRef) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", r.Kind, r.Name, r.Arch, r.Version.String())
}

// Validate 校验包坐标的必填项。
func (r PackageRef) Validate() error {
	if !r.Kind.Valid() {
		return domainErr("非法的包类型: %q", r.Kind)
	}
	if r.Name == "" {
		return domainErr("包名不能为空")
	}
	if r.Arch == "" {
		return domainErr("包 %q 缺少架构", r.Name)
	}
	return nil
}

// InstalledPackage 是本机实际安装的二进制包。
//
// SourceName 是源码包公告与二进制包之间的唯一桥接字段；
// 为空表示桥接失败，相关判定必须落 UNKNOWN，禁止用包名前缀猜测替代。
//
// 来源渠道字段只表达「可证明的已安装包来源」，与以下三者严格区分：
//  1. 已安装包信息（本结构体其余字段）；
//  2. 当前启用的软件源（阶段 2 资产采集的仓库清单）；
//  3. 软件源提供的候选修复版本（planner 查询，不在本结构体内）；
//  4. 可证明的已安装包来源（OriginChannel，唯一允许写渠道结论的地方）。
//
// 采集器（dpkg/rpm/apk/pacman 查询输出）通常无法证明安装来源，
// 无法证明时必须写 ChannelUnknown，不得猜测。
type InstalledPackage struct {
	Ref            PackageRef // Kind 固定为 binary
	SourceName     string
	SourceVersion  *Version
	Manager        PackageManager
	OriginChannel  string // 来源渠道：bookworm-security / amzn2023-core / ... 或 ChannelUnknown
	OriginEvidence string // 来源证明；OriginChannel != ChannelUnknown 时必填
	Vendor         string
	InstallTime    time.Time // 零值表示未知
	EntryHash      string    // 该包记录的内容哈希，用于资产快照一致性比对
}

// Validate 校验安装包记录。
func (p InstalledPackage) Validate() error {
	if p.Ref.Kind != PackageKindBinary {
		return domainErr("安装包 %q 的类型必须为 binary，实际为 %q", p.Ref.Name, p.Ref.Kind)
	}
	if err := p.Ref.Validate(); err != nil {
		return err
	}
	if p.Ref.Version.IsZero() {
		return domainErr("安装包 %q 缺少版本", p.Ref.Name)
	}
	if !p.Manager.Valid() {
		return domainErr("包 %q 的包管理器非法: %q", p.Ref.Name, p.Manager)
	}
	if p.OriginChannel == "" {
		return domainErr("安装包 %q 缺少来源渠道（不可证明时应为 %q）", p.Ref.Name, ChannelUnknown)
	}
	if p.OriginChannel != ChannelUnknown && p.OriginEvidence == "" {
		return domainErr("安装包 %q 声明来源渠道 %q 但缺少来源证明", p.Ref.Name, p.OriginChannel)
	}
	return nil
}

// archIndependent 把各发行版的「架构无关」写法归一到 ArchAll。
var archIndependent = map[string]string{
	"all":    ArchAll,
	"noarch": ArchAll,
}

// archCanonical 是原生架构的显式登记表，只有入表的标识才参与匹配。
// 别名对（amd64≡x86_64、arm64≡aarch64）归一到规范名，其余登记项自映射；
// 未登记的标识一律不匹配（即使同名），禁止未知架构自动放行。
// PackageRef.Arch 始终逐字保留原始标识，本表只用于匹配。
var archCanonical = map[string]string{
	"amd64":   "amd64",
	"x86_64":  "amd64",
	"arm64":   "arm64",
	"aarch64": "arm64",
	"armhf":   "armhf",
	"armel":   "armel",
	"i386":    "i386",
	"i686":    "i686",
	"x86":     "x86",
	"ppc64le": "ppc64le",
	"s390x":   "s390x",
	"riscv64": "riscv64",
	"src":     "src",
}

// CanonicalArch 归一化架构标识：
//
//	"any"          → (ArchAny, true)
//	all/noarch     → (ArchAll, true)
//	已登记原生架构  → (规范名, true)，amd64≡x86_64、arm64≡aarch64
//	空串/未登记     → ("", false)
func CanonicalArch(s string) (string, bool) {
	k := strings.ToLower(strings.TrimSpace(s))
	if k == "" {
		return "", false
	}
	if k == ArchAny {
		return ArchAny, true
	}
	if v, ok := archIndependent[k]; ok {
		return v, true
	}
	if v, ok := archCanonical[k]; ok {
		return v, true
	}
	return "", false
}

// IsArchIndependent 判断是否为架构无关声明（all / noarch）。
func IsArchIndependent(s string) bool {
	c, ok := CanonicalArch(s)
	return ok && c == ArchAll
}

// ArchMatches 判断公告架构声明是否适用于某个已安装架构。
//
//	公告 "any"        → 通配，适用一切已登记安装架构（含 all/noarch）
//	公告 all/noarch   → 仅适用架构无关的包
//	公告为已登记原生架构 → 仅适用同一规范架构（amd64≡x86_64、arm64≡aarch64）
//	任一侧为空或未登记   → 不匹配（禁止未知架构自动匹配，即使两侧同名）
//
// 例：公告 "amd64" 不匹配安装包 "all"；公告 "noarch" 不匹配安装包 "amd64"。
func ArchMatches(declared, installed string) bool {
	d, ok := CanonicalArch(declared)
	if !ok {
		return false
	}
	i, ok := CanonicalArch(installed)
	if !ok {
		return false
	}
	if d == ArchAny {
		return true
	}
	return d == i
}
