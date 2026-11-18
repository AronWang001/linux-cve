package domain

import (
	"fmt"
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

// ArchAny 表示公告未限定架构。
const ArchAny = "any"

// ArchAll 表示与架构无关的包（dpkg 的 all、rpm 的 noarch）。
const ArchAll = "all"

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
type InstalledPackage struct {
	Ref           PackageRef // Kind 固定为 binary
	SourceName    string
	SourceVersion *Version
	Manager       PackageManager
	Channel       string // 来源渠道：bookworm-security / noble-updates / amzn2023-core / main / core
	Vendor        string
	InstallTime   time.Time // 零值表示未知
	EntryHash     string    // 该包记录的内容哈希，用于资产快照一致性比对
}

// Validate 校验安装包记录。
func (p InstalledPackage) Validate() error {
	if p.Ref.Kind != PackageKindBinary {
		return domainErr("安装包 %q 的类型必须为 binary，实际为 %q", p.Ref.Name, p.Ref.Kind)
	}
	if err := p.Ref.Validate(); err != nil {
		return err
	}
	if !p.Manager.Valid() {
		return domainErr("包 %q 的包管理器非法: %q", p.Ref.Name, p.Manager)
	}
	return nil
}

// ArchMatches 判断公告架构声明是否适用于某个已安装架构。
//
//	公告 "any"     → 适用所有架构
//	公告 == 安装包 → 适用
//	安装包为 all   → 适用（dpkg all / rpm noarch 与架构无关）
func ArchMatches(declared, installed string) bool {
	if declared == "" || declared == ArchAny {
		return true
	}
	if declared == installed {
		return true
	}
	if installed == ArchAll || installed == "noarch" {
		return true
	}
	return false
}
