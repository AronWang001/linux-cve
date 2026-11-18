package domain

import "fmt"

// Version 表示一个发行版软件包版本。
//
// 只做结构化存储，不实现比较规则：
// 比较必须使用目标发行版的原生规则（dpkg / rpm / apk / pacman），
// 由 internal/version 在阶段 2 实现，避免用 SemVer 误判 Linux 包版本。
//
// 原始值无损保留是硬约束：Raw 逐字保存上游字符串，String() 优先返回 Raw，
// 解析器升级或拆分逻辑变更都不影响报告与审计的可回溯性。
// dpkg 的 epoch/tilde 回移（6.12.113-1~deb12u1）、rpm 的 EVR、
// apk 的 -rN 修订、pacman 的 pkgrel 一律以 Raw 为准，
// 禁止用 Go 字符串比较（<、>）替代包管理器版本比较。
type Version struct {
	Raw      string // 原始字符串，逐字保留，用于报告与审计
	Epoch    int    // dpkg / rpm 的 epoch，apk / pacman 为 0
	Upstream string // 上游版本部分
	Release  string // 发行修订部分（dpkg 的 -1~deb12u1 中的 1~deb12u1）
}

// String 优先返回原始串，保证报告与源数据一致。
func (v Version) String() string {
	if v.Raw != "" {
		return v.Raw
	}
	if v.Upstream == "" {
		return ""
	}
	if v.Epoch > 0 {
		if v.Release != "" {
			return fmt.Sprintf("%d:%s-%s", v.Epoch, v.Upstream, v.Release)
		}
		return fmt.Sprintf("%d:%s", v.Epoch, v.Upstream)
	}
	if v.Release != "" {
		return fmt.Sprintf("%s-%s", v.Upstream, v.Release)
	}
	return v.Upstream
}

// IsZero 判断版本是否为空。
func (v Version) IsZero() bool {
	return v.Raw == "" && v.Upstream == "" && v.Release == "" && v.Epoch == 0
}

// StructurallyEqual 比较结构化分量；两者均未解析时退化为原始串比较。
// 注意：这不是「版本是否更高」的判断，仅用于判重与快照比对。
func (v Version) StructurallyEqual(o Version) bool {
	if v.Upstream != "" && o.Upstream != "" {
		return v.Epoch == o.Epoch && v.Upstream == o.Upstream && v.Release == o.Release
	}
	return v.String() == o.String()
}

// domainErr 统一构造领域层错误，避免各处重复格式化。
func domainErr(format string, args ...any) error {
	return fmt.Errorf("domain: "+format, args...)
}
