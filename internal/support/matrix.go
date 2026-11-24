// Package support 是发行版支持矩阵的代码形态。
//
// 与 docs/support-matrix.md 一一对应：文档是给人看的验收口径，
// 这里是给程序用的判定口径。两者不一致时以文档为准并修代码。
//
// 设计约束：未登记的 release 一律视为 UNKNOWN，不得按「最新的那个」兜底。
// 不知道是否还在支持范围内的系统，既不能声称安全，也不能开放自动修复。
package support

import (
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// Entry 是一个 release 的支持声明。
type Entry struct {
	Distro   domain.DistroID
	Version  string
	Codename string
	// EOLDate 是厂商结束支持日期；零值表示尚未确定，按 unknown 处理。
	EOLDate time.Time
	// AutoFix 表示该 release 是否开放自动修复（首期只有 Debian 12/13）。
	AutoFix bool
	// Note 说明限制，直接进报告。
	Note string
}

// matrix 是已登记的支持矩阵。
//
// 日期取自各发行版官方生命周期公告，宁可比官方晚一天判 EOL，
// 也不能提前开放一个已经没人维护的系统的自动修复。
var matrix = []Entry{
	// Debian：LTS 结束日期见 https://wiki.debian.org/LTS
	{Distro: domain.DistroDebian, Version: "11", Codename: "bullseye",
		EOLDate: date(2026, 8, 31), Note: "LTS 已进入末期，仅检测"},
	{Distro: domain.DistroDebian, Version: "12", Codename: "bookworm",
		EOLDate: date(2028, 6, 30), AutoFix: true, Note: "首期自动修复目标"},
	{Distro: domain.DistroDebian, Version: "13", Codename: "trixie",
		EOLDate: date(2030, 6, 30), AutoFix: true, Note: "首期自动修复目标"},

	// Ubuntu：标准支持期结束即视为 legacy，ESM 不在本工具范围。
	{Distro: domain.DistroUbuntu, Version: "22.04", Codename: "jammy",
		EOLDate: date(2027, 6, 1), Note: "标准支持期内；ESM 不在覆盖范围"},
	{Distro: domain.DistroUbuntu, Version: "24.04", Codename: "noble",
		EOLDate: date(2029, 6, 1), Note: "标准支持期内；ESM 不在覆盖范围"},
	{Distro: domain.DistroUbuntu, Version: "24.10", Codename: "oracular",
		EOLDate: date(2025, 7, 1), Note: "非 LTS，生命周期仅 9 个月"},

	// Alpine：每个分支支持约 2 年。
	{Distro: domain.DistroAlpine, Version: "3.19", EOLDate: date(2025, 11, 1),
		Note: "secdb 覆盖，未收录不等于不受影响"},
	{Distro: domain.DistroAlpine, Version: "3.20", EOLDate: date(2026, 4, 1),
		Note: "secdb 覆盖，未收录不等于不受影响"},
	{Distro: domain.DistroAlpine, Version: "3.21", EOLDate: date(2026, 11, 1),
		Note: "secdb 覆盖，未收录不等于不受影响"},

	// 滚动发行版：没有 EOL 概念，但也永远不开放自动修复。
	{Distro: domain.DistroArch, Version: "rolling",
		Note: "滚动发行，仅检测；pacman 预演不可靠，不开放自动修复"},
}

// date 构造 UTC 日期，避免本地时区把 EOL 判定挪一天。
func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Lookup 按发行版与版本查表。
//
// 版本匹配先精确、再退化到主版本（Debian/Ubuntu 的补丁版本号不改变支持状态，
// 例如 VERSION_ID=12.5 仍属于 Debian 12）。
func Lookup(distro domain.DistroID, release string) (Entry, bool) {
	if release == "" {
		return Entry{}, false
	}
	for _, e := range matrix {
		if e.Distro == distro && e.Version == release {
			return e, true
		}
	}
	if major := majorOf(distro, release); major != release {
		for _, e := range matrix {
			if e.Distro == distro && e.Version == major {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// majorOf 取发行版的主版本号，仅对「补丁号不构成新 release」的发行版生效。
//
// Debian 的 12.5 与 RHEL 的 9.4 都属于 12 / 9 这条支持线；
// 而 Ubuntu 的 24.04、Alpine 的 3.20 本身就是 release 编号，
// 截断会把 24.04 误判成「Ubuntu 24」这种不存在的版本。
func majorOf(distro domain.DistroID, v string) string {
	switch distro {
	case domain.DistroDebian, domain.DistroRHEL, domain.DistroRocky,
		domain.DistroAlmaLinux, domain.DistroOracle, domain.DistroCloudLinux:
		if i := strings.IndexByte(v, '.'); i > 0 {
			return v[:i]
		}
	}
	return v
}

// Lifecycle 返回某 release 在当前时间的生命周期状态。
func Lifecycle(distro domain.DistroID, release string, now time.Time) domain.LifecycleState {
	e, ok := Lookup(distro, release)
	if !ok {
		return domain.LifecycleUnknown
	}
	if e.EOLDate.IsZero() {
		return domain.LifecycleUnknown
	}
	if now.After(e.EOLDate) {
		return domain.LifecycleEOL
	}
	return domain.LifecycleActive
}

// Release 返回领域层的 release 坐标。
func Release(distro domain.DistroID, release string, now time.Time) domain.Release {
	e, _ := Lookup(distro, release)
	r := domain.Release{
		ID:        string(distro) + ":" + release,
		Distro:    distro,
		Version:   release,
		Codename:  e.Codename,
		Lifecycle: Lifecycle(distro, release, now),
	}
	if !e.EOLDate.IsZero() {
		d := e.EOLDate
		r.EOLDate = &d
	}
	return r
}

// AutoFixAllowed 判断该 release 是否开放自动修复。
//
// 三个条件同时满足才为 true：矩阵显式开放、生命周期为 active、
// 发行版已登记。任何一项拿不准都返回 false。
func AutoFixAllowed(distro domain.DistroID, release string, now time.Time) bool {
	e, ok := Lookup(distro, release)
	if !ok {
		return false
	}
	if !e.AutoFix {
		return false
	}
	return Lifecycle(distro, release, now) == domain.LifecycleActive
}

// Note 返回该 release 的限制说明，未登记时给出明确提示。
func Note(distro domain.DistroID, release string) string {
	e, ok := Lookup(distro, release)
	if !ok {
		return "该发行版/版本未登记在支持矩阵中，仅做只读展示，不给出修复建议"
	}
	return e.Note
}

// Entries 返回矩阵副本，供 support 子命令与报告使用。
func Entries() []Entry {
	out := make([]Entry, len(matrix))
	copy(out, matrix)
	return out
}
