package version

import (
	"strings"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// Arch / libalpm 版本比较：忠实移植 pacman lib/libalpm/version.c
// （alpm_pkg_vercmp + 其内嵌的旧版 rpmvercmp 与 parseEVR）。
//
// 注意：libalpm 刻意保留 rpm 4.8 时代的语义，与现代 rpm 存在真实差异，
// 必须按本实现而不是 rpm.go 的规则比较：
//   1. 无 '~' / '^' 特殊排序（两者只当普通分隔符跳过）；
//   2. 段间分隔符长度不同时直接按长度判（短者旧）；
//   3. 尾部残留 alpha 段的版本更旧（1.0a < 1.0，现代 rpm 相反）；
//   4. release 仅在两侧都存在时才比较（1.0-1 == 1.0，libalpm 既有怪癖）。
//
// EVR 格式：[epoch:]version[-release]，release 取最后一个连字符之后。
// epoch 缺失视为 0（parseEVR 注释：different from RPM - always assume 0 epoch）。

// ParsePacman 解析 Arch 版本串，Raw 逐字保留。
func ParsePacman(raw string) (domain.Version, error) {
	if raw == "" {
		return domain.Version{}, versionErr("pacman", "版本串为空")
	}
	if hasSpace(raw) {
		return domain.Version{}, versionErr("pacman", "版本串含空白字符: %q", raw)
	}
	// Arch 打包规则：pkgver 不得含 '/'；':' 只允许作 epoch 分隔符一次
	if strings.Contains(raw, "/") {
		return domain.Version{}, versionErr("pacman", "版本串含非法字符 '/': %q", raw)
	}

	rest := raw
	epoch := 0
	// parseEVR：跳过前导数字，若其后是 ':' 则为 epoch
	i := 0
	for i < len(rest) && isDigit(rest[i]) {
		i++
	}
	if i < len(rest) && rest[i] == ':' {
		ep := rest[:i]
		if ep == "" {
			// libalpm 把空 epoch 视为 0，但显式拒绝更安全：":1.0" 不是合法打包版本
			return domain.Version{}, versionErr("pacman", "epoch 为空: %q", raw)
		}
		v, err := parseDecInt(ep)
		if err != nil {
			return domain.Version{}, versionErr("pacman", "epoch 溢出: %q", raw)
		}
		epoch = v
		rest = rest[i+1:]
		if strings.Contains(rest, ":") {
			return domain.Version{}, versionErr("pacman", "版本串含多余 ':': %q", raw)
		}
	} else if strings.Contains(rest, ":") {
		return domain.Version{}, versionErr("pacman", "版本串含多余 ':': %q", raw)
	}

	upstream, release := rest, ""
	if k := strings.LastIndex(rest, "-"); k >= 0 {
		upstream = rest[:k]
		release = rest[k+1:]
		if upstream == "" {
			return domain.Version{}, versionErr("pacman", "pkgver 为空: %q", raw)
		}
	}
	if upstream == "" {
		return domain.Version{}, versionErr("pacman", "pkgver 为空: %q", raw)
	}

	return domain.Version{
		Raw:      raw,
		Epoch:    epoch,
		Upstream: upstream,
		Release:  release,
	}, nil
}

// ComparePacman 按 libalpm alpm_pkg_vercmp 规则比较两个版本串，返回 -1 / 0 / 1。
func ComparePacman(a, b string) (int, error) {
	if a == "" || b == "" {
		return 0, versionErr("pacman", "版本串为空")
	}
	if hasSpace(a) || hasSpace(b) {
		return 0, versionErr("pacman", "版本串含空白字符")
	}
	va, err := ParsePacman(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParsePacman(b)
	if err != nil {
		return 0, err
	}
	return ComparePacmanVersion(va, vb), nil
}

// ComparePacmanVersion 比较已解析的 Arch 版本。
// 保留 libalpm 怪癖：release 仅当两侧都非空才参与比较。
func ComparePacmanVersion(a, b domain.Version) int {
	// alpm 用 rpmvercmp 比较 epoch 字符串（"0" 与 "0" 恒等，语义与数值比较一致）
	if r := alpmRpmvercmp(epochString(a.Epoch), epochString(b.Epoch)); r != 0 {
		return r
	}
	if r := alpmRpmvercmp(a.Upstream, b.Upstream); r != 0 {
		return r
	}
	if a.Release != "" && b.Release != "" {
		return alpmRpmvercmp(a.Release, b.Release)
	}
	// libalpm 既有行为：任一侧缺 release 则视为相等（真实差异，勿"修复"）
	return 0
}

// epochString 把数值 epoch 渲染为 alpm parseEVR 产出的十进制串。
func epochString(e int) string {
	if e == 0 {
		return "0"
	}
	// 负数不可能（解析已拒绝），这里只处理非负
	var buf [20]byte
	i := len(buf)
	for e > 0 {
		i--
		buf[i] = byte('0' + e%10)
		e /= 10
	}
	return string(buf[i:])
}

// alpmRpmvercmp 是 libalpm 内嵌的旧版 rpmvercmp（rpm 4.8 语义），返回 -1 / 0 / 1。
func alpmRpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	ptr1, ptr2 := 0, 0 // 上一段结束位置，用于比较段间分隔符长度

	for one < len(a) && two < len(b) {
		for one < len(a) && !isAlnum(a[one]) {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) {
			two++
		}
		if !(one < len(a) && two < len(b)) {
			break
		}

		// 旧 rpm 怪癖：段间分隔符长度不同则直接按长度判（短者旧）
		if (one - ptr1) != (two - ptr2) {
			if (one - ptr1) < (two - ptr2) {
				return -1
			}
			return 1
		}
		ptr1, ptr2 = one, two

		segEnd1, segEnd2 := one, two
		isnum := false
		if isDigit(a[segEnd1]) {
			for segEnd1 < len(a) && isDigit(a[segEnd1]) {
				segEnd1++
			}
			for segEnd2 < len(b) && isDigit(b[segEnd2]) {
				segEnd2++
			}
			isnum = true
		} else {
			for segEnd1 < len(a) && isAlpha(a[segEnd1]) {
				segEnd1++
			}
			for segEnd2 < len(b) && isAlpha(b[segEnd2]) {
				segEnd2++
			}
		}

		if one == segEnd1 {
			return -1 // 与上游一致：不可能路径的任意约定
		}
		if two == segEnd2 {
			if isnum {
				return 1
			}
			return -1
		}

		seg1 := a[one:segEnd1]
		seg2 := b[two:segEnd2]
		if isnum {
			s1 := trimLeadingZeros(seg1)
			s2 := trimLeadingZeros(seg2)
			if len(s1) > len(s2) {
				return 1
			}
			if len(s2) > len(s1) {
				return -1
			}
			seg1, seg2 = s1, s2
		}
		if seg1 != seg2 {
			if seg1 < seg2 {
				return -1
			}
			return 1
		}
		one, two = segEnd1, segEnd2
	}

	if one >= len(a) && two >= len(b) {
		return 0
	}

	// 终局判定（上游原注释的怪异逻辑，必须保留）：
	// 若 a 而 b 非 alpha，或 a 以 alpha 开头 → a 旧；否则 a 新。
	oneAlpha := one < len(a) && isAlpha(a[one])
	twoAlpha := two < len(b) && isAlpha(b[two])
	if (one >= len(a) && !twoAlpha) || oneAlpha {
		return -1
	}
	return 1
}
