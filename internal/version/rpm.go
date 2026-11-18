package version

import (
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// RPM 版本比较：忠实移植 rpm rpmio/rpmvercmp.cc（rpm-software-management/rpm master，
// 文件已由 .c 迁移为 .cc）。
//
// EVR 格式：[epoch:]version[-release]
//   - epoch 缺失视为 0；
//   - 在最后一个连字符处切 version 与 release（rpm 禁止二者含 '-'）；
//   - release 可缺失，比较时按空串处理（1.0 < 1.0-1 < 1.0-2 …）。
//
// rpmvercmp 语义要点：
//   - '~' 排序早于一切（含串尾）：1.0~rc1 < 1.0；
//   - '^' 排序晚于串尾、早于字母数字：1.0 < 1.0^git1 < 1.0.1；
//   - 数字段去前导零后按「位数优先，再逐位」比较；
//   - 数字段排序晚于字母段；尾部有剩余者胜（1.0 < 1.0.0）。

// ParseRPM 解析 RPM EVR 串，Raw 逐字保留。
func ParseRPM(raw string) (domain.Version, error) {
	if raw == "" {
		return domain.Version{}, versionErr("rpm", "版本串为空")
	}
	if hasSpace(raw) {
		return domain.Version{}, versionErr("rpm", "版本串含空白字符: %q", raw)
	}

	rest := raw
	epoch := 0
	if i := strings.Index(rest, ":"); i >= 0 {
		ep := rest[:i]
		if ep == "" {
			return domain.Version{}, versionErr("rpm", "epoch 为空: %q", raw)
		}
		for j := 0; j < len(ep); j++ {
			if !isDigit(ep[j]) {
				return domain.Version{}, versionErr("rpm", "epoch 非数字: %q", raw)
			}
		}
		v, err := parseDecInt(ep)
		if err != nil {
			return domain.Version{}, versionErr("rpm", "epoch 溢出: %q", raw)
		}
		epoch = v
		rest = rest[i+1:]
	}

	upstream, release := rest, ""
	if i := strings.LastIndex(rest, "-"); i >= 0 {
		upstream = rest[:i]
		release = rest[i+1:]
		if upstream == "" {
			return domain.Version{}, versionErr("rpm", "version 为空: %q", raw)
		}
		if release == "" {
			return domain.Version{}, versionErr("rpm", "release 为空: %q", raw)
		}
	} else if rest == "" {
		return domain.Version{}, versionErr("rpm", "version 为空: %q", raw)
	}

	return domain.Version{
		Raw:      raw,
		Epoch:    epoch,
		Upstream: upstream,
		Release:  release,
	}, nil
}

// CompareRPM 按 rpm EVR 规则比较两个版本串，返回 -1 / 0 / 1。
func CompareRPM(a, b string) (int, error) {
	va, err := ParseRPM(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseRPM(b)
	if err != nil {
		return 0, err
	}
	return CompareRPMVersion(va, vb), nil
}

// CompareRPMVersion 比较已解析的 RPM EVR（epoch → version → release）。
func CompareRPMVersion(a, b domain.Version) int {
	if a.Epoch != b.Epoch {
		if a.Epoch > b.Epoch {
			return 1
		}
		return -1
	}
	if r := rpmvercmp(a.Upstream, b.Upstream); r != 0 {
		return r
	}
	// 缺失 release 按空串比较（rpm 行为：1.0 < 1.0-1）
	return rpmvercmp(a.Release, b.Release)
}

// rpmvercmp 是 rpm 的段比较器（含 ~ 与 ^ 处理），返回 -1 / 0 / 1。
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	one, two := 0, 0
	for one < len(a) || two < len(b) {
		// 跳过非字母数字的分隔字符，但保留 ~ 与 ^ 交给专门分支
		for one < len(a) && !isAlnum(a[one]) && a[one] != '~' && a[one] != '^' {
			one++
		}
		for two < len(b) && !isAlnum(b[two]) && b[two] != '~' && b[two] != '^' {
			two++
		}

		ca := byteAt(a, one)
		cb := byteAt(b, two)

		// '~'：排序早于一切（含串尾）
		if ca == '~' || cb == '~' {
			if ca != '~' {
				return 1
			}
			if cb != '~' {
				return -1
			}
			one++
			two++
			continue
		}

		// '^'：排序晚于串尾、早于字母数字（1.0 < 1.0^git < 1.0.1）
		if ca == '^' || cb == '^' {
			if one >= len(a) {
				return -1
			}
			if two >= len(b) {
				return 1
			}
			if ca != '^' {
				return 1
			}
			if cb != '^' {
				return -1
			}
			one++
			two++
			continue
		}

		// 任一侧结束即停止抓段
		if !(one < len(a) && two < len(b)) {
			break
		}

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
		// 段类型不一致：数字段永远晚于字母段
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
	if one >= len(a) {
		return -1
	}
	return 1
}
