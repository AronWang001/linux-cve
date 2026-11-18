package version

import (
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// Debian 版本比较：忠实移植 dpkg lib/dpkg/version.c（Ian Jackson / Guillem Jover）。
//
// 版本格式（deb-version(5) / Debian Policy 5.6.12）：
//
//	[epoch:]upstream_version[-debian_revision]
//
// 切分规则（Policy 原文 "break the version number apart at the last hyphen"）：
//   - 在**最后一个**连字符处切 upstream 与 revision；
//   - 无连字符 → revision 缺失，比较时等价于 "0"；
//   - upstream 允许 A-Za-z0-9 . + - ~；revision 允许 A-Za-z0-9 + . ~（不含 -）。
//
// 语义要点：
//   - 缺失 epoch 视为 0；
//   - '~' 排序早于一切（含空串），回移版本 6.12.113-1~deb12u1 < 6.12.113-1；
//   - 数字段去前导零后按「位数优先，再逐位」比较；
//   - 字母排序早于非字母非数字字符。

// ParseDebian 解析 Debian 版本串，Raw 逐字保留。
func ParseDebian(raw string) (domain.Version, error) {
	if raw == "" {
		return domain.Version{}, versionErr("debian", "版本串为空")
	}
	if hasSpace(raw) {
		return domain.Version{}, versionErr("debian", "版本串含空白字符: %q", raw)
	}

	rest := raw
	epoch := 0
	if i := strings.Index(rest, ":"); i >= 0 {
		ep := rest[:i]
		if ep == "" {
			return domain.Version{}, versionErr("debian", "epoch 为空: %q", raw)
		}
		for j := 0; j < len(ep); j++ {
			if !isDigit(ep[j]) {
				return domain.Version{}, versionErr("debian", "epoch 非数字: %q", raw)
			}
		}
		v, err := parseDecInt(ep)
		if err != nil {
			return domain.Version{}, versionErr("debian", "epoch 溢出: %q", raw)
		}
		epoch = v
		rest = rest[i+1:]
	}

	upstream, revision := rest, ""
	if i := strings.LastIndex(rest, "-"); i >= 0 {
		upstream = rest[:i]
		revision = rest[i+1:]
		if revision == "" {
			return domain.Version{}, versionErr("debian", "revision 为空: %q", raw)
		}
		if !validDebianRevision(revision) {
			return domain.Version{}, versionErr("debian", "revision 含非法字符: %q", raw)
		}
	}
	if upstream == "" {
		return domain.Version{}, versionErr("debian", "upstream 为空: %q", raw)
	}
	if !validDebianUpstream(upstream) {
		return domain.Version{}, versionErr("debian", "upstream 含非法字符: %q", raw)
	}

	return domain.Version{
		Raw:      raw,
		Epoch:    epoch,
		Upstream: upstream,
		Release:  revision,
	}, nil
}

// validDebianUpstream 校验 upstream 字符集（Policy 5.6.12：A-Za-z0-9 . + - ~）。
func validDebianUpstream(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlnum(c) || c == '.' || c == '+' || c == '-' || c == '~' {
			continue
		}
		return false
	}
	return true
}

// validDebianRevision 校验 revision 字符集（A-Za-z0-9 + . ~，不含 -）。
func validDebianRevision(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlnum(c) || c == '+' || c == '.' || c == '~' {
			continue
		}
		return false
	}
	return true
}

// parseDecInt 解析十进制非负整数，溢出报错。
func parseDecInt(s string) (int, error) {
	v := 0
	for i := 0; i < len(s); i++ {
		d := int(s[i] - '0')
		if v > (int(^uint(0)>>1)-d)/10 {
			return 0, versionErr("debian", "整数溢出: %q", s)
		}
		v = v*10 + d
	}
	return v, nil
}

// CompareDebian 按 dpkg 规则比较两个 Debian 版本串，返回 -1 / 0 / 1。
func CompareDebian(a, b string) (int, error) {
	va, err := ParseDebian(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseDebian(b)
	if err != nil {
		return 0, err
	}
	return CompareDebianVersion(va, vb), nil
}

// CompareDebianVersion 比较已解析的 Debian 版本（epoch → upstream → revision）。
func CompareDebianVersion(a, b domain.Version) int {
	if a.Epoch != b.Epoch {
		if a.Epoch > b.Epoch {
			return 1
		}
		return -1
	}
	if r := verrevcmp(a.Upstream, b.Upstream); r != 0 {
		return normalize(r)
	}
	return normalize(verrevcmp(a.Release, b.Release))
}

// debOrder 是 dpkg 的 order()：digit→0、alpha→字符本身、'~'→-1、
// 其他非零字符→c+256、串尾('\0')→0。
func debOrder(c byte) int {
	switch {
	case isDigit(c):
		return 0
	case isAlpha(c):
		return int(c)
	case c == '~':
		return -1
	case c != 0:
		return int(c) + 256
	default:
		return 0
	}
}

// verrevcmp 是 dpkg 的核心比较器，逐字符推进两个串：
// 非数字段按 order 权重比；数字段去前导零后按长度与逐位比。
// 空串与 "0" 等价（缺失 revision 等价 revision 0 的语义基础）。
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0

		// 非数字游程：任一侧存在非数字字符就继续（串尾的 order=0 参与比较）
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac := debOrder(byteAt(a, i))
			bc := debOrder(byteAt(b, j))
			if ac != bc {
				return ac - bc
			}
			// 与 C 一致双指针推进；此前 ac==bc 可证不会越过串尾
			if i < len(a) {
				i++
			}
			if j < len(b) {
				j++
			}
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for i < len(a) && j < len(b) && isDigit(a[i]) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return firstDiff
		}
	}
	return 0
}
