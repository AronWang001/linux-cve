// Package version 实现 Linux 包管理器的原生版本比较规则。
//
// 硬约束：
//  1. 禁止用 Go 字符串比较（<、>）替代包管理器版本比较；
//  2. 比较器必须显式指定包管理器类型，不同管理器之间禁止直接比较；
//  3. 原始版本串无损保留（domain.Version.Raw），解析只做结构化拆分；
//  4. 非法版本返回明确错误，不得猜测比较结果。
//
// 算法忠实移植自各上游实现（见 docs/phase2-report.md 的参考来源）：
//   - Debian：dpkg lib/dpkg/version.c 的 verrevcmp / dpkg_version_compare
//   - RPM：rpm rpmio/rpmvercmp.cc 的 rpmvercmp（含 ~ 与 ^ 语义）+ EVR 拆分
//   - Alpine：apk-tools src/version.c 的 tokenizer 与 apk_version_compare
//   - Arch：pacman lib/libalpm/version.c 的 alpm_pkg_vercmp（保留旧 rpm 语义与怪癖）
package version

import (
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// Compare 按包管理器原生规则比较两个原始版本串，返回 -1 / 0 / 1。
// 管理器未知或版本非法时返回错误，绝不给出猜测结果。
func Compare(manager domain.PackageManager, a, b string) (int, error) {
	switch manager {
	case domain.ManagerDPKG:
		return CompareDebian(a, b)
	case domain.ManagerRPM:
		return CompareRPM(a, b)
	case domain.ManagerAPK:
		return CompareAPK(a, b)
	case domain.ManagerPacman:
		return ComparePacman(a, b)
	default:
		return 0, apperr.Newf(exitcode.Error, "version.compare",
			"未知包管理器 %q，禁止版本比较", manager)
	}
}

// Parse 按包管理器原生语法解析版本串，Raw 逐字保留。
func Parse(manager domain.PackageManager, raw string) (domain.Version, error) {
	switch manager {
	case domain.ManagerDPKG:
		return ParseDebian(raw)
	case domain.ManagerRPM:
		return ParseRPM(raw)
	case domain.ManagerAPK:
		return ParseAPK(raw)
	case domain.ManagerPacman:
		return ParsePacman(raw)
	default:
		return domain.Version{}, apperr.Newf(exitcode.Error, "version.parse",
			"未知包管理器 %q，禁止版本解析", manager)
	}
}

// versionErr 统一构造版本包错误。
func versionErr(component, format string, args ...any) error {
	return apperr.Newf(exitcode.Error, "version."+component, format, args...)
}

// normalize 把任意三态比较结果归一到 -1 / 0 / 1。
func normalize(r int) int {
	switch {
	case r < 0:
		return -1
	case r > 0:
		return 1
	default:
		return 0
	}
}

// isDigit / isAlpha / isAlnum 仅接受 ASCII，与上游 C 实现的
// isdigit / isalpha（C locale）保持一致，不使用 Unicode 类别。
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

// byteAt 返回索引处字节，越界返回 0（对应 C 字符串的 '\0'）。
func byteAt(s string, i int) byte {
	if i < 0 || i >= len(s) {
		return 0
	}
	return s[i]
}

// trimLeadingZeros 去掉数字串前导零（用于「按位数比较」的上游规则）。
func trimLeadingZeros(s string) string {
	i := 0
	for i < len(s) && s[i] == '0' {
		i++
	}
	return s[i:]
}

// hasSpace 判断串中是否含空白字符（各管理器版本串均不允许）。
func hasSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' {
			return true
		}
	}
	return false
}
