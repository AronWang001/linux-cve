package inventory

import (
	"strings"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
)

// SystemInfo 是只读识别出的系统事实，不含任何判定结论。
type SystemInfo struct {
	DistroID    domain.DistroID // 未登记发行版为空
	OSID        string          // /etc/os-release 的 ID 原值
	Name        string          // NAME
	Release     string          // VERSION_ID（必要时退化自 VERSION 的首词）
	Codename    string          // VERSION_CODENAME
	IDLike      []string        // ID_LIKE 原值，仅记录，禁止用于伪造支持状态
	Arch        string          // uname -m 原值
	Kernel      string          // uname -r 原值
	Manager     domain.PackageManager
	Unsupported bool // 发行版未登记：只读展示可以，判定与修复禁止
}

// ParseOSRelease 解析 /etc/os-release 内容（freedesktop 规范：KEY=VALUE，
// 值可带单/双引号；# 注释与空行忽略）。缺失字段返回空串，不报错。
func ParseOSRelease(data []byte) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		i := strings.Index(trimmed, "=")
		if i <= 0 {
			continue // 无等号或空键：忽略该行
		}
		key := trimmed[:i]
		val := trimmed[i+1:]
		// 允许键两侧空白（宽松但只影响解析，不影响取值语义）
		key = strings.TrimSpace(key)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			} else {
				// 未加引号的值去首尾空白（规范要求无空白，宽松容忍异常输入）
				val = strings.TrimSpace(val)
			}
		}
		out[key] = val
	}
	return out
}

// DetectSystem 从 os-release 与 uname 输出识别系统事实。
// osRelease 为 /etc/os-release 文件内容；arch/kernel 为 uname -m / uname -r 输出。
//
// 未登记发行版不报错，而是返回 Unsupported=true 的事实快照，
// 由调用方决定展示或拒绝（不得用 ID_LIKE / NAME 模糊匹配伪装支持）。
func DetectSystem(osRelease []byte, unameM, unameR string) (SystemInfo, error) {
	kv := ParseOSRelease(osRelease)
	info := SystemInfo{
		OSID:     strings.TrimSpace(kv["ID"]),
		Name:     strings.TrimSpace(kv["NAME"]),
		Codename: strings.TrimSpace(kv["VERSION_CODENAME"]),
		Arch:     strings.TrimSpace(unameM),
		Kernel:   strings.TrimSpace(unameR),
	}

	if like := strings.TrimSpace(kv["ID_LIKE"]); like != "" {
		info.IDLike = strings.Fields(like)
	}

	info.Release = strings.TrimSpace(kv["VERSION_ID"])
	if info.Release == "" {
		// 退化：取 VERSION 的首个空白分隔词（如 "12 (bookworm)" → "12"）
		if v := strings.TrimSpace(kv["VERSION"]); v != "" {
			fields := strings.Fields(v)
			if len(fields) > 0 {
				info.Release = fields[0]
			}
		}
	}

	if info.OSID == "" {
		return info, apperr.New(exitcode.Error, "inventory.system",
			"/etc/os-release 缺少 ID 字段，无法识别发行版")
	}

	did := domain.DistroID(info.OSID)
	if !did.Valid() {
		info.Unsupported = true
		info.Manager = domain.ManagerNone
		return info, nil
	}
	info.DistroID = did
	info.Manager = managerOf(did)

	if info.Release == "" {
		return info, apperr.Newf(exitcode.Error, "inventory.system",
			"发行版 %s 缺少 VERSION_ID/VERSION，无法确定 release", info.OSID)
	}
	if info.Arch == "" || info.Kernel == "" {
		return info, apperr.New(exitcode.Error, "inventory.system",
			"uname 输出缺失，无法确定架构或内核版本")
	}
	return info, nil
}

// managerOf 由发行版族确定包管理器。SUSE 族同样走 rpm 查询接口。
func managerOf(d domain.DistroID) domain.PackageManager {
	switch d.Family() {
	case domain.FamilyDebian:
		return domain.ManagerDPKG
	case domain.FamilyRPM, domain.FamilySUSE:
		return domain.ManagerRPM
	case domain.FamilyAlpine:
		return domain.ManagerAPK
	case domain.FamilyArch:
		return domain.ManagerPacman
	default:
		return domain.ManagerNone
	}
}
