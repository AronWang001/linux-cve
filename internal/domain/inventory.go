package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"
)

// Inventory 是一次资产采集的完整快照。
// Hash 用于执行前的一致性复核，防止用过期扫描结果去改机器。
type Inventory struct {
	DistroID      DistroID
	Release       string
	Codename      string
	Arch          string
	KernelRunning string
	KernelPackage string // 运行内核对应的软件包名
	KernelVersion string // 该包的版本
	Packages      []InstalledPackage
	CollectedAt   time.Time
	Hash          string
}

// Validate 校验快照完整性。
func (inv Inventory) Validate() error {
	if !inv.DistroID.Valid() {
		return domainErr("快照缺少合法发行版: %q", inv.DistroID)
	}
	if inv.Release == "" {
		return domainErr("快照缺少 release")
	}
	if inv.Arch == "" {
		return domainErr("快照缺少 CPU 架构")
	}
	seen := make(map[string]struct{}, len(inv.Packages))
	for _, p := range inv.Packages {
		if err := p.Validate(); err != nil {
			return err
		}
		key := p.Ref.IdentityKey()
		if _, dup := seen[key]; dup {
			return domainErr("快照中存在重复包: %s", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// ComputeHash 计算与顺序无关的快照哈希。
//
// 只纳入影响判定的字段：包身份、版本、来源包名、渠道。
// 采集时间不参与哈希，否则每次采集都会得到不同结果，失去比对意义。
func (inv Inventory) ComputeHash() string {
	lines := make([]string, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		lines = append(lines, strings.Join([]string{
			string(p.Ref.Kind),
			p.Ref.Name,
			p.Ref.Arch,
			p.Ref.Version.String(),
			p.SourceName,
			p.Channel,
		}, "|"))
	}
	sort.Strings(lines)

	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l))
		h.Write([]byte{'\n'})
	}
	// 发行版坐标也纳入，避免跨发行版误用快照
	h.Write([]byte(string(inv.DistroID) + "|" + inv.Release + "|" + inv.Arch))
	return hex.EncodeToString(h.Sum(nil))
}

// FindPackage 按包名与架构查找已安装包，找不到返回 false。
func (inv Inventory) FindPackage(name, arch string) (InstalledPackage, bool) {
	for _, p := range inv.Packages {
		if p.Ref.Name == name && p.Ref.Arch == arch {
			return p, true
		}
	}
	return InstalledPackage{}, false
}
