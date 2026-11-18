package domain

import (
	"testing"
	"time"
)

func mkPkg(name, version, source string) InstalledPackage {
	return InstalledPackage{
		Ref: PackageRef{
			Kind:    PackageKindBinary,
			Name:    name,
			Arch:    "amd64",
			Version: Version{Raw: version},
		},
		SourceName: source,
		Manager:    ManagerDPKG,
		Channel:    "bookworm-security",
	}
}

func TestInventoryValidate(t *testing.T) {
	inv := Inventory{
		DistroID: DistroDebian,
		Release:  "12",
		Arch:     "amd64",
		Packages: []InstalledPackage{
			mkPkg("openssl", "3.0.11-1~deb12u2", "openssl"),
			mkPkg("bash", "5.2.15-2", "bash"),
		},
	}
	if err := inv.Validate(); err != nil {
		t.Errorf("合法快照不应报错: %v", err)
	}

	dup := inv
	dup.Packages = append([]InstalledPackage{}, inv.Packages...)
	dup.Packages = append(dup.Packages, mkPkg("openssl", "3.0.11-1~deb12u2", "openssl"))
	if err := dup.Validate(); err == nil {
		t.Error("重复包应被拒绝")
	}

	bad := inv
	bad.Arch = ""
	if err := bad.Validate(); err == nil {
		t.Error("缺架构应被拒绝")
	}
}

// TestInventoryHashOrderIndependent 快照哈希必须与包顺序无关，
// 否则同一台机器两次采集会得到不同哈希，闸门永远不通过。
func TestInventoryHashOrderIndependent(t *testing.T) {
	a := Inventory{
		DistroID: DistroDebian, Release: "12", Arch: "amd64",
		Packages: []InstalledPackage{
			mkPkg("openssl", "3.0.11-1~deb12u2", "openssl"),
			mkPkg("bash", "5.2.15-2", "bash"),
			mkPkg("zlib1g", "1:1.2.13.dfsg-1", "zlib"),
		},
	}
	b := Inventory{
		DistroID: DistroDebian, Release: "12", Arch: "amd64",
		Packages: []InstalledPackage{
			mkPkg("zlib1g", "1:1.2.13.dfsg-1", "zlib"),
			mkPkg("openssl", "3.0.11-1~deb12u2", "openssl"),
			mkPkg("bash", "5.2.15-2", "bash"),
		},
	}
	if a.ComputeHash() != b.ComputeHash() {
		t.Error("包顺序不同不应影响快照哈希")
	}
}

// TestInventoryHashSensitive 影响判定的字段变化必须改变哈希。
func TestInventoryHashSensitive(t *testing.T) {
	base := Inventory{
		DistroID: DistroDebian, Release: "12", Arch: "amd64",
		Packages: []InstalledPackage{mkPkg("openssl", "3.0.11-1~deb12u2", "openssl")},
	}
	h := base.ComputeHash()

	changedVersion := base
	changedVersion.Packages = []InstalledPackage{mkPkg("openssl", "3.0.11-1~deb12u3", "openssl")}
	if changedVersion.ComputeHash() == h {
		t.Error("版本变化必须改变快照哈希")
	}

	changedRelease := base
	changedRelease.Release = "13"
	if changedRelease.ComputeHash() == h {
		t.Error("release 变化必须改变快照哈希")
	}

	changedArch := base
	changedArch.Arch = "arm64"
	if changedArch.ComputeHash() == h {
		t.Error("架构变化必须改变快照哈希")
	}

	// 采集时间不参与哈希：同一台机器重复采集应得到相同结果
	withTime := base
	withTime.CollectedAt = base.CollectedAt.Add(time.Hour)
	if withTime.ComputeHash() != h {
		t.Error("采集时间不应影响快照哈希")
	}
}

func TestFindPackage(t *testing.T) {
	inv := Inventory{Packages: []InstalledPackage{mkPkg("openssl", "3.0.11-1~deb12u2", "openssl")}}
	if p, ok := inv.FindPackage("openssl", "amd64"); !ok || p.Ref.Name != "openssl" {
		t.Error("应能找到已安装包")
	}
	if _, ok := inv.FindPackage("openssl", "arm64"); ok {
		t.Error("架构不匹配不应命中")
	}
}
