package inventory

import "github.com/AronWang001/linux-cve/internal/domain"

// KernelFacts 是内核相关事实，只含证据充分的映射，不含任何修复/重启结论。
type KernelFacts struct {
	Running       string // uname -r
	Package       string // 映射到的软件包名，无证据为空
	PackageVerRaw string // 该包版本原始串，无证据为空
	Evidence      string // 映射依据说明，报告原样输出
}

// mapKernel 仅接受精确证据的内核包映射：
//
//   - dpkg 系：包名 linux-image-<uname -r> 必须精确存在（Debian/Ubuntu 内核打包命名约定）；
//   - rpm 系：kernel / kernel-core 的 "<version>-<release>.<arch>" 必须精确等于 uname -r；
//   - 其余（apk/pacman 或映射不上）：留空，只记录事实，不猜测。
func mapKernel(sys SystemInfo, pkgs []domain.InstalledPackage) KernelFacts {
	kf := KernelFacts{Running: sys.Kernel}
	if sys.Kernel == "" {
		return kf
	}

	switch sys.Manager {
	case domain.ManagerDPKG:
		want := "linux-image-" + sys.Kernel
		for _, p := range pkgs {
			if p.Ref.Name == want {
				kf.Package = p.Ref.Name
				kf.PackageVerRaw = p.Ref.Version.String()
				kf.Evidence = "包名与 linux-image-<uname -r> 精确一致"
				return kf
			}
		}
	case domain.ManagerRPM:
		for _, p := range pkgs {
			if p.Ref.Name != "kernel" && p.Ref.Name != "kernel-core" {
				continue
			}
			// RHEL 系 uname -r 形如 5.14.0-427.13.1.el9_4.x86_64，
			// 即 <version>-<release>.<arch> 的精确拼接
			candidate := p.Ref.Version.String() + "." + p.Ref.Arch
			if candidate == sys.Kernel {
				kf.Package = p.Ref.Name
				kf.PackageVerRaw = p.Ref.Version.String()
				kf.Evidence = "<version>-<release>.<arch> 与 uname -r 精确一致"
				return kf
			}
		}
	}
	// apk / pacman 无精确映射证据（uname -r 与包版本不同构），保持留空
	return kf
}
