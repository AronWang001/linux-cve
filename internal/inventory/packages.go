package inventory

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/apperr"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/exitcode"
	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/version"
)

// 各包管理器的采集命令（只读查询，固定参数，无 Shell 拼接）。
// 命令格式参考各工具 man page 与上游源码（见 docs/phase2-report.md）。
const (
	// dpkg：Status 用于过滤「已安装」；Source 原始字段为空即桥接失败。
	dpkgQueryFormat = "${binary:Package}\t${Version}\t${Architecture}\t${Source}\t${source:Version}\t${Vendor}\t${Status}\n"

	// rpm：EPOCHNUM 为 (none) 时视作 0；SOURCERPM 为 (none) 即桥接失败。
	rpmQueryFormat = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\t%{INSTALLTIME}\n"
)

// collectDebian 采集 dpkg 系（Debian / Ubuntu）已安装包。
func collectDebian(ctx context.Context, r Runner) ([]domain.InstalledPackage, []string, error) {
	out, err := r.Run(ctx, "dpkg-query", "-W", "-f="+dpkgQueryFormat)
	if err != nil {
		return nil, nil, err
	}
	var pkgs []domain.InstalledPackage
	var warns []string
	for i, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 7 {
			warns = append(warns, fmt.Sprintf("dpkg 第 %d 行字段数 %d ≠ 7，跳过", i+1, len(f)))
			continue
		}
		// 仅保留完全安装的包（want/eflag/status 三段，status == installed）
		sf := strings.Fields(f[6])
		if len(sf) != 3 || sf[2] != "installed" {
			continue
		}

		name := f[0]
		arch := strings.TrimSpace(f[2])
		// multiarch 限定名 "libc6:amd64" 去掉限定符；限定符必须等于架构字段才剥离
		if k := strings.LastIndex(name, ":"); k > 0 && name[k+1:] == arch {
			name = name[:k]
		}

		ver, vwarn := parseVersionOrKeep(domain.ManagerDPKG, f[1])
		if vwarn != "" {
			warns = append(warns, name+": "+vwarn)
		}

		// Source 原始字段："name (version)" 或 "name" 或空。
		// 空 = 桥接失败（禁止用包名前缀猜测替代）。
		srcName, srcVer := parseDebianSource(f[3], f[4])

		p := domain.InstalledPackage{
			Ref: domain.PackageRef{
				Kind:    domain.PackageKindBinary,
				Name:    name,
				Arch:    arch,
				Version: ver,
			},
			SourceName:    srcName,
			Manager:       domain.ManagerDPKG,
			OriginChannel: domain.ChannelUnknown, // dpkg-query 无法证明安装来源
			Vendor:        strings.TrimSpace(f[5]),
		}
		if srcVer != "" {
			sv, _ := parseVersionOrKeep(domain.ManagerDPKG, srcVer)
			p.SourceVersion = &sv
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, warns, nil
}

// parseDebianSource 解析 dpkg Source 字段："name (version)" / "name" / ""。
// 返回源码包名与源码包版本；无法证明时均为空。
func parseDebianSource(raw, derivedVer string) (name, srcVer string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if i := strings.Index(raw, "("); i >= 0 && strings.HasSuffix(raw, ")") {
		name = strings.TrimSpace(raw[:i])
		srcVer = strings.TrimSpace(raw[i+1 : len(raw)-1])
	} else {
		name = raw
		srcVer = strings.TrimSpace(derivedVer) // dpkg 给出的 source:Version，可为空
	}
	return name, srcVer
}

// collectRPM 采集 RPM 系（RHEL/兼容系/SUSE）已安装包。
func collectRPM(ctx context.Context, r Runner) ([]domain.InstalledPackage, []string, error) {
	out, err := r.Run(ctx, "rpm", "-qa", "--qf", rpmQueryFormat)
	if err != nil {
		return nil, nil, err
	}
	var pkgs []domain.InstalledPackage
	var warns []string
	for i, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 8 {
			warns = append(warns, fmt.Sprintf("rpm 第 %d 行字段数 %d ≠ 8，跳过", i+1, len(f)))
			continue
		}
		name := strings.TrimSpace(f[0])
		if name == "" {
			warns = append(warns, fmt.Sprintf("rpm 第 %d 行缺包名，跳过", i+1))
			continue
		}

		epoch := 0
		if e := strings.TrimSpace(f[1]); e != "" && e != "(none)" && e != "(null)" {
			v, err := strconv.Atoi(e)
			if err != nil {
				warns = append(warns, name+": epoch 非法 "+e)
				continue
			}
			epoch = v
		}
		up, rel := strings.TrimSpace(f[2]), strings.TrimSpace(f[3])
		rawEVR := joinEVR(epoch, up, rel)

		ver, vwarn := parseVersionOrKeep(domain.ManagerRPM, rawEVR)
		if vwarn != "" {
			warns = append(warns, name+": "+vwarn)
		}

		// SOURCERPM："name-ver-rel.src.rpm"；rpm 禁止 ver/rel 含 '-'，
		// 故从尾部切两刀即得源码包名。"(none)" = 桥接失败。
		srcName := ""
		if s := strings.TrimSpace(f[5]); s != "" && s != "(none)" && s != "(null)" {
			if n, ok := parseSourceRPM(s); ok {
				srcName = n
			} else {
				warns = append(warns, name+": SOURCERPM 无法解析 "+s)
			}
		}

		installTime := time.Time{}
		if ts := strings.TrimSpace(f[7]); ts != "" && ts != "0" && ts != "(none)" {
			if sec, err := strconv.ParseInt(ts, 10, 64); err == nil && sec > 0 {
				installTime = time.Unix(sec, 0).UTC()
			}
		}

		vendor := strings.TrimSpace(f[6])
		if vendor == "(none)" || vendor == "(null)" {
			vendor = ""
		}

		p := domain.InstalledPackage{
			Ref: domain.PackageRef{
				Kind:    domain.PackageKindBinary,
				Name:    name,
				Arch:    strings.TrimSpace(f[4]),
				Version: ver,
			},
			SourceName:    srcName,
			Manager:       domain.ManagerRPM,
			OriginChannel: domain.ChannelUnknown, // rpm -qa 无法证明安装来源
			Vendor:        vendor,
			InstallTime:   installTime,
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, warns, nil
}

// parseSourceRPM 从 "name-ver-rel.src.rpm" 解析源码包名。
// rpm 禁止 version/release 含 '-'，从尾部两刀切分是可靠解析而非猜测。
func parseSourceRPM(s string) (string, bool) {
	orig := s
	s = strings.TrimSuffix(s, ".src.rpm")
	s = strings.TrimSuffix(s, ".nosrc.rpm")
	if s == orig || s == "" {
		return "", false // 无 src/nosrc 后缀，不认定
	}
	i2 := strings.LastIndex(s, "-")
	if i2 <= 0 {
		return "", false
	}
	i1 := strings.LastIndex(s[:i2], "-")
	if i1 <= 0 {
		return "", false
	}
	name := s[:i1]
	return name, name != ""
}

// joinEVR 组装 rpm 原始 EVR 串（epoch>0 时带 epoch 前缀）。
func joinEVR(epoch int, up, rel string) string {
	s := ""
	if epoch > 0 {
		s = strconv.Itoa(epoch) + ":"
	}
	s += up
	if rel != "" {
		s += "-" + rel
	}
	return s
}

// collectAPK 采集 Alpine 已安装包。
//
// 两条只读查询互补（依据 apk-tools src/app_list.c）：
//   - apk list --manifest        → "name version"（空格分隔，无切分歧义）
//   - apk list --installed -v    → "name-version arch {origin} (license) [installed]"
//
// 第二条只提供架构与 {origin}，以 name-version 全串与第一条关联；
// 第一条缺关联时保底仍有 name/version，不丢包。
func collectAPK(ctx context.Context, r Runner) ([]domain.InstalledPackage, []string, error) {
	manifest, err := r.Run(ctx, "apk", "list", "--manifest")
	if err != nil {
		return nil, nil, err
	}
	detail, err := r.Run(ctx, "apk", "list", "--installed", "-v")
	if err != nil {
		return nil, nil, err
	}

	// name-version 全串 → 架构与来源
	type aux struct{ arch, origin string }
	auxByFullName := make(map[string]aux)
	var warns []string
	for _, line := range strings.Split(string(detail), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.Contains(f[0], "-") {
			continue // 描述行 / 异常行
		}
		a := aux{arch: f[1]}
		for _, tok := range f[2:] {
			if strings.HasPrefix(tok, "{") && strings.HasSuffix(tok, "}") {
				a.origin = strings.Trim(tok, "{}")
				break
			}
		}
		auxByFullName[f[0]] = a
	}

	var pkgs []domain.InstalledPackage
	for i, line := range strings.Split(string(manifest), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			warns = append(warns, fmt.Sprintf("apk manifest 第 %d 行字段数 %d ≠ 2，跳过", i+1, len(f)))
			continue
		}
		name, rawVer := f[0], f[1]

		ver, vwarn := parseVersionOrKeep(domain.ManagerAPK, rawVer)
		if vwarn != "" {
			warns = append(warns, name+": "+vwarn)
		}

		arch, origin := "", ""
		if a, ok := auxByFullName[name+"-"+rawVer]; ok {
			arch, origin = a.arch, a.origin
		} else {
			warns = append(warns, name+": 未关联到 -v 明细，缺架构/来源")
			continue // 架构是包身份必填项，缺证据不能入库
		}

		p := domain.InstalledPackage{
			Ref: domain.PackageRef{
				Kind:    domain.PackageKindBinary,
				Name:    name,
				Arch:    arch,
				Version: ver,
			},
			// {origin} 是 apk 自身输出的源包归属（缺 origin 时 apk 打印包名），属工具证据
			SourceName:    origin,
			Manager:       domain.ManagerAPK,
			OriginChannel: domain.ChannelUnknown,
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, warns, nil
}

// collectPacman 采集 Arch 已安装包（pacman -Qi 全量输出按块解析）。
//
// 注意：pacman -Qi 不输出 pkgbase，源码包名无可靠证据 → SourceName 留空（桥接失败）。
func collectPacman(ctx context.Context, r Runner) ([]domain.InstalledPackage, []string, error) {
	out, err := r.Run(ctx, "pacman", "-Qi")
	if err != nil {
		return nil, nil, err
	}
	var pkgs []domain.InstalledPackage
	var warns []string

	fields := map[string]string{}
	flush := func() {
		if len(fields) == 0 {
			return
		}
		name := fields["Name"]
		rawVer := fields["Version"]
		if name == "" || rawVer == "" {
			warns = append(warns, "pacman 块缺 Name/Version，跳过")
			fields = map[string]string{}
			return
		}
		ver, vwarn := parseVersionOrKeep(domain.ManagerPacman, rawVer)
		if vwarn != "" {
			warns = append(warns, name+": "+vwarn)
		}
		installTime := time.Time{}
		if s := fields["Install Date"]; s != "" {
			if t, err := time.Parse("Mon 02 Jan 2006 03:04:05 PM MST", s); err == nil {
				installTime = t.UTC()
			}
		}
		pkgs = append(pkgs, domain.InstalledPackage{
			Ref: domain.PackageRef{
				Kind:    domain.PackageKindBinary,
				Name:    name,
				Arch:    fields["Architecture"],
				Version: ver,
			},
			SourceName:    "", // 无 pkgbase 证据，禁止猜测
			Manager:       domain.ManagerPacman,
			OriginChannel: domain.ChannelUnknown,
			Vendor:        fields["Packager"],
			InstallTime:   installTime,
		})
		fields = map[string]string{}
	}

	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		// 字段行形如 "Name            : bash"，以首个 " : " 切分
		if i := strings.Index(line, " : "); i > 0 {
			key := strings.TrimSpace(line[:i])
			fields[key] = strings.TrimSpace(line[i+3:])
		}
		// 无分隔符的折行忽略（pacman -Qi 不折行；容忍异常输入）
	}
	flush()
	return pkgs, warns, nil
}

// parseVersionOrKeep 解析失败时保留 Raw-only 版本并返回警告，
// 不丢包、不猜测拆分（比较阶段会把 Raw-only 落 UNKNOWN）。
func parseVersionOrKeep(manager domain.PackageManager, raw string) (domain.Version, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return domain.Version{}, "版本串为空"
	}
	v, err := version.Parse(manager, raw)
	if err != nil {
		return domain.Version{Raw: raw}, "版本解析失败，保留原始串: " + err.Error()
	}
	return v, ""
}

// collectPackages 按包管理器分发采集。
func collectPackages(ctx context.Context, r Runner, manager domain.PackageManager) ([]domain.InstalledPackage, []string, error) {
	switch manager {
	case domain.ManagerDPKG:
		return collectDebian(ctx, r)
	case domain.ManagerRPM:
		return collectRPM(ctx, r)
	case domain.ManagerAPK:
		return collectAPK(ctx, r)
	case domain.ManagerPacman:
		return collectPacman(ctx, r)
	default:
		return nil, nil, apperr.Newf(exitcode.Unsupported, "inventory.packages",
			"包管理器 %q 无采集实现", manager)
	}
}
