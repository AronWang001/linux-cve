#!/usr/bin/env bash
#
# lib/kernel.sh - 运行内核与已安装内核包之间的映射
#
# 统一输出格式（每行一个内核）：
#   <包名>\t<包版本/EVR>\t<标识>
# 其中「标识」用于匹配 uname -r 与 /boot 下的镜像文件：
#   debian -> 6.1.0-54-amd64      rpm  -> 6.1.189-236.400.amzn2023
#   alpine -> linux-lts           arch -> linux
#
# 只相信包数据库，不根据文件名猜测版本。

# ShellCheck 单文件分析看不到跨文件使用点：本文件产出的全局状态由
# fix.sh / lib/*.sh / adapters/*.sh 读取，故整体关闭「变量未使用」提示。
# shellcheck disable=SC2034

kernel_branch() {
    local value="$1"
    [[ ${value} =~ ^([0-9]+)\.([0-9]+) ]] || return 1
    printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# ---------------------------------------------------------------------------
# Debian / Ubuntu（dpkg）
# ---------------------------------------------------------------------------

# 查询某个内核 release 对应的 linux-image 软件包版本
query_kernel_package() {
    local rel="$1" fields="" st="" ver="" owner=""

    fields="$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "linux-image-${rel}" 2>/dev/null || true)"
    if [[ -n ${fields} ]]; then
        read -r st ver <<<"${fields}"
        if [[ ${st} == "ii" ]] && [[ -n ${ver} ]]; then
            printf '%s\n' "${ver%$'\r'}"
            return 0
        fi
    fi

    owner="$(dpkg -S "$(sysfile "/boot/vmlinuz-${rel}")" 2>/dev/null | head -n 1 || true)"
    if [[ -n ${owner} ]]; then
        owner="${owner%%:*}"
        ver="$(dpkg-query -W -f='${Version}' "${owner}" 2>/dev/null || true)"
        if [[ -n ${ver} ]]; then
            printf '%s\n' "${ver%$'\r'}"
            return 0
        fi
    fi
    return 1
}

# 列出状态为 ii 的具体内核镜像包，输出 "release<TAB>version"
list_installed_kernels() {
    local st="" pkg="" ver=""
    while read -r st pkg ver; do
        [[ ${st} == "ii" ]] || continue
        [[ ${pkg} == linux-image-[0-9]* ]] || continue
        case "${pkg}" in
            *-dbg | *-dbgsym | *-unsigned | *-signed-template) continue ;;
        esac
        [[ -n ${ver} ]] || continue
        printf '%s\t%s\n' "${pkg#linux-image-}" "${ver%$'\r'}"
    done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'linux-image-*' 2>/dev/null || true)
}

has_vmlinuz() {
    [[ -f "$(sysfile "/boot/vmlinuz-$1")" ]]
}

# Debian 内核 flavor：由运行内核文件名决定，不能凭发行版猜测
kernel_flavour() {
    case "${KERNEL_RELEASE}" in
        *-cloud-amd64) printf 'cloud-amd64\n' ;;
        *-rt-amd64) printf 'rt-amd64\n' ;;
        *-amd64) printf 'amd64\n' ;;
        *-cloud-arm64) printf 'cloud-arm64\n' ;;
        *-arm64) printf 'arm64\n' ;;
        *) printf 'amd64\n' ;;
    esac
}

# ---------------------------------------------------------------------------
# RPM 系（Amazon Linux / RHEL / Rocky / AlmaLinux / Oracle / Fedora）
# ---------------------------------------------------------------------------

_rpm_is_kernel_pkg() {
    case "$1" in
        kernel | kernel-core | kernel-uek | kernel-uek-core) return 0 ;;
        kernel-rt | kernel-rt-core | kernel-default | kernel-default-base) return 0 ;;
        kernel-lpae | kernel-vanilla | kernel-kvmsmall | kernel-64k | kernel-64kb) return 0 ;;
        kernel-azure | kernel-azure-core | kernel-uek64k) return 0 ;;
        kernel6.*) [[ "$1" =~ ^kernel6\.[0-9]+(-core)?$ ]] && return 0 ;;
    esac
    return 1
}

# 列出已安装内核包，输出 "包名<TAB>EVR<TAB>EVR"
kernel_rpm_list() {
    have rpm || return 1
    rpm -qa --qf '%{NAME}\t%{VERSION}\t%{RELEASE}\n' 2>/dev/null |
        while IFS=$'\t' read -r name ver rel; do
            [[ -n ${name} ]] || continue
            _rpm_is_kernel_pkg "${name}" || continue
            [[ -n ${ver} && -n ${rel} ]] || continue
            printf '%s\t%s-%s\t%s-%s\n' "${name}" "${ver}" "${rel}" "${ver}" "${rel}"
        done |
        sort -t$'\t' -k3,3 -k1,1 |
        awk -F'\t' '!seen[$3]++'
}

# ---------------------------------------------------------------------------
# Alpine（apk）
# ---------------------------------------------------------------------------

_apk_kernel_names() {
    printf '%s\n' linux-lts linux-virt linux-edge linux-rpi linux-rpi2 linux-rpi4 linux
}

kernel_apk_list() {
    have apk || return 1
    local name="" line="" ver="" found=0
    while read -r name; do
        [[ -n ${name} ]] || continue
        line="$(apk info -v "${name}" 2>/dev/null | head -n 1 || true)"
        [[ -n ${line} ]] || continue
        ver="${line#"${name}"-}"
        [[ -n ${ver} ]] || continue
        printf '%s\t%s\t%s\n' "${name}" "${ver}" "${name}"
        found=1
    done < <(_apk_kernel_names)
    [[ ${found} -eq 1 ]]
}

# ---------------------------------------------------------------------------
# Arch（pacman）
# ---------------------------------------------------------------------------

_arch_kernel_names() {
    printf '%s\n' linux linux-lts linux-zen linux-hardened linux-rt linux-rt-lts
}

kernel_pacman_list() {
    have pacman || return 1
    local name="" line="" ver="" found=0
    while read -r name; do
        [[ -n ${name} ]] || continue
        line="$(pacman -Q "${name}" 2>/dev/null || true)"
        [[ -n ${line} ]] || continue
        ver="${line#* }"
        [[ -n ${ver} ]] || continue
        printf '%s\t%s\t%s\n' "${name}" "${ver}" "${name}"
        found=1
    done < <(_arch_kernel_names)
    [[ ${found} -eq 1 ]]
}

# pacman 版本 -> uname -r 形式（6.12.10.arch1 + 1 -> 6.12.10-arch1-1）
_pacman_uname_form() {
    local pkgver="${1%-*}" pkgrel="${1##*-}"
    printf '%s-%s-%s\n' "${pkgver%.*}" "${pkgver##*.}" "${pkgrel}"
}

# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------

# 列出已安装内核：<包名>\t<EVR>\t<标识>
kernel_scan_installed() {
    {
        case "${DISTRO_FAMILY}" in
            debian)
                list_installed_kernels | while IFS=$'\t' read -r rel ver; do
                    printf 'linux-image-%s\t%s\t%s\n' "${rel}" "${ver}" "${rel}"
                done
                ;;
            rpm | suse) kernel_rpm_list ;;
            alpine) kernel_apk_list ;;
            arch) kernel_pacman_list ;;
            *) return 1 ;;
        esac
    } | tr -d '\r'
}

# 把运行内核映射到软件包，写入 RUNNING_PKG / RUNNING_VERSION / RUNNING_IDENT
kernel_resolve_running() {
    RUNNING_PKG=""
    RUNNING_VERSION=""
    RUNNING_IDENT=""

    case "${DISTRO_FAMILY}" in
        debian)
            RUNNING_IDENT="${KERNEL_RELEASE}"
            RUNNING_PKG="linux-image-${KERNEL_RELEASE}"
            RUNNING_VERSION="$(query_kernel_package "${KERNEL_RELEASE}" || true)"
            [[ -n ${RUNNING_VERSION} ]]
            ;;
        rpm | suse)
            local pkg="" evr="" ident=""
            while IFS=$'\t' read -r pkg evr ident; do
                [[ -n ${evr} ]] || continue
                # uname -r 可能是 EVR 本身（部分 RHEL 系）、EVR + .arch（UEK/RHCK）
                # 或 EVR + -flavor（SUSE，如 6.4.0-150600.23.143-default）
                if [[ ${KERNEL_RELEASE} == "${evr}" ]] ||
                    [[ ${KERNEL_RELEASE} == "${evr}".* ]] ||
                    [[ ${KERNEL_RELEASE} == "${evr}"-* ]]; then
                    RUNNING_PKG="${pkg}"
                    RUNNING_VERSION="${evr}"
                    RUNNING_IDENT="${evr}"
                    return 0
                fi
            done < <(kernel_scan_installed)
            return 1
            ;;
        alpine)
            local pkg="" evr="" ident="" base=""
            base="${KERNEL_RELEASE%-*-*}"
            while IFS=$'\t' read -r pkg evr ident; do
                [[ -n ${evr} ]] || continue
                if [[ ${evr%-r*} == "${base}" ]] || [[ ${evr%-r*} == "${KERNEL_RELEASE}" ]]; then
                    RUNNING_PKG="${pkg}"
                    RUNNING_VERSION="${evr}"
                    RUNNING_IDENT="${pkg}"
                    return 0
                fi
            done < <(kernel_scan_installed)
            return 1
            ;;
        arch)
            local pkg="" evr="" ident=""
            while IFS=$'\t' read -r pkg evr ident; do
                [[ -n ${evr} ]] || continue
                if [[ "$(_pacman_uname_form "${evr}")" == "${KERNEL_RELEASE}" ]]; then
                    RUNNING_PKG="${pkg}"
                    RUNNING_VERSION="${evr}"
                    RUNNING_IDENT="${pkg}"
                    return 0
                fi
            done < <(kernel_scan_installed)
            return 1
            ;;
        *)
            return 1
            ;;
    esac
}

# 按家族比较两个内核包版本
kernel_evr_ge() {
    version_ge_family "${DISTRO_FAMILY}" "$1" "$2"
}

# 内核镜像是否真实存在（容器中 /boot 可能不存在，此时不做否定判断）
kernel_image_present() {
    local ident="$1" evr="$2" native=""
    case "${DISTRO_FAMILY}" in
        debian)
            has_vmlinuz "${ident}"
            ;;
        rpm)
            case "${ARCH}" in
                amd64) native="x86_64" ;;
                arm64) native="aarch64" ;;
                *) native="${ARCH_RAW}" ;;
            esac
            [[ -f "$(sysfile "/boot/vmlinuz-${evr}.${native}")" ]] ||
                [[ -f "$(sysfile "/boot/vmlinuz-${evr}")" ]]
            ;;
        *)
            return 0
            ;;
    esac
}

# 找到已安装、达到修复版本、但尚未运行的内核
find_fixed_installed_kernel() {
    local pkg="" evr="" ident="" best="" best_ver=""

    while IFS=$'\t' read -r pkg evr ident; do
        [[ -n ${ident} ]] || continue
        [[ ${ident} != "${RUNNING_IDENT}" ]] || continue
        kernel_evr_ge "${evr}" "${FIXED_VERSION}" || continue
        if [[ ${DISTRO_FAMILY} == "debian" ]]; then
            has_vmlinuz "${ident}" || continue
        fi
        if [[ -z ${best_ver} ]] || ! kernel_evr_ge "${best_ver}" "${evr}"; then
            best="${ident}"
            best_ver="${evr}"
        fi
    done < <(kernel_scan_installed)

    [[ -n ${best} ]] || return 1
    printf '%s\t%s\n' "${best}" "${best_ver}"
}

# 找到已安装的最新一代内核（用于提示「存在未生效的更新」）
detect_newest_installed() {
    local pkg="" evr="" ident="" best="" best_ver=""

    while IFS=$'\t' read -r pkg evr ident; do
        [[ -n ${ident} ]] || continue
        [[ ${ident} != "${RUNNING_IDENT}" ]] || continue
        if [[ -z ${best_ver} ]] || ! kernel_evr_ge "${best_ver}" "${evr}"; then
            best="${ident}"
            best_ver="${evr}"
        fi
    done < <(kernel_scan_installed)

    NEWEST_INSTALLED_ID="${best}"
    NEWEST_INSTALLED_VERSION="${best_ver}"
}
