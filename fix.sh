#!/usr/bin/env bash
#
# fix.sh - Debian 12/13 CVE-2026-98432 检测与一键修复工具
#
# 用途：检测当前 Debian 系统的运行内核是否受 CVE-2026-98432 影响，
#       并在用户确认后通过官方 APT 软件源安装修复版本内核。
#
# 依据（2026-11-01 核对 Debian Security Tracker / DSA、DLA）：
#   Debian 12 bookworm / linux 6.1    -> 6.1.190-1            (DLA-4841-1)
#   Debian 12 bookworm / linux-6.12   -> 6.12.113-1~deb12u1   (DLA-4850-1)
#   Debian 13 trixie   / linux 6.12   -> 6.12.113-1           (DSA-6568-1)
#
# 设计原则：
#   * 只使用 Debian 官方软件源，不编译内核，不引入第三方源
#   * 不删除旧内核，不自动重启，不升级无关软件包
#   * 不修改 SSH / 防火墙 / 网络 / 业务配置
#   * 安装成功 != 漏洞已修复：必须重启进入新内核后才算修复
#
# 退出码：0 已修复 / 1 错误或不支持 / 2 存在漏洞 / 3 待重启 / 4 无法确认 / 5 用户取消
#
# License: MIT

set -Eeuo pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_NAME="${0##*/}"
readonly CVE_ID="CVE-2026-98432"
readonly PROJECT_URL="https://github.com/AronWang001/debian-cve-2026-98432-fix"

readonly EX_OK=0
readonly EX_ERROR=1
readonly EX_VULNERABLE=2
readonly EX_PENDING_REBOOT=3
readonly EX_UNKNOWN=4
readonly EX_CANCELLED=5

# 测试钩子：只读文件系统前缀，生产环境为空字符串
SYSROOT="${FIX_SYSROOT:-}"
SYSROOT="${SYSROOT%/}"

MODE="fix"
ASSUME_YES=0
USE_COLOR="auto"
SECTION_TOTAL=4

# 运行环境
OS_PRETTY=""
OS_ID=""
OS_VERSION_ID=""
OS_CODENAME=""
RELEASE=""
ARCH_RAW=""
ARCH=""
KERNEL_RELEASE=""
KERNEL_BRANCH=""
RUNNING_PKG=""
RUNNING_VERSION=""
APT_SOURCE_COUNT=0
APT_SECURITY=0
HAS_APT_LISTS=0
REBOOT_FLAG=0

# 修复版本基准
FIXED_VERSION=""
ADVISORY=""
SOURCE_PACKAGE=""

# 判定结果
STATUS=""
STATUS_REASON=""
INSTALLED_FIXED_RELEASE=""
INSTALLED_FIXED_VERSION=""
NEWEST_INSTALLED_RELEASE=""
NEWEST_INSTALLED_VERSION=""

# 修复目标与结果
TARGET_PKG=""
TARGET_VERSION=""
TARGET_RELEASE=""
NEW_KERNEL_RELEASE=""
NEW_KERNEL_VERSION=""

# 颜色
C_RESET=""
C_BOLD=""
C_DIM=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

setup_colors() {
    if [[ ${USE_COLOR} == "never" ]] || [[ -n ${NO_COLOR:-} ]] || [[ ! -t 1 ]] || [[ ${TERM:-} == "dumb" ]]; then
        C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
        return 0
    fi
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;36m'
}

log_info() { printf '%s[信息]%s %s\n' "${C_BLUE}" "${C_RESET}" "$*"; }
log_ok()   { printf '%s[通过]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
log_warn() { printf '%s[警告]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
log_err()  { printf '%s[失败]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }

# 计算字符串显示宽度（CJK 字符按 2 列计），用于中英文混排的列对齐
display_width() {
    local text="$1" chars=0 bytes=0
    chars=${#text}
    bytes=$(LC_ALL=C printf '%s' "${text}" | wc -c | tr -d ' ')
    printf '%s' "$((bytes - (bytes - chars) / 2))"
}

step_title() {
    printf '\n%s==> [%s/%s] %s%s\n' "${C_BOLD}${C_BLUE}" "$1" "${SECTION_TOTAL}" "$2" "${C_RESET}"
}

kv() {
    local label="$1" value="$2" width=14 pad="" len=0
    len=$(display_width "${label}")
    while ((len < width)); do
        pad+=" "
        len=$((len + 1))
    done
    printf '  %s%s%s %s\n' "${C_DIM}" "${label}${pad}" "${C_RESET}" "${value}"
}

die() {
    log_err "$*"
    exit "${EX_ERROR}"
}

on_err() {
    local code="$1" line="$2" cmd="$3"
    log_err "脚本在第 ${line} 行意外失败（退出码 ${code}）：${cmd}"
    log_err "请将上述信息反馈至 ${PROJECT_URL}/issues"
}

trap 'on_err "$?" "${LINENO}" "${BASH_COMMAND}"' ERR

# 给绝对路径加上测试前缀（生产环境为空操作）
sysfile() {
    printf '%s%s' "${SYSROOT}" "$1"
}

# 判断版本 $1 是否 >= $2，遵循 Debian 软件包版本比较规则
version_ge() {
    dpkg --compare-versions "$1" ge "$2"
}

# 从版本号或内核 release 中取出 major.minor
kernel_branch() {
    local value="$1"
    [[ ${value} =~ ^([0-9]+)\.([0-9]+) ]] || return 1
    printf '%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
用法: ${SCRIPT_NAME} [选项]

Debian 12/13 ${CVE_ID} 内核漏洞检测与一键修复工具（v${SCRIPT_VERSION}）

选项:
  -c, --check       仅检测并输出状态，不修改系统（只读）
  -y, --yes         跳过交互确认（无人值守场景使用，请确认风险已知）
  -h, --help        显示本帮助
  -V, --version     显示版本信息
      --no-color    禁用彩色输出

退出码:
  0  已修复：当前运行内核已达到官方修复版本
  1  运行错误或环境不支持
  2  存在漏洞：当前运行内核仍受影响
  3  待重启：修复内核已安装，但仍运行旧内核
  4  无法确认：环境或软件包信息不足
  5  用户取消：未做任何修改

示例:
  sudo bash fix.sh --check     # 只体检，不改动系统
  sudo bash fix.sh             # 交互式检测并修复
  bash fix.sh --help           # 查看帮助

项目主页: ${PROJECT_URL}
EOF
}

version_info() {
    printf '%s %s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"
    printf 'CVE: %s\n' "${CVE_ID}"
    printf '项目: %s\n' "${PROJECT_URL}"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c | --check)
                MODE="check"
                ;;
            -y | --yes)
                ASSUME_YES=1
                ;;
            -h | --help)
                usage
                exit "${EX_OK}"
                ;;
            -V | --version)
                version_info
                exit "${EX_OK}"
                ;;
            --no-color)
                USE_COLOR="never"
                ;;
            *)
                log_err "未知参数：$1"
                printf '\n' >&2
                usage >&2
                exit "${EX_ERROR}"
                ;;
        esac
        shift
    done
}

# ---------------------------------------------------------------------------
# 环境检测
# ---------------------------------------------------------------------------

require_root() {
    local uid="${EUID:-$(id -u)}"
    if [[ ${uid} -ne 0 ]]; then
        log_err "需要 root 权限运行本脚本（当前 UID=${uid}）。"
        log_err "请使用：sudo bash ${SCRIPT_NAME}${*:+ $*}"
        log_err "仅做检测可用：sudo bash ${SCRIPT_NAME} --check"
        exit "${EX_ERROR}"
    fi
}

detect_os() {
    local file="" key="" val=""
    local os_id="" os_ver="" os_code="" os_pretty=""
    local found=0

    for file in "$(sysfile /etc/os-release)" "$(sysfile /usr/lib/os-release)"; do
        [[ -r ${file} ]] || continue
        while IFS='=' read -r key val; do
            val="${val%\"}"
            val="${val#\"}"
            case "${key}" in
                ID) os_id="${val}" ;;
                VERSION_ID) os_ver="${val}" ;;
                VERSION_CODENAME) os_code="${val}" ;;
                PRETTY_NAME) os_pretty="${val}" ;;
            esac
        done <"${file}"
        found=1
        break
    done

    if [[ ${found} -eq 0 ]] || [[ -z ${os_id} ]]; then
        OS_PRETTY="未知"
        die "无法读取 /etc/os-release，无法确认操作系统，已停止（未做任何修改）。"
    fi

    OS_ID="${os_id}"
    OS_VERSION_ID="${os_ver}"
    OS_CODENAME="${os_code}"
    OS_PRETTY="${os_pretty:-Debian ${os_ver}}"

    if [[ ${OS_ID,,} != "debian" ]]; then
        die "当前系统为 ${OS_PRETTY}（ID=${OS_ID}），不是 Debian，本工具拒绝执行。"
    fi

    case "${OS_VERSION_ID}" in
        12) RELEASE="bookworm" ;;
        13) RELEASE="trixie" ;;
        *)
            die "当前 Debian 版本为 ${OS_VERSION_ID:-未知}，本工具仅支持 Debian 12 (bookworm) 与 Debian 13 (trixie)，已停止。"
            ;;
    esac

    if [[ -n ${OS_CODENAME} ]] && [[ ${OS_CODENAME} != "${RELEASE}" ]]; then
        die "版本号与代号不一致（VERSION_ID=${OS_VERSION_ID}，VERSION_CODENAME=${OS_CODENAME}），无法确认环境，已停止。"
    fi
}

detect_arch() {
    ARCH_RAW="$(uname -m)"
    case "${ARCH_RAW}" in
        x86_64 | amd64)
            ARCH="amd64"
            ;;
        *)
            die "当前 CPU 架构为 ${ARCH_RAW}，本工具目前仅支持 amd64 (x86_64)，已停止。"
            ;;
    esac

    local dpkg_arch=""
    if command -v dpkg >/dev/null 2>&1; then
        dpkg_arch="$(dpkg --print-architecture 2>/dev/null || true)"
    fi
    if [[ -n ${dpkg_arch} ]] && [[ ${dpkg_arch} != "amd64" ]]; then
        die "dpkg 报告的系统架构为 ${dpkg_arch}，与 CPU 架构 ${ARCH_RAW} 不一致，无法确认环境，已停止。"
    fi
}

detect_kernel() {
    KERNEL_RELEASE="$(uname -r)"
    if [[ -z ${KERNEL_RELEASE} ]]; then
        die "无法获取当前运行内核版本（uname -r 为空），已停止。"
    fi
    if ! KERNEL_BRANCH="$(kernel_branch "${KERNEL_RELEASE}")"; then
        die "无法解析内核版本号：${KERNEL_RELEASE}，已停止。"
    fi
}

# 查询某个内核 release 对应的 linux-image 软件包版本
query_kernel_package() {
    local rel="$1" fields="" st="" ver="" owner=""

    fields="$(dpkg-query -W -f='${db:Status-Abbrev} ${Version}' "linux-image-${rel}" 2>/dev/null || true)"
    if [[ -n ${fields} ]]; then
        read -r st ver <<<"${fields}"
        if [[ ${st} == "ii" ]] && [[ -n ${ver} ]]; then
            printf '%s\n' "${ver}"
            return 0
        fi
    fi

    owner="$(dpkg -S "$(sysfile "/boot/vmlinuz-${rel}")" 2>/dev/null | head -n 1 || true)"
    if [[ -n ${owner} ]]; then
        owner="${owner%%:*}"
        ver="$(dpkg-query -W -f='${Version}' "${owner}" 2>/dev/null || true)"
        if [[ -n ${ver} ]]; then
            printf '%s\n' "${ver}"
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
        printf '%s\t%s\n' "${pkg#linux-image-}" "${ver}"
    done < <(dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'linux-image-*' 2>/dev/null || true)
}

has_vmlinuz() {
    [[ -f "$(sysfile "/boot/vmlinuz-$1")" ]]
}

detect_apt() {
    command -v apt-get >/dev/null 2>&1 || die "未找到 apt-get，无法确认 APT 环境，已停止。"
    command -v apt-cache >/dev/null 2>&1 || die "未找到 apt-cache，无法确认 APT 环境，已停止。"

    local -a files=()
    local -a lists=()
    local f="" nullglob_was_off=1

    shopt -q nullglob && nullglob_was_off=0
    shopt -s nullglob
    files=(
        "$(sysfile /etc/apt/sources.list)"
        "$(sysfile /etc/apt/sources.list.d)"/*.list
        "$(sysfile /etc/apt/sources.list.d)"/*.sources
    )
    lists=("$(sysfile /var/lib/apt/lists)"/*Packages*)
    if [[ ${nullglob_was_off} -eq 1 ]]; then
        shopt -u nullglob
    fi

    for f in "${files[@]}"; do
        if [[ -r ${f} ]] && [[ -s ${f} ]]; then
            APT_SOURCE_COUNT=$((APT_SOURCE_COUNT + 1))
        fi
    done

    if [[ ${APT_SOURCE_COUNT} -eq 0 ]]; then
        die "未找到可用的 APT 软件源配置（/etc/apt/sources.list 或 sources.list.d/*），已停止。"
    fi

    if grep -RqsE 'security\.debian\.org|(bookworm|trixie)-security' "${files[@]}" 2>/dev/null; then
        APT_SECURITY=1
    fi

    if [[ ${#lists[@]} -gt 0 ]]; then
        HAS_APT_LISTS=1
    fi
}

detect_reboot_flags() {
    if [[ -e "$(sysfile /var/run/reboot-required)" ]] || [[ -e "$(sysfile /run/reboot-required)" ]]; then
        REBOOT_FLAG=1
    fi
}

# 找到最新的已安装内核（不论是否为修复版本）
detect_newest_installed() {
    local rel="" ver=""
    while IFS=$'\t' read -r rel ver; do
        has_vmlinuz "${rel}" || continue
        if [[ -z ${NEWEST_INSTALLED_VERSION} ]] || dpkg --compare-versions "${ver}" gt "${NEWEST_INSTALLED_VERSION}"; then
            NEWEST_INSTALLED_RELEASE="${rel}"
            NEWEST_INSTALLED_VERSION="${ver}"
        fi
    done < <(list_installed_kernels)
}

print_environment() {
    step_title 1 "环境检测"

    log_ok "运行权限：root（UID=0）"
    log_ok "操作系统：${OS_PRETTY}（Debian ${OS_VERSION_ID} / ${RELEASE}）"
    log_ok "CPU 架构：${ARCH_RAW}（${ARCH}）"
    log_ok "运行内核：${KERNEL_RELEASE}（分支 ${KERNEL_BRANCH}）"

    if [[ -n ${RUNNING_VERSION} ]]; then
        log_ok "内核软件包：${RUNNING_PKG} ${RUNNING_VERSION}"
    else
        log_warn "内核软件包：无法把运行内核 ${KERNEL_RELEASE} 映射到已安装的 linux-image 包"
    fi

    if [[ ${APT_SECURITY} -eq 1 ]]; then
        log_ok "APT 软件源：${APT_SOURCE_COUNT} 个配置文件，已包含 security 源"
    else
        log_warn "APT 软件源：${APT_SOURCE_COUNT} 个配置文件，未发现 security 源（可能无法获取修复内核）"
    fi

    if [[ ${MODE} == "check" ]] && [[ ${HAS_APT_LISTS} -eq 0 ]]; then
        log_warn "APT 索引：本地元数据为空，--check 不会更新索引，候选版本可能显示为未知"
    fi

    if [[ ${REBOOT_FLAG} -eq 1 ]]; then
        log_warn "待重启标记：/var/run/reboot-required 存在（系统有更新等待重启）"
    else
        log_ok "待重启标记：不存在"
    fi

    if [[ -n ${NEWEST_INSTALLED_RELEASE} ]] && [[ ${NEWEST_INSTALLED_RELEASE} != "${KERNEL_RELEASE}" ]]; then
        log_warn "已安装内核 ${NEWEST_INSTALLED_RELEASE} 与运行内核不一致（存在未生效的更新）"
    fi
}

# ---------------------------------------------------------------------------
# 漏洞判定
# ---------------------------------------------------------------------------

fixed_version_for() {
    case "$1/$2" in
        bookworm/6.1) printf '6.1.190-1\n' ;;
        bookworm/6.12) printf '6.12.113-1~deb12u1\n' ;;
        trixie/6.12) printf '6.12.113-1\n' ;;
        *) return 1 ;;
    esac
}

advisory_for() {
    case "$1/$2" in
        bookworm/6.1) printf 'DLA-4841-1\n' ;;
        bookworm/6.12) printf 'DLA-4850-1\n' ;;
        trixie/6.12) printf 'DSA-6568-1\n' ;;
        *) printf '未知\n' ;;
    esac
}

source_package_for() {
    case "$1/$2" in
        bookworm/6.12) printf 'linux-6.12\n' ;;
        *) printf 'linux\n' ;;
    esac
}

# 查找已安装、达到修复版本、但尚未运行的内核
find_fixed_installed_kernel() {
    local rel="" ver="" best="" best_ver=""
    while IFS=$'\t' read -r rel ver; do
        [[ ${rel} != "${KERNEL_RELEASE}" ]] || continue
        dpkg --compare-versions "${ver}" ge "${FIXED_VERSION}" || continue
        has_vmlinuz "${rel}" || continue
        if [[ -z ${best_ver} ]] || dpkg --compare-versions "${ver}" gt "${best_ver}"; then
            best="${rel}"
            best_ver="${ver}"
        fi
    done < <(list_installed_kernels)
    [[ -n ${best} ]] || return 1
    printf '%s\n' "${best}"
}

assess() {
    if ! FIXED_VERSION="$(fixed_version_for "${RELEASE}" "${KERNEL_BRANCH}")"; then
        FIXED_VERSION=""
        STATUS="unknown"
        STATUS_REASON="运行内核分支 ${KERNEL_BRANCH} 不在已核实的修复版本表中（仅覆盖 Debian 12 的 6.1 / 6.12 与 Debian 13 的 6.12），无法确认安全状态。"
        return 0
    fi
    ADVISORY="$(advisory_for "${RELEASE}" "${KERNEL_BRANCH}")"
    SOURCE_PACKAGE="$(source_package_for "${RELEASE}" "${KERNEL_BRANCH}")"

    if [[ -z ${RUNNING_VERSION} ]]; then
        STATUS="unknown"
        STATUS_REASON="无法将运行内核 ${KERNEL_RELEASE} 映射到已安装的 linux-image 软件包（可能为自编译或第三方内核），无法确认安全状态。"
        return 0
    fi

    if version_ge "${RUNNING_VERSION}" "${FIXED_VERSION}"; then
        STATUS="fixed"
        STATUS_REASON="当前运行内核软件包版本 ${RUNNING_VERSION} 已达到官方修复版本 ${FIXED_VERSION}。"
        return 0
    fi

    local fixed_rel=""
    if fixed_rel="$(find_fixed_installed_kernel)"; then
        INSTALLED_FIXED_RELEASE="${fixed_rel}"
        INSTALLED_FIXED_VERSION="$(query_kernel_package "${fixed_rel}" || true)"
        STATUS="pending"
        STATUS_REASON="修复版本内核 ${fixed_rel} 已安装，但当前仍运行 ${KERNEL_RELEASE}，需要重启后才会生效。"
        return 0
    fi

    STATUS="vulnerable"
    STATUS_REASON="当前运行内核软件包版本 ${RUNNING_VERSION} 低于官方修复版本 ${FIXED_VERSION}（分支 ${KERNEL_BRANCH}）。"
}

print_assessment() {
    step_title 2 "漏洞状态判定"
    kv "漏洞编号" "${CVE_ID}"
    kv "官方依据" "${ADVISORY:-未知}（源码包 ${SOURCE_PACKAGE:-linux}）"
    kv "基线核对" "2026-11-01 · Debian Security Tracker"
    kv "内核分支" "${KERNEL_BRANCH}"
    kv "修复版本" "${FIXED_VERSION:-未知}"
    kv "运行内核" "${KERNEL_RELEASE}"
    kv "运行版本" "${RUNNING_VERSION:-未知}"

    case "${STATUS}" in
        fixed)
            printf '  %s判定结果：已修复%s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
            ;;
        pending)
            printf '  %s判定结果：待重启%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
            ;;
        vulnerable)
            printf '  %s判定结果：存在漏洞%s\n' "${C_RED}${C_BOLD}" "${C_RESET}"
            ;;
        *)
            printf '  %s判定结果：无法确认%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
            ;;
    esac
    printf '  %s\n' "${STATUS_REASON}"
}

# ---------------------------------------------------------------------------
# 修复流程
# ---------------------------------------------------------------------------

kernel_flavour() {
    case "${KERNEL_RELEASE}" in
        *-cloud-amd64) printf 'cloud-amd64\n' ;;
        *-rt-amd64) printf 'rt-amd64\n' ;;
        *) printf 'amd64\n' ;;
    esac
}

apt_candidate() {
    local pkg="$1" out=""
    out="$(LC_ALL=C apt-cache policy "${pkg}" 2>/dev/null | awk '/^ *Candidate:/ {print $2; exit}' || true)"
    [[ -n ${out} ]] || return 1
    printf '%s\n' "${out}"
}

# 候选版本是否可用：存在、分支一致、且达到修复版本
candidate_usable() {
    local cand="$1" cand_branch=""
    [[ -n ${cand} ]] || return 1
    [[ ${cand} != "(none)" ]] || return 1
    cand_branch="$(kernel_branch "${cand}" || true)"
    [[ ${cand_branch} == "${KERNEL_BRANCH}" ]] || return 1
    version_ge "${cand}" "${FIXED_VERSION}"
}

select_target_package() {
    local flavour="" cand="" pkg="" ver="" best="" best_ver="" search_re=""

    flavour="$(kernel_flavour)"
    if [[ ${RELEASE} == "bookworm" ]] && [[ ${KERNEL_BRANCH} == "6.12" ]]; then
        TARGET_PKG="linux-image-6.12-${flavour}"
    else
        TARGET_PKG="linux-image-${flavour}"
    fi

    if cand="$(apt_candidate "${TARGET_PKG}")" && candidate_usable "${cand}"; then
        TARGET_VERSION="${cand}"
        return 0
    fi

    # 回退：在同一分支的具体镜像包中挑选最高可用版本
    search_re="^linux-image-${KERNEL_BRANCH//./\\.}\\..*-${flavour}$"
    while read -r pkg _; do
        [[ -n ${pkg} ]] || continue
        case "${pkg}" in
            *-unsigned) continue ;;
        esac
        ver="$(apt_candidate "${pkg}" || true)"
        candidate_usable "${ver}" || continue
        if [[ -z ${best_ver} ]] || dpkg --compare-versions "${ver}" gt "${best_ver}"; then
            best="${pkg}"
            best_ver="${ver}"
        fi
    done < <(LC_ALL=C apt-cache search --names-only "${search_re}" 2>/dev/null || true)

    if [[ -n ${best} ]]; then
        TARGET_PKG="${best}"
        TARGET_VERSION="${best_ver}"
        return 0
    fi

    return 1
}

resolve_target_release() {
    local name="${TARGET_PKG#linux-image-}"
    if [[ ${name} =~ ^[0-9][^[:space:]]*-${ARCH}$ ]]; then
        TARGET_RELEASE="${name}"
    else
        TARGET_RELEASE=""
    fi
}

confirm() {
    local prompt="$1" reply=""

    if [[ ${ASSUME_YES} -eq 1 ]]; then
        log_warn "已指定 --yes，跳过交互确认"
        return 0
    fi

    if [[ ${FIX_NO_TTY:-0} -eq 1 ]]; then
        printf '%s [y/N] ' "${prompt}" >&2
        IFS= read -r reply || reply=""
    elif { : </dev/tty; } 2>/dev/null; then
        printf '%s [y/N] ' "${prompt}" >/dev/tty
        IFS= read -r reply </dev/tty || reply=""
    else
        printf '%s [y/N] ' "${prompt}" >&2
        IFS= read -r reply || reply=""
    fi

    case "${reply,,}" in
        y | yes | 是) return 0 ;;
        "")
            log_warn "未获取到输入，按取消处理"
            return 1
            ;;
        *) return 1 ;;
    esac
}

print_plan() {
    step_title 3 "修复计划"
    kv "目标软件包" "${TARGET_PKG}"
    kv "可安装版本" "${TARGET_VERSION}"
    kv "修复版本基准" "${FIXED_VERSION}"
    if [[ -n ${TARGET_RELEASE} ]]; then
        kv "预计新内核" "${TARGET_RELEASE}"
    else
        kv "预计新内核" "由 APT 依赖解析决定（分支 ${KERNEL_BRANCH}）"
    fi

    printf '\n  即将执行：\n'
    printf '   1. apt-get update（仅刷新索引）\n'
    printf '   2. apt-get install %s\n' "${TARGET_PKG}"
    printf '   3. 校验安装结果、initramfs 与 GRUB 配置\n'
    printf '\n  %s不会执行：自动重启、删除旧内核、升级无关软件包、编译内核，%s\n' "${C_DIM}" "${C_RESET}"
    printf '  %s也不会修改 SSH / 防火墙 / 网络 / 业务配置。%s\n' "${C_DIM}" "${C_RESET}"
    printf '\n'
}

apt_update() {
    step_title 4 "更新内核"
    log_info "执行 apt-get update ..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get \
        -o DPkg::Lock::Timeout=120 \
        -o Acquire::Retries=3 \
        update; then
        log_err "apt-get update 执行失败，已停止，未安装任何内核。"
        log_err "请检查网络连通性与 /etc/apt/sources.list 配置后重试。"
        exit "${EX_ERROR}"
    fi
    log_ok "APT 索引更新完成"
}

apt_install() {
    log_info "执行 apt-get install ${TARGET_PKG} ..."
    if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
        -o DPkg::Lock::Timeout=120 \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        --no-install-recommends "${TARGET_PKG}"; then
        log_err "内核安装失败（apt-get install 返回非零），已停止后续操作。"
        log_err "系统未重启，当前仍运行 ${KERNEL_RELEASE}。请根据上方 APT 报错处理后重试。"
        exit "${EX_ERROR}"
    fi
    log_ok "apt-get install 命令执行完成，开始校验实际安装结果"
}

verify_install() {
    local rel="" ver="" newest="" newest_ver=""
    while IFS=$'\t' read -r rel ver; do
        dpkg --compare-versions "${ver}" ge "${FIXED_VERSION}" || continue
        has_vmlinuz "${rel}" || continue
        if [[ -z ${newest_ver} ]] || dpkg --compare-versions "${ver}" gt "${newest_ver}"; then
            newest="${rel}"
            newest_ver="${ver}"
        fi
    done < <(list_installed_kernels)

    if [[ -z ${newest} ]]; then
        log_err "安装命令返回成功，但未检测到达到修复版本 ${FIXED_VERSION} 的内核镜像。"
        log_err "安装成功不等于漏洞已修复，请执行 'dpkg -l | grep linux-image' 核对后重试。"
        exit "${EX_ERROR}"
    fi

    NEW_KERNEL_RELEASE="${newest}"
    NEW_KERNEL_VERSION="${newest_ver}"
    log_ok "已安装修复内核：${NEW_KERNEL_RELEASE}（${NEW_KERNEL_VERSION}）"
}

check_initramfs() {
    local rel="$1" path=""
    path="$(sysfile "/boot/initrd.img-${rel}")"
    if [[ -s ${path} ]]; then
        log_ok "initramfs 已生成：/boot/initrd.img-${rel}"
        return 0
    fi
    log_err "未检测到有效的 initramfs：/boot/initrd.img-${rel}"
    log_err "请手动执行 'update-initramfs -c -k ${rel}'，确认无误后再次运行本脚本。"
    exit "${EX_ERROR}"
}

grub_config_path() {
    local candidate=""
    for candidate in "/boot/grub/grub.cfg" "/boot/grub2/grub.cfg"; do
        if [[ -f "$(sysfile "${candidate}")" ]]; then
            printf '%s\n' "$(sysfile "${candidate}")"
            return 0
        fi
    done
    return 1
}

check_grub() {
    local rel="$1" cfg=""

    if ! cfg="$(grub_config_path)"; then
        log_warn "未检测到 GRUB 配置文件（可能使用 systemd-boot 或其他引导器），无法确认引导项。"
        log_warn "请重启前自行确认引导程序已包含新内核 ${rel}。"
        return 0
    fi

    if grep -Fqs -- "${rel}" "${cfg}"; then
        log_ok "GRUB 配置已包含新内核：${cfg}"
        return 0
    fi

    log_warn "GRUB 配置中未找到新内核 ${rel}，尝试重新生成引导配置"
    if command -v update-grub >/dev/null 2>&1; then
        if ! update-grub; then
            log_err "update-grub 执行失败，引导配置可能未更新，已停止。"
            log_err "请手动执行 'update-grub' 排查后，再次运行本脚本。"
            exit "${EX_ERROR}"
        fi
    elif command -v grub-mkconfig >/dev/null 2>&1; then
        if ! grub-mkconfig -o "${cfg}"; then
            log_err "grub-mkconfig 执行失败，引导配置可能未更新，已停止。"
            log_err "请手动执行 'grub-mkconfig -o ${cfg}' 排查后，再次运行本脚本。"
            exit "${EX_ERROR}"
        fi
    else
        log_err "系统中未找到 update-grub / grub-mkconfig，无法更新引导配置，已停止。"
        exit "${EX_ERROR}"
    fi

    if grep -Fqs -- "${rel}" "${cfg}"; then
        log_ok "GRUB 配置已更新并包含新内核：${cfg}"
        return 0
    fi

    log_err "重新生成后 GRUB 配置中仍不包含新内核 ${rel}，引导项可能不可用，已停止。"
    log_err "请检查 /etc/default/grub 与 /etc/grub.d/ 配置后重试。"
    exit "${EX_ERROR}"
}

print_reboot_notice() {
    printf '\n%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
    printf '%s 修复结果%s\n' "${C_BOLD}" "${C_RESET}"
    printf '%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
    kv "原运行内核" "${KERNEL_RELEASE}（${RUNNING_VERSION:-未知}）"
    kv "新安装内核" "${NEW_KERNEL_RELEASE}（${NEW_KERNEL_VERSION:-未知}）"
    kv "安装状态" "成功，修复内核已就位"
    kv "是否需要重启" "需要"

    cat <<EOF

  ${C_YELLOW}${C_BOLD}新内核已经安装，但当前服务器仍在运行旧内核。${C_RESET}
  需要安排维护窗口重启服务器，才能让修复后的内核正式生效。
  重启前本机仍然受 ${CVE_ID} 影响，请勿视为已修复。

  重启命令（复制后自行执行，本脚本不会自动重启）：

      ${C_BOLD}reboot${C_RESET}

  重启后请再次执行本脚本进行二次验证：

      sudo bash ${SCRIPT_NAME} --check

EOF
}

run_fix() {
    if ! select_target_package; then
        log_err "软件源中未找到分支 ${KERNEL_BRANCH} 且版本 >= ${FIXED_VERSION} 的内核包。"
        log_err "请确认已启用 ${RELEASE}-security 源并执行 apt-get update 后重试，本脚本不做任何修改。"
        exit "${EX_ERROR}"
    fi
    resolve_target_release
    print_plan

    if ! confirm "确认安装上述内核更新？"; then
        log_warn "已取消，系统未做任何修改。"
        exit "${EX_CANCELLED}"
    fi

    apt_update

    local cand=""
    cand="$(apt_candidate "${TARGET_PKG}" || true)"
    if ! candidate_usable "${cand}"; then
        log_err "更新索引后，${TARGET_PKG} 的候选版本仍不可用（当前：${cand:-未知}）。"
        log_err "修复需要 >= ${FIXED_VERSION}，请检查软件源是否包含 ${RELEASE}-security。"
        exit "${EX_ERROR}"
    fi
    TARGET_VERSION="${cand}"

    apt_install
    verify_install
    check_initramfs "${NEW_KERNEL_RELEASE}"
    check_grub "${NEW_KERNEL_RELEASE}"

    print_reboot_notice
    exit "${EX_PENDING_REBOOT}"
}

# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

print_banner() {
    printf '\n%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}${C_BLUE}" "${C_RESET}"
    printf ' Debian %s 检测与修复工具  v%s\n' "${CVE_ID}" "${SCRIPT_VERSION}"
    if [[ ${MODE} == "check" ]]; then
        printf ' 模式：只读检测（--check），不会修改系统\n'
    else
        printf ' 模式：交互式检测与修复\n'
    fi
    printf '%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}${C_BLUE}" "${C_RESET}"
}

main() {
    parse_args "$@"
    if [[ ${MODE} == "check" ]]; then
        SECTION_TOTAL=2
    fi
    setup_colors
    print_banner
    require_root "$@"

    detect_os
    detect_arch
    detect_kernel
    detect_apt
    detect_reboot_flags

    RUNNING_PKG="linux-image-${KERNEL_RELEASE}"
    RUNNING_VERSION="$(query_kernel_package "${KERNEL_RELEASE}" || true)"
    detect_newest_installed

    print_environment
    assess
    print_assessment

    case "${STATUS}" in
        fixed)
            printf '\n%s无需操作：当前运行内核已包含该漏洞的修复。%s\n\n' "${C_GREEN}" "${C_RESET}"
            exit "${EX_OK}"
            ;;
        unknown)
            printf '\n%s建议：请先确认内核来源与软件包完整性，或参考 %s 手工判断。%s\n\n' \
                "${C_YELLOW}" "${ADVISORY:-官方公告}" "${C_RESET}"
            exit "${EX_UNKNOWN}"
            ;;
        pending)
            NEW_KERNEL_RELEASE="${INSTALLED_FIXED_RELEASE}"
            NEW_KERNEL_VERSION="${INSTALLED_FIXED_VERSION}"
            printf '\n%s修复内核已安装但尚未生效，请安排维护窗口重启。%s\n' "${C_YELLOW}" "${C_RESET}"
            print_reboot_notice
            exit "${EX_PENDING_REBOOT}"
            ;;
        vulnerable)
            if [[ ${MODE} == "check" ]]; then
                printf '\n%s当前系统受 %s 影响，可执行以下命令修复：%s\n' "${C_YELLOW}" "${CVE_ID}" "${C_RESET}"
                printf '    sudo bash %s\n\n' "${SCRIPT_NAME}"
                if select_target_package; then
                    printf '  预计安装：%s（%s）\n\n' "${TARGET_PKG}" "${TARGET_VERSION}"
                else
                    printf '  %s软件源中暂未找到可用的修复内核，请先检查 security 源与 apt-get update。%s\n\n' \
                        "${C_YELLOW}" "${C_RESET}"
                fi
                exit "${EX_VULNERABLE}"
            fi
            run_fix
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
