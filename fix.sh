#!/usr/bin/env bash
#
# fix.sh - CVE-2026-98432 多发行版检测与修复工具
#
# 用途：识别当前 Linux 发行版与运行内核，判断 CVE-2026-98432 的官方修复状态，
#       仅对「官方修复包已核验 + 适配完成 + 用户确认」的发行版执行内核更新。
#
# 支持策略（2026-11-01 核验）：
#   * 自动检测 + 自动修复：Debian 12/13、Amazon Linux 2 / 2023
#   * 仅检测（官方尚未修复）：Ubuntu 20.04/22.04/24.04、RHEL 8/9/10
#   * 仅识别（未完成核验）：Rocky、AlmaLinux、Oracle Linux、Fedora、
#     openSUSE/SUSE、Arch、Alpine
#
# 设计原则：
#   * 只使用发行版官方源或用户已配置的仓库，不新增第三方源
#   * 不编译内核、不删除旧内核、不做全系统升级、不自动重启
#   * 不修改 SSH / 防火墙 / 网络 / HAProxy / V2bX / Xray 等业务配置
#   * 安装成功 != 漏洞已修复：必须重启进入新内核后才算修复
#
# 退出码：0 已修复 / 1 错误或不支持 / 2 存在漏洞 / 3 待重启
#         4 无法确认 / 5 用户取消 / 6 官方尚未发布修复包
#
# License: MIT

set -Eeuo pipefail

readonly SCRIPT_VERSION="1.2.0"
readonly SCRIPT_NAME="${0##*/}"
readonly CVE_ID="CVE-2026-98432"
readonly PROJECT_URL="https://github.com/AronWang001/linux-cve-2026-98432-fix"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LIB_ROOT="${SCRIPT_DIR}"

# shellcheck source=lib/common.sh
source "${LIB_ROOT}/lib/common.sh"
# shellcheck source=lib/version.sh
source "${LIB_ROOT}/lib/version.sh"
# shellcheck source=lib/detect.sh
source "${LIB_ROOT}/lib/detect.sh"
# shellcheck source=lib/advisory.sh
source "${LIB_ROOT}/lib/advisory.sh"
# shellcheck source=lib/kernel.sh
source "${LIB_ROOT}/lib/kernel.sh"
# shellcheck source=lib/package_manager.sh
source "${LIB_ROOT}/lib/package_manager.sh"
# shellcheck source=lib/install.sh
source "${LIB_ROOT}/lib/install.sh"
# shellcheck source=lib/status.sh
source "${LIB_ROOT}/lib/status.sh"
# shellcheck source=lib/report.sh
source "${LIB_ROOT}/lib/report.sh"

trap 'on_err "$?" "${LINENO}" "${BASH_COMMAND}"' ERR

# ---------------------------------------------------------------------------
# 全局状态
# ---------------------------------------------------------------------------

# 这一段只做初始化：变量由 lib/*.sh 与 adapters/*.sh 在运行时读写，
# ShellCheck 单文件分析看不到跨文件的使用点，故对整段关闭「未使用」提示。
# shellcheck disable=SC2034

# 系统身份
OS_PRETTY=""
OS_ID=""
OS_NAME=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
OS_ID_LIKE=""
OS_VERSION_ID=""
OS_CODENAME=""
DISTRO_ID=""
DISTRO_FAMILY=""
DISTRO_RELEASE=""
DISTRO_CODENAME=""
ADAPTER_NAME=""
ADAPTER_ID=""
ADAPTER_DATA_DISTRO=""
ADAPTER_FAMILY=""
ADAPTER_DETECT_SUPPORTED=0
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
ADAPTER_KERNEL_FLAVORS=""
ADAPTER_ADVISORY_URL=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
ADAPTER_UPDATE_PROCEDURE=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
ADAPTER_NOTES=""

# 硬件与内核
ARCH_RAW=""
ARCH=""
PM_ARCH=""
ARCH_CONFLICT=0
KERNEL_RELEASE=""
KERNEL_BRANCH=""
KERNEL_FLAVOR=""
RUNNING_PKG=""
RUNNING_VERSION=""
RUNNING_IDENT=""
NEWEST_INSTALLED_ID=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
NEWEST_INSTALLED_VERSION=""
IS_CONTAINER=0
CONTAINER_KIND=""
REBOOT_FLAG=0
PM_NAME=""

# 软件源
APT_SOURCE_COUNT=0
APT_SECURITY=0
HAS_APT_LISTS=0
REPO_FILE_COUNT=0

# 基线
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
BASE_INDEX=-1
BASE_STATUS=""
FIXED_VERSION=""
ADVISORY=""
ADVISORY_URL=""
BASELINE_VERIFIED=""
BASELINE_NOTE=""
BASELINE_PACKAGE=""
BASELINE_AUTOFIX=""
BASELINE_FAMILY=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
BASELINE_RELEASE=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
BASELINE_BRANCH=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
BASELINE_FLAVORS=""
# shellcheck disable=SC2034  # 跨文件使用的全局状态，由 lib/*.sh 与 fix.sh 共同读写
BASELINE_ARCHES=""

# 判定
STATUS=""
STATUS_REASON=""
AUTOFIX=0
INSTALLED_FIXED_RELEASE=""
INSTALLED_FIXED_VERSION=""

# 目标与结果
TARGET_PKG=""
TARGET_VERSION=""
TARGET_RELEASE=""
NEW_KERNEL_RELEASE=""
NEW_KERNEL_VERSION=""

# 报告
REPORT_PATH=""

# ---------------------------------------------------------------------------
# 参数与输出
# ---------------------------------------------------------------------------

usage() {
    cat <<EOF
用法: ${SCRIPT_NAME} [选项]

CVE-2026-98432 多发行版检测与修复工具（v${SCRIPT_VERSION}）

检测支持：Debian 12/13、Ubuntu 20.04/22.04/24.04、Amazon Linux 2/2023、
          RHEL 8/9/10、Rocky、AlmaLinux、Oracle Linux、Fedora、
          openSUSE/SUSE、Arch Linux、Alpine Linux
自动修复：仅 Debian 12/13 与 Amazon Linux 2/2023（官方修复包已核验）

选项:
  -c, --check          仅检测并输出状态，不修改系统（只读）
  -y, --yes            跳过交互确认（不能绕过发行版白名单与版本校验）
  -h, --help           显示本帮助
  -V, --version        显示版本信息
      --no-color       禁用彩色输出
      --list-distros   显示各发行版的检测/自动修复支持与官方补丁状态
      --report [文件]  生成检测报告（不修改系统），默认写入当前目录

退出码:
  0  已修复：当前运行内核已达到官方修复版本
  1  运行错误或环境不支持
  2  存在漏洞：官方修复包可用，当前运行内核仍受影响
  3  待重启：修复内核已安装，但仍运行旧内核
  4  无法确认：公告、内核来源、包映射或版本无法确认
  5  用户取消：未做任何修改
  6  官方尚未发布可确认的修复包（仅检测，不安装）

示例:
  sudo bash ${SCRIPT_NAME} --check          # 只体检，不改动系统
  sudo bash ${SCRIPT_NAME} --report         # 生成检测报告
  sudo bash ${SCRIPT_NAME}                  # 交互式检测与修复
  bash ${SCRIPT_NAME} --list-distros        # 查看支持矩阵

项目主页: ${PROJECT_URL}
EOF
}

version_info() {
    printf '%s %s\n' "${SCRIPT_NAME}" "${SCRIPT_VERSION}"
    printf 'CVE: %s\n' "${CVE_ID}"
    printf '自动修复: Debian 12/13, Amazon Linux 2/2023\n'
    printf '仅检测: Ubuntu, RHEL, Rocky, AlmaLinux, Oracle Linux, Fedora, SUSE, Arch, Alpine\n'
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
            --list-distros)
                MODE="list"
                ;;
            --report)
                MODE="report"
                if [[ $# -gt 1 ]] && [[ ${2:-} != -* ]]; then
                    REPORT_PATH="$2"
                    shift
                fi
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

print_banner() {
    printf '\n%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}${C_BLUE}" "${C_RESET}"
    printf ' %s 多发行版检测与修复工具  v%s\n' "${CVE_ID}" "${SCRIPT_VERSION}"
    case "${MODE}" in
        check) printf ' 模式：只读检测（--check），不会修改系统\n' ;;
        report) printf ' 模式：生成检测报告，不会修改系统\n' ;;
        list) printf ' 模式：支持矩阵\n' ;;
        *) printf ' 模式：交互式检测与修复\n' ;;
    esac
    printf '%s────────────────────────────────────────────────────────%s\n' "${C_BOLD}${C_BLUE}" "${C_RESET}"
}

require_root() {
    local uid="${EUID:-$(id -u)}"
    if [[ ${uid} -ne 0 ]]; then
        log_err "需要 root 权限运行本脚本（当前 UID=${uid}）。"
        log_err "请使用：sudo bash ${SCRIPT_NAME}${*:+ $*}"
        log_err "仅做检测可用：sudo bash ${SCRIPT_NAME} --check"
        exit "${EX_ERROR}"
    fi
}

# ---------------------------------------------------------------------------
# 软件源检测（只读）
# ---------------------------------------------------------------------------

detect_pm_sources() {
    local -a files=()
    local -a lists=()
    local f="" nullglob_was_off=1

    case "${DISTRO_FAMILY}" in
        debian)
            have apt-get || die "未找到 apt-get，无法确认 APT 环境，已停止。"
            have apt-cache || die "未找到 apt-cache，无法确认 APT 环境，已停止。"

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

            if grep -RqsE 'security\.debian\.org|ubuntu\.com/security|security\.ubuntu\.com' "${files[@]}" 2>/dev/null; then
                APT_SECURITY=1
            fi

            # 注意：这里必须用 if 而不是 `[[ ]] && 赋值`。
            # 后者在条件为假时会让函数返回 1，配合 set -e 会直接中断脚本，
            # 而「容器里 /var/lib/apt/lists 为空」是完全正常的场景。
            if [[ ${#lists[@]} -gt 0 ]]; then
                HAS_APT_LISTS=1
            fi
            ;;
        rpm)
            shopt -q nullglob && nullglob_was_off=0
            shopt -s nullglob
            files=("$(sysfile /etc/yum.repos.d)"/*.repo)
            if [[ ${nullglob_was_off} -eq 1 ]]; then
                shopt -u nullglob
            fi
            for f in "${files[@]}"; do
                if [[ -r ${f} ]]; then
                    REPO_FILE_COUNT=$((REPO_FILE_COUNT + 1))
                fi
            done
            ;;
        alpine)
            if [[ -r "$(sysfile /etc/apk/repositories)" ]]; then
                REPO_FILE_COUNT=1
            fi
            ;;
        arch)
            if [[ -r "$(sysfile /etc/pacman.conf)" ]]; then
                REPO_FILE_COUNT=1
            fi
            ;;
        suse)
            shopt -q nullglob && nullglob_was_off=0
            shopt -s nullglob
            files=("$(sysfile /etc/zypp/repos.d)"/*.repo)
            if [[ ${nullglob_was_off} -eq 1 ]]; then
                shopt -u nullglob
            fi
            for f in "${files[@]}"; do
                if [[ -r ${f} ]]; then
                    REPO_FILE_COUNT=$((REPO_FILE_COUNT + 1))
                fi
            done
            ;;
    esac

    return 0
}

print_environment() {
    step_title 1 "环境检测"

    log_ok "运行权限：root（UID=0）"
    log_ok "操作系统：${OS_PRETTY}"
    log_ok "发行版识别：${ADAPTER_NAME:-未知} ${DISTRO_RELEASE}（family=${DISTRO_FAMILY:-unknown}）"
    log_ok "CPU 架构：${ARCH_RAW}（${ARCH}）"
    if [[ ${ARCH_CONFLICT} -eq 1 ]]; then
        log_warn "架构交叉校验不一致：uname=${ARCH}，包管理器=${PM_ARCH}，判定结果将转为无法确认"
    fi
    log_ok "运行内核：${KERNEL_RELEASE}（分支 ${KERNEL_BRANCH}）"

    if [[ -n ${RUNNING_VERSION} ]]; then
        log_ok "内核软件包：${RUNNING_PKG} ${RUNNING_VERSION}"
    else
        log_warn "内核软件包：无法把运行内核 ${KERNEL_RELEASE} 映射到已安装的内核软件包"
    fi

    case "${DISTRO_FAMILY}" in
        debian)
            if [[ ${APT_SECURITY} -eq 1 ]]; then
                log_ok "软件源：${APT_SOURCE_COUNT} 个配置文件，已包含 security 源"
            else
                log_warn "软件源：${APT_SOURCE_COUNT} 个配置文件，未发现 security 源（可能无法获取修复内核）"
            fi
            if [[ ${MODE} != "fix" ]] && [[ ${HAS_APT_LISTS} -eq 0 ]]; then
                log_warn "APT 索引：本地元数据为空，本次不会更新索引，候选版本可能显示为未知"
            fi
            ;;
        rpm | suse)
            log_ok "软件源：${REPO_FILE_COUNT} 个仓库配置文件（${PM_NAME:-$(pm_name)}）"
            ;;
        alpine | arch)
            if [[ ${REPO_FILE_COUNT} -eq 1 ]]; then
                log_ok "软件源：已找到官方仓库配置"
            else
                log_warn "软件源：未找到仓库配置文件"
            fi
            ;;
    esac

    if [[ ${REBOOT_FLAG} -eq 1 ]]; then
        log_warn "待重启标记：/var/run/reboot-required 存在（系统有更新等待重启）"
    else
        log_ok "待重启标记：不存在"
    fi

    if [[ -n ${NEWEST_INSTALLED_ID} ]] && [[ ${NEWEST_INSTALLED_ID} != "${RUNNING_IDENT}" ]]; then
        log_warn "已安装内核 ${NEWEST_INSTALLED_ID} 与运行内核不一致（存在未生效的更新）"
    fi
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

report_status_exit() {
    case "${STATUS}" in
        "${ST_FIXED}") printf '%s\n' "${EX_OK}" ;;
        "${ST_PENDING}") printf '%s\n' "${EX_PENDING_REBOOT}" ;;
        "${ST_VULN_FIXABLE}") printf '%s\n' "${EX_VULNERABLE}" ;;
        "${ST_NOT_RELEASED}") printf '%s\n' "${EX_PATCH_NOT_RELEASED}" ;;
        "${ST_TESTING}") printf '%s\n' "${EX_PATCH_TESTING_ONLY}" ;;
        "${ST_UNSUPPORTED}") printf '%s\n' "${EX_ERROR}" ;;
        *) printf '%s\n' "${EX_UNKNOWN}" ;;
    esac
}

main() {
    parse_args "$@"

    case "${MODE}" in
        check | report) SECTION_TOTAL=2 ;;
        *) SECTION_TOTAL=4 ;;
    esac

    setup_colors

    if [[ ${MODE} == "list" ]]; then
        print_distro_table
        exit "${EX_OK}"
    fi

    print_banner
    require_root "$@"

    identify_distro || true
    PM_NAME="$(pm_name)"
    detect_kernel
    detect_arch
    distro_extra_detect

    if detect_container; then
        IS_CONTAINER=1
    fi

    kernel_resolve_running || true
    detect_reboot_flags
    detect_pm_sources
    detect_newest_installed || true

    print_environment
    assess
    print_assessment

    if [[ ${MODE} == "report" ]]; then
        if [[ -z ${REPORT_PATH} ]]; then
            REPORT_PATH="./cve-2026-98432-report-$(date '+%Y%m%d-%H%M%S').txt"
        fi
        write_report "${REPORT_PATH}" || exit "${EX_ERROR}"
        exit "$(report_status_exit)"
    fi

    case "${STATUS}" in
        "${ST_FIXED}")
            printf '\n%s无需操作：当前运行内核已包含该漏洞的修复。%s\n\n' "${C_GREEN}" "${C_RESET}"
            exit "${EX_OK}"
            ;;
        "${ST_UNSUPPORTED}")
            printf '\n%s本工具不支持当前系统，未做任何修改。%s\n' "${C_YELLOW}" "${C_RESET}"
            printf '  支持矩阵：sudo bash %s --list-distros\n\n' "${SCRIPT_NAME}"
            exit "${EX_ERROR}"
            ;;
        "${ST_UNKNOWN}")
            printf '\n%s建议：请先确认内核来源与软件包完整性，或参考 %s 手工判断。%s\n\n' \
                "${C_YELLOW}" "${ADVISORY_URL:-${ADAPTER_ADVISORY_URL:-官方公告}}" "${C_RESET}"
            exit "${EX_UNKNOWN}"
            ;;
        "${ST_NOT_RELEASED}")
            printf '\n%s官方尚未发布可确认的修复包，本脚本不会安装任何软件。%s\n' "${C_YELLOW}" "${C_RESET}"
            printf '  官方状态：%s\n' "${ADVISORY_URL:-${ADAPTER_ADVISORY_URL}}"
            printf '  建议：保持关注官方公告，发布修复包后更新本工具基线再执行。\n\n'
            exit "${EX_PATCH_NOT_RELEASED}"
            ;;
        "${ST_TESTING}")
            printf '\n%s官方只在 testing 仓库提供了修复包，生产仓库尚未发布。%s\n' "${C_YELLOW}" "${C_RESET}"
            printf '  官方依据：%s\n' "${ADVISORY:-未知}"
            printf '  测试版本：%s\n' "${FIXED_VERSION:-未知}"
            printf '  本脚本不会启用 testing 源，也不会安装测试内核。\n'
            printf '  建议：等待官方将该内核移入生产仓库后，更新本工具基线再执行。\n\n'
            exit "${EX_PATCH_TESTING_ONLY}"
            ;;
        "${ST_PENDING}")
            NEW_KERNEL_RELEASE="${INSTALLED_FIXED_RELEASE}"
            NEW_KERNEL_VERSION="${INSTALLED_FIXED_VERSION}"
            printf '\n%s修复内核已安装但尚未生效，请安排维护窗口重启。%s\n' "${C_YELLOW}" "${C_RESET}"
            print_reboot_notice
            exit "${EX_PENDING_REBOOT}"
            ;;
        "${ST_VULN_FIXABLE}")
            if [[ ${MODE} == "check" ]]; then
                if [[ ${AUTOFIX} -eq 1 ]]; then
                    printf '\n%s当前系统受 %s 影响，可执行以下命令修复：%s\n' "${C_YELLOW}" "${CVE_ID}" "${C_RESET}"
                    printf '    sudo bash %s\n\n' "${SCRIPT_NAME}"
                    if [[ ${DISTRO_FAMILY} == "debian" ]] && select_target_package; then
                        printf '  预计安装：%s（%s）\n\n' "${TARGET_PKG}" "${TARGET_VERSION}"
                    elif [[ ${DISTRO_FAMILY} == "rpm" ]] && select_target_rpm; then
                        printf '  预计安装：%s（%s）\n\n' "${TARGET_PKG}" "${TARGET_VERSION}"
                    elif [[ ${DISTRO_FAMILY} == "suse" ]] && select_target_suse; then
                        printf '  预计安装：%s（%s）\n\n' "${TARGET_PKG}" "${TARGET_VERSION}"
                    else
                        printf '  %s软件源中暂未找到可用的修复内核，请先检查官方仓库并刷新索引。%s\n\n' \
                            "${C_YELLOW}" "${C_RESET}"
                    fi
                else
                    # 只检测的发行版不能引导用户执行修复命令，否则与「未启用自动修复」自相矛盾。
                    printf '\n%s当前系统受 %s 影响，但该发行版未启用自动修复。%s\n\n' \
                        "${C_YELLOW}" "${CVE_ID}" "${C_RESET}"
                    printf '  请按官方公告手工升级内核，或等待本工具完成实机验证后再启用自动修复。\n'
                    printf '  官方状态：%s\n\n' "${ADVISORY_URL}"
                fi
                exit "${EX_VULNERABLE}"
            fi
            if [[ ${AUTOFIX} -ne 1 ]]; then
                log_warn "该发行版未启用自动修复（公告未核验或未完成适配），已停止，未做任何修改。"
                printf '  官方状态：%s\n\n' "${ADVISORY_URL}"
                exit "${EX_VULNERABLE}"
            fi
            run_fix
            ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
