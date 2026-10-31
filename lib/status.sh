#!/usr/bin/env bash
#
# lib/status.sh - 统一漏洞状态机
#
# 六个状态互斥：
#   FIXED                       当前运行内核达标
#   PENDING_REBOOT              修复内核已安装但未重启
#   VULNERABLE_PATCH_AVAILABLE  官方修复包可用，当前内核仍受影响
#   PATCH_NOT_RELEASED          官方尚未发布可确认修复包
#   UNKNOWN                     公告/内核来源/包映射/版本无法确认
#   UNSUPPORTED                 系统、架构或内核 flavor 不支持

# ShellCheck 单文件分析看不到跨文件使用点：本文件产出的全局状态由
# fix.sh / lib/*.sh / adapters/*.sh 读取，故整体关闭「变量未使用」提示。
# shellcheck disable=SC2034

arch_in_list() {
    local list="$1" want="$2" item=""
    local -a _items=()
    IFS=',' read -r -a _items <<<"${list}"
    for item in "${_items[@]}"; do
        item="${item// /}"
        if [[ ${item} == "${want}" ]]; then
            return 0
        fi
    done
    return 1
}

assess() {
    STATUS=""
    STATUS_REASON=""
    AUTOFIX=0
    INSTALLED_FIXED_RELEASE=""
    INSTALLED_FIXED_VERSION=""

    # 1) 发行版身份
    if [[ -z ${DISTRO_FAMILY} ]] || [[ ${ADAPTER_DETECT_SUPPORTED:-0} -ne 1 ]]; then
        STATUS="${ST_UNSUPPORTED}"
        STATUS_REASON="当前系统 ${OS_PRETTY}（ID=${OS_ID:-未知}）不在本工具支持的发行版列表中，已停止，未做任何修改。"
        return 0
    fi

    # 2) 发行版版本：adapter 显式声明支持的版本范围
    if [[ -n ${ADAPTER_RELEASES:-} ]] && ! arch_in_list "${ADAPTER_RELEASES}" "${DISTRO_RELEASE}"; then
        STATUS="${ST_UNSUPPORTED}"
        STATUS_REASON="${ADAPTER_SUPPORTED_TEXT:-本工具在 ${ADAPTER_NAME} 上仅支持版本 ${ADAPTER_RELEASES}（当前 ${DISTRO_RELEASE}），已停止，未做任何修改。}"
        return 0
    fi

    # 3) 容器环境：uname -r 是宿主机内核，无法可靠映射，必须 fail closed
    if [[ ${IS_CONTAINER} -eq 1 ]]; then
        STATUS="${ST_UNKNOWN}"
        STATUS_REASON="检测到容器环境（${CONTAINER_KIND}）：容器内的 uname -r 指向宿主机内核，无法可靠映射到容器内的内核软件包，因此不做判定，也不允许自动修复。"
        return 0
    fi

    # 4) 架构：只有可能自动修复的发行版才强制架构白名单（检测型发行版不拦截）
    if [[ ${ADAPTER_AUTOFIX_DEFAULT} -eq 1 ]] && ! arch_in_list "${ADAPTER_ARCHES}" "${ARCH}"; then
        STATUS="${ST_UNSUPPORTED}"
        STATUS_REASON="本工具在 ${ADAPTER_NAME} 上仅支持 ${ADAPTER_ARCHES} 架构（当前 ${ARCH_RAW} / ${ARCH}），已停止，未做任何修改。"
        return 0
    fi

    # 5) 架构冲突：uname 与包管理器不一致时不做任何猜测
    if [[ ${ARCH_CONFLICT} -eq 1 ]]; then
        STATUS="${ST_UNKNOWN}"
        STATUS_REASON="uname 报告的架构（${ARCH}）与包管理器报告的架构（${PM_ARCH}）不一致，无法确认环境，已停止。"
        return 0
    fi

    # 6) 运行内核 -> 软件包映射
    if [[ -z ${RUNNING_VERSION} ]]; then
        STATUS="${ST_UNKNOWN}"
        STATUS_REASON="无法将运行内核 ${KERNEL_RELEASE} 映射到已安装的内核软件包（可能为自编译或第三方内核），无法确认安全状态。"
        return 0
    fi

    # 7) 官方基线
    if ! baseline_lookup "${ADAPTER_DATA_DISTRO}" "${DISTRO_RELEASE}" "${KERNEL_BRANCH}"; then
        STATUS="${ST_UNKNOWN}"
        STATUS_REASON="运行内核分支 ${KERNEL_BRANCH} 不在已核实的修复版本表中（${ADAPTER_NAME} ${DISTRO_RELEASE}），无法确认安全状态。"
        return 0
    fi

    case "${BASE_STATUS}" in
        fixed)
            ;;
        patch_not_released)
            STATUS="${ST_NOT_RELEASED}"
            STATUS_REASON="官方尚未发布可确认的修复包（${ADVISORY}，核验日期 ${BASELINE_VERIFIED}），本机仍可能受影响，但无包可装。"
            return 0
            ;;
        *)
            STATUS="${ST_UNKNOWN}"
            STATUS_REASON="官方公告状态无法核验或缺少可确认的修复版本（${ADVISORY}，核验日期 ${BASELINE_VERIFIED}）：${BASELINE_NOTE}"
            return 0
            ;;
    esac

    # 8) 版本判定
    if version_ge_family "${DISTRO_FAMILY}" "${RUNNING_VERSION}" "${FIXED_VERSION}"; then
        STATUS="${ST_FIXED}"
        STATUS_REASON="当前运行内核软件包版本 ${RUNNING_VERSION} 已达到官方修复版本 ${FIXED_VERSION}。"
        AUTOFIX=0
        return 0
    fi

    local found=""
    if found="$(find_fixed_installed_kernel)"; then
        INSTALLED_FIXED_RELEASE="${found%%$'\t'*}"
        INSTALLED_FIXED_VERSION="${found##*$'\t'}"
        STATUS="${ST_PENDING}"
        STATUS_REASON="修复版本内核 ${INSTALLED_FIXED_RELEASE} 已安装，但当前仍运行 ${KERNEL_RELEASE}，需要重启后才会生效。"
        AUTOFIX=0
        return 0
    fi

    STATUS="${ST_VULN_FIXABLE}"
    STATUS_REASON="当前运行内核软件包版本 ${RUNNING_VERSION} 低于官方修复版本 ${FIXED_VERSION}（分支 ${KERNEL_BRANCH}）。"

    if [[ ${ADAPTER_AUTOFIX_DEFAULT} -eq 1 ]] && [[ ${BASELINE_AUTOFIX} == "yes" ]]; then
        AUTOFIX=1
    fi
    return 0
}

print_assessment() {
    local flavor_label="${KERNEL_FLAVOR}"

    # RPM 系同一个发行版可能有多个内核包（如 AL2023 的 kernel / kernel6.12 / kernel6.18），
    # 这里显示真实的运行内核包名，避免只看到笼统的「kernel」。
    if [[ ${DISTRO_FAMILY} == "rpm" ]] && [[ -n ${RUNNING_PKG} ]]; then
        flavor_label="${RUNNING_PKG}"
    fi

    step_title 2 "漏洞状态判定"
    kv "漏洞编号" "${CVE_ID}"
    kv "发行版" "${OS_PRETTY}"
    kv "发行版标识" "${DISTRO_ID} ${DISTRO_RELEASE}${flavor_label:+ / ${flavor_label}}"
    kv "官方依据" "${ADVISORY:-未知}${BASELINE_FAMILY:+（${BASELINE_FAMILY} 包管理）}"
    kv "基线核对" "${BASELINE_VERIFIED:-未核验} · ${ADVISORY_URL:-${ADAPTER_ADVISORY_URL:-}}"
    kv "内核分支" "${KERNEL_BRANCH}"
    kv "修复版本" "${FIXED_VERSION:-未知}"
    kv "运行内核" "${KERNEL_RELEASE}"
    kv "运行版本" "${RUNNING_VERSION:-未知}"
    kv "自动修复" "$([[ ${AUTOFIX} -eq 1 ]] && printf '已启用' || printf '未启用（仅检测）')"

    case "${STATUS}" in
        "${ST_FIXED}")
            printf '  %s判定结果：已修复%s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
            ;;
        "${ST_PENDING}")
            printf '  %s判定结果：待重启%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
            ;;
        "${ST_VULN_FIXABLE}")
            printf '  %s判定结果：存在漏洞%s\n' "${C_RED}${C_BOLD}" "${C_RESET}"
            ;;
        "${ST_NOT_RELEASED}")
            printf '  %s判定结果：官方尚未修复%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
            ;;
        "${ST_UNSUPPORTED}")
            printf '  %s判定结果：不支持%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
            ;;
        *)
            printf '  %s判定结果：无法确认%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
            ;;
    esac
    printf '  %s\n' "${STATUS_REASON}"
}
