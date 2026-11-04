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

# CloudLinux staged rollout：官方采用分批推送，即使公告已发布修复包，
# 本实例的官方仓库也可能还没拿到。查询只读，不刷新索引、不改仓库配置。
# 结果写入 CL_ROLLOUT_STATE：reached / pending / unknown
cloudlinux_check_rollout() {
    local cand=""

    CL_ROLLOUT_STATE="unknown"
    CL_ROLLOUT_CAND=""

    have rpm || return 0
    if ! cand="$(rpm_candidate "${BASELINE_PACKAGE:-kernel}")"; then
        return 0
    fi
    CL_ROLLOUT_CAND="${cand}"
    if version_ge_family "rpm" "${cand}" "${FIXED_VERSION}"; then
        CL_ROLLOUT_STATE="reached"
    else
        CL_ROLLOUT_STATE="pending"
    fi
    return 0
}

assess() {
    STATUS=""
    STATUS_REASON=""
    AUTOFIX=0
    INSTALLED_FIXED_RELEASE=""
    INSTALLED_FIXED_VERSION=""
    # 提前初始化，避免在提前返回的分支里被 print_assessment / write_report 读取时报 unbound
    BASE_STATUS=""
    FIXED_VERSION=""
    ADVISORY=""
    ADVISORY_URL=""
    BASELINE_VERIFIED=""
    BASELINE_NOTE=""
    BASELINE_PACKAGE=""
    BASELINE_AUTOFIX=""
    BASELINE_FAMILY=""
    BASELINE_CHANNEL=""
    BASELINE_STREAM=""
    BASELINE_ADV_STATUS=""
    BASELINE_TESTED_INSTALL=""
    BASELINE_TESTED_REBOOT=""
    BASELINE_PROCEDURE=""
    # CloudLinux 变体与内核流由 fix.sh 在 kernel_resolve_running 之后写入，
    # 这里只做「未赋值时补空」，不能在判定开始时清空，否则输出会丢掉变体信息。
    : "${CL_VARIANT:=}"
    : "${CL_STREAM:=}"
    CL_ROLLOUT_STATE=""
    CL_ROLLOUT_CAND=""

    # 1) 发行版身份
    if [[ -z ${DISTRO_FAMILY} ]] || [[ ${ADAPTER_DETECT_SUPPORTED:-0} -ne 1 ]]; then
        STATUS="${ST_UNSUPPORTED}"
        STATUS_REASON="当前系统 ${OS_PRETTY}（ID=${OS_ID:-未知}）不在本工具支持的发行版列表中，已停止，未做任何修改。"
        return 0
    fi

    # 1b) CloudLinux 身份交叉校验失败：宁可不判定，也不套用 RHEL/Ubuntu 的结论
    if [[ ${DISTRO_ID} == "cloudlinux" ]] && [[ ${CL_IDENTITY_OK:-1} -ne 1 ]]; then
        STATUS="${ST_UNKNOWN}"
        STATUS_REASON="CloudLinux 身份无法交叉确认：${CL_IDENTITY_REASON}"
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
    # 新适配发行版按「产品 + 版本 + 内核分支 + 软件包 + 架构」严格匹配：
    # 通配记录、flavor 不匹配或多条记录冲突都按 UNKNOWN 处理。
    if [[ ${ADAPTER_STRICT_BASELINE:-0} -eq 1 ]]; then
        local exact_rc=0
        baseline_lookup_exact "${ADAPTER_DATA_DISTRO}" "${DISTRO_RELEASE}" \
            "${KERNEL_BRANCH}" "${RUNNING_PKG}" "${ARCH}" "${PRODUCT_KEY:-}" || exact_rc=$?
        if [[ ${exact_rc} -eq 2 ]]; then
            STATUS="${ST_UNKNOWN}"
            STATUS_REASON="基线表中存在多条同时匹配的记录（${ADAPTER_NAME} ${DISTRO_RELEASE} / ${KERNEL_BRANCH} / ${RUNNING_PKG} / ${ARCH}），无法确定唯一修复版本，已停止。"
            return 0
        fi
        if [[ ${exact_rc} -ne 0 ]]; then
            STATUS="${ST_UNKNOWN}"
            STATUS_REASON="基线表未收录该组合（${ADAPTER_NAME} ${DISTRO_RELEASE} / 内核 ${KERNEL_BRANCH} / 包 ${RUNNING_PKG} / 架构 ${ARCH}），无法确认安全状态。"
            return 0
        fi
    elif ! baseline_lookup "${ADAPTER_DATA_DISTRO}" "${DISTRO_RELEASE}" "${KERNEL_BRANCH}"; then
        STATUS="${ST_UNKNOWN}"
        STATUS_REASON="运行内核分支 ${KERNEL_BRANCH} 不在已核实的修复版本表中（${ADAPTER_NAME} ${DISTRO_RELEASE}），无法确认安全状态。"
        return 0
    fi

    case "${BASE_STATUS}" in
        fixed)
            ;;
        not_affected)
            STATUS="${ST_NOT_AFFECTED}"
            STATUS_REASON="官方说明该内核分支不受 ${CVE_ID} 影响（${ADVISORY}，核验日期 ${BASELINE_VERIFIED}）：${BASELINE_NOTE}"
            return 0
            ;;
        testing)
            STATUS="${ST_TESTING}"
            STATUS_REASON="官方仅在 testing 仓库提供修复包（${ADVISORY}，核验日期 ${BASELINE_VERIFIED}）：${BASELINE_NOTE}"
            return 0
            ;;
        patch_not_released | in_progress)
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

    # 7b) CloudLinux staged rollout：官方已发布不等于本实例可获取。
    if [[ ${DISTRO_ID} == "cloudlinux" ]] && [[ ${BASELINE_ADV_STATUS} == "staged_rollout" ]]; then
        cloudlinux_check_rollout
    fi

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

    # CloudLinux：区分「官方已发布」「本实例已收到推送」「无法确认」三种情况，
    # 未收到推送或无法确认时绝不安装，也不启用 rollout bypass。
    if [[ ${DISTRO_ID} == "cloudlinux" ]] && [[ ${BASELINE_ADV_STATUS} == "staged_rollout" ]]; then
        case "${CL_ROLLOUT_STATE}" in
            pending)
                STATUS_REASON="官方已发布修复包 ${FIXED_VERSION}，但当前实例尚未进入 staged rollout（官方仓库候选 ${CL_ROLLOUT_CAND:-未知}）。本工具不会启用 rollout bypass，也不会安装任何软件。"
                ;;
            unknown)
                STATUS_REASON="官方已发布修复包 ${FIXED_VERSION}，但无法确认当前实例是否已收到 staged rollout 推送（仓库元数据不可用或查询失败）。本工具不会安装任何软件。"
                ;;
            *)
                STATUS_REASON="当前运行内核软件包版本 ${RUNNING_VERSION} 低于官方修复版本 ${FIXED_VERSION}（分支 ${KERNEL_BRANCH}），官方仓库候选 ${CL_ROLLOUT_CAND:-未知} 已达标。"
                ;;
        esac
    fi

    # 自动修复需要三重条件：适配器默认允许、基线显式 autofix、严格模式下
    # 还必须具备真实安装与重启验证记录（容器/模拟测试不算）。
    # CloudLinux 额外要求本实例的 rollout 已真正推送，否则不得安装。
    local rollout_ok=1
    if [[ ${DISTRO_ID} == "cloudlinux" ]] && [[ ${BASELINE_ADV_STATUS} == "staged_rollout" ]] &&
        [[ ${CL_ROLLOUT_STATE} != "reached" ]]; then
        rollout_ok=0
    fi
    if [[ ${rollout_ok} -eq 1 ]] && [[ ${ADAPTER_AUTOFIX_DEFAULT} -eq 1 ]] && [[ ${BASELINE_AUTOFIX} == "yes" ]]; then
        if [[ ${ADAPTER_STRICT_BASELINE:-0} -ne 1 ]] ||
            { [[ ${BASELINE_TESTED_INSTALL} == "yes" ]] && [[ ${BASELINE_TESTED_REBOOT} == "yes" ]]; }; then
            AUTOFIX=1
        fi
    fi
    return 0
}

# 「自动修复」一行描述的是这台机器当前能不能用本工具装包。
# 已修复、待重启、不受影响、状态未确认时，AUTOFIX 本来就不会被置 1，
# 若一律显示「未启用（仅检测）」会让人误以为该发行版不支持自动修复。
autofix_label() {
    case "${STATUS}" in
        "${ST_FIXED}") printf '不适用（已修复）' ;;
        "${ST_PENDING}") printf '不适用（等待重启）' ;;
        "${ST_NOT_AFFECTED}") printf '不适用（不受影响）' ;;
        "${ST_UNSUPPORTED}") printf '不可用（不支持的系统）' ;;
        "${ST_UNKNOWN}") printf '不可用（状态未确认）' ;;
        *) if [[ ${AUTOFIX} -eq 1 ]]; then printf '已启用'; else printf '未启用（仅检测）'; fi ;;
    esac
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
    if [[ -n ${CL_VARIANT} ]]; then
        kv "CloudLinux" "${CL_VARIANT}"
    fi
    kv "修复版本" "${FIXED_VERSION:-未知}"
    if [[ -n ${BASELINE_CHANNEL} ]]; then
        kv "仓库渠道" "${BASELINE_CHANNEL}"
    fi
    if [[ -n ${CL_ROLLOUT_STATE} ]]; then
        case "${CL_ROLLOUT_STATE}" in
            reached) kv "Rollout" "已推送到本实例（候选 ${CL_ROLLOUT_CAND}）" ;;
            pending) kv "Rollout" "尚未推送到本实例（候选 ${CL_ROLLOUT_CAND:-未知}）" ;;
            *) kv "Rollout" "无法确认（仓库元数据不可用）" ;;
        esac
    fi
    # SUSE Micro 等产品必须走 transactional-update，普通 zypper 安装流程不适用；
    # 这类信息必须显式告知用户，否则「有修复包」会被误解为「可以直接装」。
    if [[ -n ${BASELINE_PROCEDURE} ]]; then
        kv "更新方式" "${BASELINE_PROCEDURE}"
    fi
    kv "运行内核" "${KERNEL_RELEASE}"
    kv "运行版本" "${RUNNING_VERSION:-未知}"
    kv "自动修复" "$(autofix_label)"

    case "${STATUS}" in
        "${ST_FIXED}")
            printf '  %s判定结果：已修复%s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
            ;;
        "${ST_NOT_AFFECTED}")
            printf '  %s判定结果：不受影响%s\n' "${C_GREEN}${C_BOLD}" "${C_RESET}"
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
        "${ST_TESTING}")
            printf '  %s判定结果：仅测试仓库有补丁%s\n' "${C_YELLOW}${C_BOLD}" "${C_RESET}"
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
