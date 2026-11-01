#!/usr/bin/env bash
#
# lib/report.sh - --list-distros 与 --report
#
# 报告只写入白名单字段：不含环境变量、不含 /etc/shadow、不含任何凭据，
# 也不读取 SSH 私钥、token 或业务配置。

# STATUS / STATUS_REASON / AUTOFIX 等全局状态由 fix.sh 初始化，ShellCheck
# 无法跨文件看到赋值，会误判为可能拼写错误，故在此关闭 SC2153。
# shellcheck disable=SC2153
ADAPTER_IDS=(debian ubuntu amazon_linux rhel rocky almalinux oracle_linux fedora suse arch alpine)

# 按显示宽度补空格（CJK 按 2 列计）
pad_cjk() {
    local text="$1" width="$2" len=0 pad=""
    len=$(display_width "${text}")
    while ((len < width)); do
        pad+=" "
        len=$((len + 1))
    done
    printf '%s%s' "${text}" "${pad}"
}

status_label() {
    case "$1" in
        fixed) printf '官方已修复' ;;
        testing) printf '仅测试仓库' ;;
        patch_not_released) printf '官方未修复' ;;
        *) printf '无法确认' ;;
    esac
}

print_distro_table() {
    load_baseline_db || true

    printf '\n%s支持矩阵%s（基线核验日期见最后一列）\n' "${C_BOLD}" "${C_RESET}"
    printf '%s\n' "─────────────────────────────────────────────────────────────────────────────"

    printf '%s' "$(pad_cjk "发行版" 26)"
    printf '%s' "$(pad_cjk "检测" 8)"
    printf '%s' "$(pad_cjk "自动修复" 12)"
    printf '%s' "$(pad_cjk "官方补丁状态" 18)"
    printf '%s\n' "核验日期"

    local id="" file="" summary="" autofix="" status="" verified="" name=""
    for id in "${ADAPTER_IDS[@]}"; do
        file="${LIB_ROOT}/adapters/${id}.sh"
        [[ -r ${file} ]] || continue
        # 子 shell 中读取 adapter 声明，避免污染主流程的全局变量
        summary="$(
            # shellcheck source=/dev/null
            source "${file}"
            data_distro="${ADAPTER_DATA_DISTRO}"
            summary_line="$(adapter_summary_status "${data_distro}")"
            printf '%s\t%s\n' "${ADAPTER_NAME}" "${summary_line}"
        )"
        name="${summary%%$'\t'*}"
        summary="${summary#*$'\t'}"
        autofix="${summary%%|*}"
        summary="${summary#*|}"
        status="${summary%%|*}"
        summary="${summary#*|}"
        verified="${summary%%|*}"
        # 末段「说明」不进入表格，这里显式丢弃，保留字段分隔便于后续扩展
        : "${summary#*|}"

        printf '%s' "$(pad_cjk "${name}" 26)"
        printf '%s' "$(pad_cjk "支持" 8)"
        if [[ ${autofix} == "yes" ]]; then
            printf '%s' "$(pad_cjk "支持" 12)"
        else
            printf '%s' "$(pad_cjk "仅检测" 12)"
        fi
        printf '%s' "$(pad_cjk "$(status_label "${status}")" 18)"
        printf '%s\n' "${verified:-未核验}"
    done

    printf '%s\n' "─────────────────────────────────────────────────────────────────────────────"
    printf '说明：\n'
    printf '  * 「检测」= 能识别发行版并映射运行内核；「自动修复」= 官方修复包已核验且允许安装。\n'
    printf '  * 未启用自动修复的发行版不会执行任何安装命令，只输出状态与官方公告链接。\n'
    printf '  * 修复基线为人工核验后维护（data/%s.yml），不是实时在线同步。\n\n' "${CVE_ID,,}"
}

# 生成不含敏感信息的本地报告
write_report() {
    local path="$1" tmp=""

    tmp="$(mktemp "${TMPDIR:-/tmp}/cve-report.XXXXXX")"
    {
        printf 'CVE 检测报告\n'
        printf '============\n\n'
        printf '漏洞编号      : %s\n' "${CVE_ID}"
        printf '官方公告      : %s\n' "${ADVISORY_URL:-${ADAPTER_ADVISORY_URL:-未知}}"
        printf '公告编号      : %s\n' "${ADVISORY:-未知}"
        printf '基线核验日期  : %s\n' "${BASELINE_VERIFIED:-未核验}"
        printf '脚本版本      : %s\n' "${SCRIPT_VERSION}"
        printf '生成时间(UTC) : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        printf '主机名        : %s\n' "$(hostname 2>/dev/null || printf 'unknown')"
        printf '\n'
        printf '[系统]\n'
        printf '发行版        : %s\n' "${OS_PRETTY}"
        printf '发行版标识    : %s %s\n' "${DISTRO_ID}" "${DISTRO_RELEASE}"
        printf '包管理家族    : %s (%s)\n' "${DISTRO_FAMILY:-unknown}" "$(pm_name)"
        printf 'CPU 架构      : %s (%s)\n' "${ARCH_RAW}" "${ARCH}"
        printf '容器环境      : %s\n' "$([[ ${IS_CONTAINER} -eq 1 ]] && printf '是（%s）' "${CONTAINER_KIND}" || printf '否')"
        printf '\n'
        printf '[内核]\n'
        printf '运行内核      : %s\n' "${KERNEL_RELEASE}"
        printf '内核分支      : %s\n' "${KERNEL_BRANCH}"
        printf '内核 flavor   : %s\n' "${KERNEL_FLAVOR:-未知}"
        printf '内核流        : %s\n' "${BASELINE_STREAM:-未知}"
        printf '对应软件包    : %s\n' "${RUNNING_PKG:-未知}"
        printf '软件包版本    : %s\n' "${RUNNING_VERSION:-未知}"
        printf '待重启标记    : %s\n' "$([[ ${REBOOT_FLAG} -eq 1 ]] && printf '存在' || printf '不存在')"
        printf '\n'
        printf '[判定]\n'
        printf '状态          : %s\n' "${STATUS}"
        printf '说明          : %s\n' "${STATUS_REASON}"
        printf '自动修复      : %s\n' "$([[ ${AUTOFIX} -eq 1 ]] && printf '可用' || printf '不可用（仅检测）')"
        printf '修复版本基准  : %s\n' "${FIXED_VERSION:-未知}"
        printf '仓库渠道      : %s\n' "${BASELINE_CHANNEL:-未知}"
        printf '更新方式      : %s\n' "${BASELINE_PROCEDURE:-常规包管理器升级}"
        printf '实机验证      : 安装 %s / 重启 %s\n' \
            "${BASELINE_TESTED_INSTALL:-未记录}" "${BASELINE_TESTED_REBOOT:-未记录}"
        printf '\n'
        printf '[备注]\n'
        printf '%s\n' "${BASELINE_NOTE:-无}"
        printf '\n报告不包含密码、令牌、私钥或业务配置内容。\n'
    } >"${tmp}"

    if ! mv "${tmp}" "${path}" 2>/dev/null; then
        rm -f "${tmp}"
        log_err "无法写入报告文件：${path}"
        return 1
    fi
    log_ok "检测报告已生成：${path}"
}
