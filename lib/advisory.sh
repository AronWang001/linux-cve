#!/usr/bin/env bash
#
# lib/advisory.sh - 官方修复基线（本地、人工核验后维护）
#
# 基线来自 data/cve-2026-98432.yml，字段含义见该文件头部注释。
# 本模块不做在线抓取：README 明确说明核验日期与更新方式，
# 不宣称实时同步；无法核验时一律返回 UNKNOWN。

# 基线数据用平行数组保存，字段由 baseline_lookup 读取并映射为 BASE_* / FIXED_VERSION。
# ShellCheck 单文件分析看不到这些读取点，故对本段关闭「未使用」提示。
# shellcheck disable=SC2034
declare -a B_ID=()
declare -a B_DISTRO=()
declare -a B_NAME=()
declare -a B_RELEASE=()
declare -a B_CODENAME=()
declare -a B_FAMILY=()
declare -a B_BRANCH=()
declare -a B_FLAVORS=()
declare -a B_ARCHES=()
declare -a B_PACKAGE=()
declare -a B_STATUS=()
declare -a B_FIXED=()
declare -a B_ADVISORY=()
declare -a B_ADVISORY_URL=()
declare -a B_REPO=()
declare -a B_PROCEDURE=()
declare -a B_AUTOFIX=()
declare -a B_VERIFIED=()
declare -a B_NOTES=()
# v1.2.0 新增：产品/SP/内核流/flavor/仓库渠道/公告状态/实测标记
declare -a B_PRODUCT=()
declare -a B_SP=()
declare -a B_STREAM=()
declare -a B_FLAVOR=()
declare -a B_CHANNEL=()
declare -a B_ADV_STATUS=()
declare -a B_TEST_INSTALL=()
declare -a B_TEST_REBOOT=()

# shellcheck disable=SC2034  # 由 baseline_lookup / write_report 等读取
BASELINE_COUNT=0
BASELINE_FILE=""
BASELINE_LOADED=0

# 去掉值两侧的引号
# 结果写入 UNQUOTED 而不是标准输出：基线有上百个字段，
# 每字段一次 $(...) 会 fork 一个子 shell，在 Git Bash/Windows 上累计到分钟级。
_unquote() {
    local v="$1"
    v="${v%\"}"
    v="${v#\"}"
    v="${v%\'}"
    v="${v#\'}"
    UNQUOTED="${v}"
}

load_baseline_db() {
    [[ ${BASELINE_LOADED} -eq 1 ]] && return 0

    BASELINE_FILE="${LIB_ROOT}/data/${CVE_ID,,}.yml"
    if [[ ! -r ${BASELINE_FILE} ]]; then
        return 1
    fi

    local line="" key="" val="" cur=-1
    while IFS= read -r line || [[ -n ${line} ]]; do
        line="${line%$'\r'}"
        [[ ${line} =~ ^[[:space:]]*# ]] && continue
        [[ -z ${line//[[:space:]]/} ]] && continue

        if [[ ${line} == "- "* ]]; then
            cur=${BASELINE_COUNT}
            BASELINE_COUNT=$((BASELINE_COUNT + 1))
            # 先给所有字段置空，避免可选字段在 set -u 下被读取时报 unbound
            B_ID[cur]="" B_DISTRO[cur]="" B_NAME[cur]="" B_RELEASE[cur]=""
            B_CODENAME[cur]="" B_FAMILY[cur]="" B_BRANCH[cur]="" B_FLAVORS[cur]=""
            B_ARCHES[cur]="" B_PACKAGE[cur]="" B_STATUS[cur]="" B_FIXED[cur]=""
            B_ADVISORY[cur]="" B_ADVISORY_URL[cur]="" B_REPO[cur]="" B_PROCEDURE[cur]=""
            B_AUTOFIX[cur]="" B_VERIFIED[cur]="" B_NOTES[cur]=""
            B_PRODUCT[cur]="" B_SP[cur]="" B_STREAM[cur]="" B_FLAVOR[cur]=""
            B_CHANNEL[cur]="" B_ADV_STATUS[cur]="" B_TEST_INSTALL[cur]="" B_TEST_REBOOT[cur]=""
            line="${line#- }"
        fi
        [[ ${cur} -lt 0 ]] && continue
        [[ ${line} == *:* ]] || continue

        key="${line%%:*}"
        key="${key//[[:space:]]/}"
        val="${line#*:}"
        val="${val# }"
        _unquote "${val}"
        val="${UNQUOTED}"

        case "${key}" in
            id) B_ID[cur]="${val}" ;;
            distro) B_DISTRO[cur]="${val}" ;;
            name) B_NAME[cur]="${val}" ;;
            release) B_RELEASE[cur]="${val}" ;;
            codename) B_CODENAME[cur]="${val}" ;;
            family) B_FAMILY[cur]="${val}" ;;
            branch) B_BRANCH[cur]="${val}" ;;
            flavors) B_FLAVORS[cur]="${val}" ;;
            architectures) B_ARCHES[cur]="${val}" ;;
            package) B_PACKAGE[cur]="${val}" ;;
            status) B_STATUS[cur]="${val}" ;;
            fixed_version) B_FIXED[cur]="${val}" ;;
            advisory) B_ADVISORY[cur]="${val}" ;;
            advisory_url) B_ADVISORY_URL[cur]="${val}" ;;
            repo) B_REPO[cur]="${val}" ;;
            update_procedure) B_PROCEDURE[cur]="${val}" ;;
            autofix) B_AUTOFIX[cur]="${val}" ;;
            verified) B_VERIFIED[cur]="${val}" ;;
            notes) B_NOTES[cur]="${val}" ;;
            product) B_PRODUCT[cur]="${val}" ;;
            service_pack) B_SP[cur]="${val}" ;;
            kernel_stream) B_STREAM[cur]="${val}" ;;
            kernel_flavor) B_FLAVOR[cur]="${val}" ;;
            repo_channel) B_CHANNEL[cur]="${val}" ;;
            advisory_status) B_ADV_STATUS[cur]="${val}" ;;
            tested_install) B_TEST_INSTALL[cur]="${val}" ;;
            tested_reboot) B_TEST_REBOOT[cur]="${val}" ;;
        esac
    done <"${BASELINE_FILE}"

    BASELINE_LOADED=1
    [[ ${BASELINE_COUNT} -gt 0 ]]
}

# 按 distro + release + 内核分支查找基线，结果写入 BASE_* 全局变量
# 返回 0 命中 / 1 未收录
baseline_lookup() {
    local distro="$1" release="$2" branch="$3"
    local i=0 r="" b="" score=0 best=0 best_score=-1

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
    BASELINE_RELEASE=""
    BASELINE_BRANCH=""
    BASELINE_FLAVORS=""
    BASELINE_ARCHES=""

    load_baseline_db || return 1

    for ((i = 0; i < BASELINE_COUNT; i++)); do
        [[ ${B_DISTRO[i]} == "${distro}" ]] || continue
        r="${B_RELEASE[i]}"
        b="${B_BRANCH[i]}"
        score=0
        if [[ ${r} == "${release}" ]]; then
            score=2
        elif [[ ${r} == "*" ]]; then
            score=0
        else
            continue
        fi
        if [[ ${b} == "${branch}" ]]; then
            score=$((score + 2))
        elif [[ ${b} == "*" ]]; then
            score=$((score + 1))
        else
            continue
        fi
        if ((score > best_score)); then
            best_score=${score}
            best=${i}
        fi
    done

    ((best_score < 0)) && return 1

    # shellcheck disable=SC2034  # 保留索引，便于调试与后续扩展
    BASE_INDEX=${best}
    BASE_STATUS="${B_STATUS[best]}"
    FIXED_VERSION="${B_FIXED[best]}"
    ADVISORY="${B_ADVISORY[best]}"
    ADVISORY_URL="${B_ADVISORY_URL[best]}"
    BASELINE_VERIFIED="${B_VERIFIED[best]}"
    BASELINE_NOTE="${B_NOTES[best]}"
    BASELINE_PACKAGE="${B_PACKAGE[best]}"
    BASELINE_AUTOFIX="${B_AUTOFIX[best]}"
    BASELINE_FAMILY="${B_FAMILY[best]}"
    BASELINE_RELEASE="${B_RELEASE[best]}"
    BASELINE_BRANCH="${B_BRANCH[best]}"
    BASELINE_FLAVORS="${B_FLAVORS[best]}"
    BASELINE_ARCHES="${B_ARCHES[best]}"
    BASELINE_PROCEDURE="${B_PROCEDURE[best]}"
    return 0
}

# 严格匹配：产品 + 版本 + 内核分支 + 软件包 + 架构全部命中才返回结果
# 参数：distro release branch package arch
# 返回：0 唯一命中，1 无记录，2 多条记录冲突（必须按 UNKNOWN 处理）
# 与 baseline_lookup 的区别：不接受 flavor/架构的「恰好匹配」，
# 避免一条通配记录把整个发行版家族误判为已修复。
baseline_lookup_exact() {
    local distro="$1" release="$2" branch="$3" pkg="$4" arch="$5" prod="${6:-}"
    local i=0 score=0 best_score=-1 best=-1 ties=0
    local r="" b="" p="" a="" pr=""

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
    BASELINE_RELEASE=""
    BASELINE_BRANCH=""
    BASELINE_FLAVORS=""
    BASELINE_ARCHES=""
    BASELINE_CHANNEL=""
    BASELINE_STREAM=""
    BASELINE_ADV_STATUS=""
    BASELINE_TESTED_INSTALL=""
    BASELINE_TESTED_REBOOT=""
    BASELINE_PROCEDURE=""

    load_baseline_db || return 1

    for ((i = 0; i < BASELINE_COUNT; i++)); do
        [[ ${B_DISTRO[i]} == "${distro}" ]] || continue
        r="${B_RELEASE[i]}"
        b="${B_BRANCH[i]}"
        p="${B_PACKAGE[i]}"
        a="${B_ARCHES[i]}"
        pr="${B_PRODUCT[i]}"

        # 产品必须匹配：openSUSE Leap 16.0 与 SLES 16.0 的 release/包名相同，
        # 只有 product 能区分两者的公告与仓库。
        if [[ -n ${pr} ]]; then
            [[ ${pr} == "${prod}" ]] || continue
        fi

        # 每条记录从 0 开始计分：缺少 package 字段的记录（如整版 UNKNOWN）
        # 若沿用上一条的分数，会与真实命中并列，把唯一命中变成「冲突」。
        score=0

        # 软件包必须精确匹配：kernel-default 与 kernel-default-base 的 EVR 不同
        if [[ -n ${p} ]]; then
            [[ ${p} == "${pkg}" ]] || continue
            score=4
        fi

        if [[ -n ${a} ]]; then
            if ! arch_in_list "${a}" "${arch}"; then
                continue
            fi
        fi

        if [[ ${r} == "${release}" ]]; then
            score=$((score + 4))
        elif [[ ${r} == "*" ]]; then
            :
        else
            continue
        fi

        if [[ ${b} == "${branch}" ]]; then
            score=$((score + 2))
        elif [[ ${b} == "*" ]]; then
            :
        else
            continue
        fi

        if ((score > best_score)); then
            best_score=${score}
            best=${i}
            ties=0
        elif ((score == best_score)); then
            ties=$((ties + 1))
        fi
    done

    ((best < 0)) && return 1
    ((ties > 0)) && return 2

    # shellcheck disable=SC2034  # 保留索引，便于调试与后续扩展
    BASE_INDEX=${best}
    BASE_STATUS="${B_STATUS[best]}"
    FIXED_VERSION="${B_FIXED[best]}"
    ADVISORY="${B_ADVISORY[best]}"
    ADVISORY_URL="${B_ADVISORY_URL[best]}"
    BASELINE_VERIFIED="${B_VERIFIED[best]}"
    BASELINE_NOTE="${B_NOTES[best]}"
    BASELINE_PACKAGE="${B_PACKAGE[best]}"
    BASELINE_AUTOFIX="${B_AUTOFIX[best]}"
    BASELINE_FAMILY="${B_FAMILY[best]}"
    BASELINE_RELEASE="${B_RELEASE[best]}"
    BASELINE_BRANCH="${B_BRANCH[best]}"
    BASELINE_FLAVORS="${B_FLAVORS[best]}"
    BASELINE_ARCHES="${B_ARCHES[best]}"
    BASELINE_CHANNEL="${B_CHANNEL[best]}"
    BASELINE_STREAM="${B_STREAM[best]}"
    BASELINE_ADV_STATUS="${B_ADV_STATUS[best]}"
    BASELINE_TESTED_INSTALL="${B_TEST_INSTALL[best]}"
    BASELINE_TESTED_REBOOT="${B_TEST_REBOOT[best]}"
    BASELINE_PROCEDURE="${B_PROCEDURE[best]}"
    return 0
}

# 汇总某个发行版在基线表中的状态，供 --list-distros 使用
# 输出：autofix | status | verified | 说明
# 注意：一条记录 fixed 只代表「该产品/版本/flavor/架构」有修复包，
# 不能据此宣称整个发行版家族都支持自动修复。
adapter_summary_status() {
    local distro="$1"
    local i=0 n_fixed=0 n_testing=0 n_pending=0 n_unknown=0
    local verified="" autofix="no" branches=0

    load_baseline_db || {
        printf 'no|unknown||基线文件缺失\n'
        return 0
    }

    for ((i = 0; i < BASELINE_COUNT; i++)); do
        [[ ${B_DISTRO[i]} == "${distro}" ]] || continue
        branches=$((branches + 1))
        if [[ ${B_VERIFIED[i]} > ${verified} ]]; then
            verified="${B_VERIFIED[i]}"
        fi
        case "${B_STATUS[i]}" in
            fixed) n_fixed=$((n_fixed + 1)) ;;
            testing) n_testing=$((n_testing + 1)) ;;
            patch_not_released | in_progress) n_pending=$((n_pending + 1)) ;;
            *) n_unknown=$((n_unknown + 1)) ;;
        esac
        if [[ ${B_AUTOFIX[i]} == "yes" ]]; then
            autofix="yes"
        fi
    done

    if ((branches == 0)); then
        printf 'no|unknown||未收录\n'
        return 0
    fi
    if ((n_fixed > 0)); then
        if [[ ${autofix} == "yes" ]]; then
            printf 'yes|fixed|%s|%d 条已核验基线，可自动修复\n' "${verified}" "${n_fixed}"
        else
            printf 'no|fixed|%s|%d 条已核验基线，仅检测（未完成实机验证）\n' "${verified}" "${n_fixed}"
        fi
        return 0
    fi
    if ((n_testing > 0)); then
        printf 'no|testing|%s|官方仅提供 testing 仓库补丁\n' "${verified}"
        return 0
    fi
    if ((n_pending > 0)); then
        printf 'no|patch_not_released|%s|官方尚未发布可确认修复包\n' "${verified}"
        return 0
    fi
    printf 'no|unknown|%s|官方状态无法核验\n' "${verified}"
}

# ---------------------------------------------------------------------------
# v1.0.0 兼容入口（测试与旧调用方使用）
# ---------------------------------------------------------------------------

# fixed_version_for <codename> <branch>
fixed_version_for() {
    local codename="$1" branch="$2" release=""

    case "${codename}" in
        bookworm) release="12" ;;
        trixie) release="13" ;;
        *) return 1 ;;
    esac

    baseline_lookup "debian" "${release}" "${branch}" || return 1
    [[ ${BASE_STATUS} == "fixed" ]] || return 1
    [[ -n ${FIXED_VERSION} ]] || return 1
    printf '%s\n' "${FIXED_VERSION}"
}

advisory_for() {
    local codename="$1" branch="$2" release=""

    case "${codename}" in
        bookworm) release="12" ;;
        trixie) release="13" ;;
        *) printf '未知\n' && return 0 ;;
    esac

    if baseline_lookup "debian" "${release}" "${branch}"; then
        printf '%s\n' "${ADVISORY:-未知}"
    else
        printf '未知\n'
    fi
}

source_package_for() {
    case "$1/$2" in
        bookworm/6.12) printf 'linux-6.12\n' ;;
        *) printf 'linux\n' ;;
    esac
}
