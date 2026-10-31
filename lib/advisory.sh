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

# shellcheck disable=SC2034  # 由 baseline_lookup / write_report 等读取
BASELINE_COUNT=0
BASELINE_FILE=""
BASELINE_LOADED=0

# 去掉值两侧的引号
_unquote() {
    local v="$1"
    v="${v%\"}"
    v="${v#\"}"
    v="${v%\'}"
    v="${v#\'}"
    printf '%s' "${v}"
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
            line="${line#- }"
        fi
        [[ ${cur} -lt 0 ]] && continue
        [[ ${line} == *:* ]] || continue

        key="${line%%:*}"
        key="${key//[[:space:]]/}"
        val="${line#*:}"
        val="${val# }"
        val="$(_unquote "${val}")"

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
    return 0
}

# 汇总某个发行版在基线表中的状态，供 --list-distros 使用
# 输出：autofix | status | verified | 说明
adapter_summary_status() {
    local distro="$1"
    local i=0 n_fixed=0 n_pending=0 n_unknown=0 verified="" status="" autofix="no" branches=0

    load_baseline_db || {
        printf 'no|unknown||基线文件缺失\n'
        return 0
    }

    for ((i = 0; i < BASELINE_COUNT; i++)); do
        [[ ${B_DISTRO[i]} == "${distro}" ]] || continue
        branches=$((branches + 1))
        [[ ${B_VERIFIED[i]} > ${verified} ]] && verified="${B_VERIFIED[i]}"
        case "${B_STATUS[i]}" in
            fixed) n_fixed=$((n_fixed + 1)) ;;
            patch_not_released) n_pending=$((n_pending + 1)) ;;
            *) n_unknown=$((n_unknown + 1)) ;;
        esac
        [[ ${B_AUTOFIX[i]} == "yes" ]] && autofix="yes"
    done

    if ((branches == 0)); then
        printf 'no|unknown||未收录\n'
        return 0
    fi
    if ((n_fixed > 0)); then
        printf '%s|fixed|%s|%d 条已核验修复基线\n' "${autofix}" "${verified}" "${n_fixed}"
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
