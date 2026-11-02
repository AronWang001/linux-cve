#!/usr/bin/env bash
#
# tests/test_baseline.sh - 基线文件的静态一致性检查
#
# 不需要包管理器模拟，直接读取 data/cve-2026-98432.yml：
#   * ID 唯一、组合键唯一；
#   * fixed/testing 必须有完整 EVR、公告与链接；
#   * autofix=yes 必须有正式修复包，且（新模型记录）完成安装与重启验证；
#   * 不允许用通配记录声明「已修复」。
#
# 用法：bash tests/test_baseline.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${TESTS_DIR}/.." && pwd)"

# 这三个变量由 lib/advisory.sh 读取（LIB_ROOT/CVE_ID 用于定位基线文件，
# BASELINE_FILE 由 load_baseline_db 回填），ShellCheck 无法跨文件看到读取点。
# shellcheck disable=SC2034
LIB_ROOT="${REPO_DIR}"
# shellcheck disable=SC2034
CVE_ID="CVE-2026-98432"
BASELINE_COUNT=0
BASELINE_FILE=""

# shellcheck source=/dev/null
source "${REPO_DIR}/lib/advisory.sh"
load_baseline_db || {
    printf '无法读取基线文件：%s\n' "${BASELINE_FILE}" >&2
    exit 1
}

TOTAL=0
PASSED=0
FAILED=0
CASE_FAILS=0

C_RESET="" C_RED="" C_GREEN="" C_BOLD=""
if [[ -t 1 ]] && [[ -z ${NO_COLOR:-} ]]; then
    C_RESET=$'\033[0m'
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_BOLD=$'\033[1m'
fi

fail() {
    CASE_FAILS=$((CASE_FAILS + 1))
    printf '    %s✗%s %s\n' "${C_RED}" "${C_RESET}" "$*"
}

begin_case() {
    TOTAL=$((TOTAL + 1))
    CASE_FAILS=0
    printf '%s\n' "${C_BOLD}[${TOTAL}] $1${C_RESET}"
}

end_case() {
    if [[ ${CASE_FAILS} -eq 0 ]]; then
        PASSED=$((PASSED + 1))
        printf '    %s✓ 通过%s\n' "${C_GREEN}" "${C_RESET}"
    else
        FAILED=$((FAILED + 1))
        printf '    %s✗ 失败（%d 项断言）%s\n' "${C_RED}" "${CASE_FAILS}" "${C_RESET}"
    fi
}

begin_case "ID 唯一且命名规范"
declare -A seen_id=()
for ((i = 0; i < BASELINE_COUNT; i++)); do
    id="${B_ID[i]}"
    if [[ -z ${id} ]]; then
        fail "第 $((i + 1)) 条记录缺少 id"
        continue
    fi
    if [[ ! ${id} =~ ^[a-z0-9][a-z0-9.-]*$ ]]; then
        fail "id 命名不规范：${id}"
    fi
    if [[ -n ${seen_id[${id}]:-} ]]; then
        fail "id 重复：${id}"
    fi
    seen_id[${id}]=1
done
end_case

begin_case "组合键唯一（distro|product|release|branch|package）"
declare -A seen_key=()
for ((i = 0; i < BASELINE_COUNT; i++)); do
    key="${B_DISTRO[i]}|${B_PRODUCT[i]}|${B_RELEASE[i]}|${B_BRANCH[i]}|${B_PACKAGE[i]}"
    if [[ -n ${seen_key[${key}]:-} ]]; then
        fail "组合重复：${key}（${B_ID[i]}）"
    fi
    seen_key[${key}]=1
done
end_case

begin_case "status 取值合法"
for ((i = 0; i < BASELINE_COUNT; i++)); do
    case "${B_STATUS[i]}" in
        fixed | testing | patch_not_released | in_progress | not_affected | unknown) ;;
        *) fail "${B_ID[i]} 的 status 非法：${B_STATUS[i]}" ;;
    esac
done
end_case

begin_case "not_affected 记录不得带修复版本或自动修复"
for ((i = 0; i < BASELINE_COUNT; i++)); do
    [[ ${B_STATUS[i]} == "not_affected" ]] || continue
    [[ -z ${B_FIXED[i]} ]] || fail "${B_ID[i]} 声明 not_affected 却给出了 fixed_version：${B_FIXED[i]}"
    [[ ${B_AUTOFIX[i]} != "yes" ]] || fail "${B_ID[i]} 声明 not_affected 却允许自动修复"
    [[ -n ${B_NOTES[i]} ]] || fail "${B_ID[i]} 声明 not_affected 但缺少官方依据说明"
done
end_case

begin_case "fixed/testing 记录必须有完整 EVR 与公告"
for ((i = 0; i < BASELINE_COUNT; i++)); do
    case "${B_STATUS[i]}" in
        fixed | testing)
            if [[ -z ${B_FIXED[i]} ]]; then
                fail "${B_ID[i]} 缺少 fixed_version"
            elif [[ ${B_FIXED[i]} != *-* ]]; then
                fail "${B_ID[i]} 的 fixed_version 不是 EVR：${B_FIXED[i]}"
            fi
            [[ -n ${B_ADVISORY[i]} ]] || fail "${B_ID[i]} 缺少 advisory"
            if [[ ${B_ADVISORY_URL[i]} != https://* ]]; then
                fail "${B_ID[i]} 的 advisory_url 不是 https 链接"
            fi
            ;;
    esac
done
end_case

begin_case "通配记录不得声明已修复"
for ((i = 0; i < BASELINE_COUNT; i++)); do
    if [[ ${B_RELEASE[i]} == "*" ]] && [[ ${B_STATUS[i]} == "fixed" ]]; then
        fail "${B_ID[i]} 用 release=* 声明 fixed，无法精确匹配"
    fi
done
end_case

begin_case "autofix=yes 必须有正式补丁与验证证据"
for ((i = 0; i < BASELINE_COUNT; i++)); do
    [[ ${B_AUTOFIX[i]} == "yes" ]] || continue
    [[ ${B_STATUS[i]} == "fixed" ]] || fail "${B_ID[i]} 的 autofix=yes 但 status 不是 fixed"
    [[ -n ${B_FIXED[i]} ]] || fail "${B_ID[i]} 的 autofix=yes 但缺少 fixed_version"
    [[ -n ${B_ADVISORY[i]} ]] || fail "${B_ID[i]} 的 autofix=yes 但缺少公告"
    # 新模型记录（带 kernel_stream）必须完成真实安装与重启验证
    if [[ -n ${B_STREAM[i]} ]]; then
        [[ ${B_TEST_INSTALL[i]} == "yes" ]] || fail "${B_ID[i]} 的 autofix=yes 但未记录实机安装验证"
        [[ ${B_TEST_REBOOT[i]} == "yes" ]] || fail "${B_ID[i]} 的 autofix=yes 但未记录重启验证"
    else
        # 旧模型记录沿用 v1.0/v1.1 已完成的实机验证结论，只允许 Debian 与
        # Amazon Linux 使用；其他发行版必须补齐 kernel_stream 与验证字段，
        # 否则就是绕过实机验证要求。
        case "${B_DISTRO[i]}" in
            debian | amazon) ;;
            *) fail "${B_ID[i]} 的 autofix=yes 既未记录 kernel_stream，也不属于已验证的 Debian / Amazon 记录" ;;
        esac
    fi
done
end_case

begin_case "architectures 与 verified 必填"
for ((i = 0; i < BASELINE_COUNT; i++)); do
    [[ -n ${B_ARCHES[i]} ]] || fail "${B_ID[i]} 缺少 architectures"
    if [[ ! ${B_VERIFIED[i]} =~ ^20[0-9]{2}-[0-9]{2}-[0-9]{2}$ ]]; then
        fail "${B_ID[i]} 的 verified 不是 YYYY-MM-DD：${B_VERIFIED[i]}"
    fi
    [[ -n ${B_NOTES[i]} ]] || fail "${B_ID[i]} 缺少 notes"
done
end_case

printf '\n%s────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
printf '记录数：%d  用例：%d  通过：%s%d%s  失败：%s%d%s\n' \
    "${BASELINE_COUNT}" "${TOTAL}" "${C_GREEN}" "${PASSED}" "${C_RESET}" "${C_RED}" "${FAILED}" "${C_RESET}"
if ((FAILED > 0)); then
    exit 1
fi
printf '%s全部通过%s\n' "${C_GREEN}" "${C_RESET}"
