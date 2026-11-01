#!/usr/bin/env bash
#
# tests/test_installer.sh - install.sh 的整包校验闸门
#
# 只测试本地校验逻辑（不联网、不下载）：
#   * 清单缺失、哈希不符、清单未覆盖全部脚本、路径穿越都必须中止；
#   * 校验通过时才允许继续执行。
#
# 用法：bash tests/test_installer.sh

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${TESTS_DIR}/.." && pwd)"
INSTALL_SH="${REPO_DIR}/install.sh"

TOTAL=0
PASSED=0
FAILED=0
CASE_FAILS=0
CASE_NAME=""

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
    CASE_NAME="$1"
    CASE_FAILS=0
    printf '%s\n' "${C_BOLD}[${TOTAL}] ${CASE_NAME}${C_RESET}"
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

assert_rc() {
    if [[ ${RC} -ne $1 ]]; then
        fail "退出码期望 $1，实际 ${RC}"
    fi
}

assert_has() {
    if ! grep -Fq -- "$1" <<<"${OUT}"; then
        fail "输出应包含「$1」"
    fi
}

TMP="$(mktemp -d)"
TMP="$(cygpath -m "${TMP}" 2>/dev/null || printf '%s' "${TMP}")"
trap 'rm -rf "${TMP}"' EXIT

# 构造一个最小发布包布局
SRC="${TMP}/src"
mkdir -p "${SRC}/lib" "${SRC}/adapters" "${SRC}/data"
printf '#!/usr/bin/env bash\necho fix\n' >"${SRC}/fix.sh"
printf '#!/usr/bin/env bash\necho install\n' >"${SRC}/install.sh"
printf '#!/usr/bin/env bash\n' >"${SRC}/lib/common.sh"
printf '#!/usr/bin/env bash\n' >"${SRC}/lib/status.sh"
printf '#!/usr/bin/env bash\n' >"${SRC}/adapters/debian.sh"
printf 'cve: test\n' >"${SRC}/data/cve-2026-98432.yml"

good_sums() {
    (
        cd "${SRC}" &&
            find . -type f \( -name '*.sh' -o -name '*.yml' \) | sed 's|^\./||' | LC_ALL=C sort |
            while IFS= read -r f; do
                sha256sum "${f}"
            done
    ) >"${TMP}/SHA256SUMS"
}

run_verify() {
    local sums="$1"
    OUT="$(
        (
            # 在子 shell 中加载，避免 install.sh 的 set -Eeuo pipefail 影响本测试脚本
            # shellcheck source=/dev/null
            source "${INSTALL_SH}"
            SRC_DIR="${SRC}"
            awk 'NF >= 2 {sub(/^\*/, "", $2); print $2}' "${sums}" | LC_ALL=C sort >"${TMP}/files.txt"
            check_manifest_coverage "${TMP}/files.txt"
            verify_manifest "${sums}"
        ) 2>&1
    )"
    RC=$?
}

run_coverage() {
    local files="$1"
    OUT="$(
        (
            # shellcheck source=/dev/null
            source "${INSTALL_SH}"
            # install.sh 被 source 时把 SRC_DIR 初始化为空，这里指向假源码目录，
            # 供 check_manifest_coverage 读取；ShellCheck 看不到跨文件读取。
            # shellcheck disable=SC2034
            SRC_DIR="${SRC}"
            check_manifest_coverage "${files}"
        ) 2>&1
    )"
    RC=$?
}

run_paths() {
    local members="$1"
    OUT="$(
        (
            # shellcheck source=/dev/null
            source "${INSTALL_SH}"
            check_archive_paths "${members}"
        ) 2>&1
    )"
    RC=$?
}

begin_case "完整清单：全部哈希通过"
good_sums
run_verify "${TMP}/SHA256SUMS"
assert_rc 0
assert_has "6 个文件 SHA256 校验通过"
end_case

begin_case "哈希不符：中止且不执行工具代码"
good_sums
printf 'tampered\n' >"${SRC}/lib/status.sh"
run_verify "${TMP}/SHA256SUMS"
assert_rc 1
assert_has "校验失败"
end_case

begin_case "清单缺少脚本：中止"
printf '#!/usr/bin/env bash\n' >"${SRC}/lib/status.sh"
good_sums
grep -v 'lib/status.sh' "${TMP}/SHA256SUMS" >"${TMP}/SHA256SUMS.part"
run_verify "${TMP}/SHA256SUMS.part"
assert_rc 1
assert_has "缺少必要条目"
end_case

begin_case "清单未覆盖 adapters：中止"
good_sums
awk '{print $2}' "${TMP}/SHA256SUMS" | sed 's/^\*//' | grep -v 'adapters/' >"${TMP}/files.txt"
run_coverage "${TMP}/files.txt"
assert_rc 1
assert_has "缺少必要条目"
end_case

begin_case "清单含路径穿越：中止"
good_sums
printf '%s  ../../etc/passwd\n' "$(sha256sum "${SRC}/fix.sh" | awk '{print $1}')" >>"${TMP}/SHA256SUMS"
run_verify "${TMP}/SHA256SUMS"
assert_rc 1
assert_has "不安全路径"
end_case

begin_case "归档成员含 ..：解包前中止"
printf 'repo-1.2.0/fix.sh\nrepo-1.2.0/../../evil.sh\n' >"${TMP}/members.txt"
run_paths "${TMP}/members.txt"
assert_rc 1
assert_has "不安全路径"
end_case

begin_case "归档成员正常：通过路径检查"
printf 'repo-1.2.0/fix.sh\nrepo-1.2.0/lib/common.sh\n' >"${TMP}/members.txt"
run_paths "${TMP}/members.txt"
assert_rc 0
end_case

printf '\n%s────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
printf '用例：%d  通过：%s%d%s  失败：%s%d%s\n' \
    "${TOTAL}" "${C_GREEN}" "${PASSED}" "${C_RESET}" "${C_RED}" "${FAILED}" "${C_RESET}"
if ((FAILED > 0)); then
    exit 1
fi
printf '%s全部通过%s\n' "${C_GREEN}" "${C_RESET}"
