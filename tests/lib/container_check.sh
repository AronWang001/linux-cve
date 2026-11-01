#!/usr/bin/env bash
#
# tests/lib/container_check.sh - 在容器内部执行的冒烟检查
#
# 只验证「真实发行版环境下的识别」与「容器内 fail closed」，
# 不安装任何软件包，也不代表已完成真实内核启动验证。

set -uo pipefail

EXPECT="${1:-}"
FAILS=0

fail() {
    printf '✗ %s\n' "$*" >&2
    FAILS=$((FAILS + 1))
}

START_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
if [[ ! -r ${START_DIR}/fix.sh ]]; then
    START_DIR="/src"
fi

printf '== 发行版信息 ==\n'
grep -E '^(PRETTY_NAME|ID|VERSION_ID)=' /etc/os-release || true

OUT="$(bash "${START_DIR}/fix.sh" --check --no-color 2>&1)"
RC=$?

printf '%s\n' "${OUT}"

case "${RC}" in
    0 | 2 | 3 | 4 | 6 | 7) ;;
    *) fail "退出码异常：${RC}" ;;
esac

if [[ -n ${EXPECT} ]] && ! grep -Fq -- "${EXPECT}" <<<"${OUT}"; then
    fail "未识别出发行版：${EXPECT}"
fi

if ! grep -Fq "判定结果" <<<"${OUT}"; then
    fail "缺少判定结果"
fi

# 所有冒烟测试都在容器内运行：必须识别出容器并拒绝判定/安装
if ! grep -Fq "容器环境" <<<"${OUT}"; then
    fail "容器环境未被识别（可能误判宿主机内核）"
fi

if ! grep -Fq "自动修复" <<<"${OUT}"; then
    fail "缺少自动修复状态输出"
fi

LIST="$(bash "${START_DIR}/fix.sh" --list-distros --no-color 2>&1)"
if ! grep -Fq "支持矩阵" <<<"${LIST}"; then
    fail "--list-distros 输出异常"
fi

if [[ ${FAILS} -gt 0 ]]; then
    printf '容器冒烟检查失败：%d 项\n' "${FAILS}" >&2
    exit 1
fi

printf '✓ 容器冒烟检查通过（rc=%s）\n' "${RC}"
exit 0
