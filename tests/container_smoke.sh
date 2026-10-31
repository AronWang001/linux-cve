#!/usr/bin/env bash
#
# tests/container_smoke.sh - 在真实发行版容器中执行只读识别冒烟测试
#
# 用法：bash tests/container_smoke.sh <镜像> <期望出现的发行版名称>
#
# 说明：容器测试只覆盖「发行版识别 + 容器 fail closed」，
#       不能代替真实内核启动验证，README 已明确列出该限制。

set -uo pipefail

IMAGE="${1:-}"
EXPECT="${2:-}"

if [[ -z ${IMAGE} ]]; then
    printf '用法：%s <镜像> <期望发行版名称>\n' "${0##*/}" >&2
    exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
    printf '未找到 docker，跳过容器测试\n' >&2
    exit 0
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

printf '== 容器冒烟测试：%s ==\n' "${IMAGE}"

docker run --rm \
    -v "${REPO_DIR}:/src:ro" \
    -e EXPECT="${EXPECT}" \
    "${IMAGE}" \
    sh -c '
        if ! command -v bash >/dev/null 2>&1; then
            if command -v apk >/dev/null 2>&1; then
                apk add --no-cache bash
            fi
        fi
        exec bash /src/tests/lib/container_check.sh "$EXPECT"
    '
