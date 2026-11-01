#!/usr/bin/env bash
#
# install.sh - CVE-2026-98432 修复工具的引导安装器
#
# 作用：把指定 Tag 的完整工具包下载到临时目录，校验 fix.sh 的 SHA256 后
#       以同样的参数调用 fix.sh。本文件不含任何系统修改逻辑。
#
# 用法（以下命令可直接整条粘贴执行）：
#   一键修复（交互式，确认后直接执行修复）：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash
#
#   只读检查：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash -s -- --check
#
#   免交互执行（跳过确认，但不跳过白名单、公告核验与版本校验）：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash -s -- --yes
#
#   先下载再审查：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh -o install.sh
#     less install.sh && sudo bash install.sh
#
# License: MIT

set -Eeuo pipefail

readonly REPO="AronWang001/linux-cve-2026-98432-fix"
readonly VERSION="1.1.2"
readonly TAG="v${VERSION}"
readonly SRC_NAME="${REPO##*/}"   # GitHub 归档解压后的目录名前缀
readonly TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"
readonly SUMS="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"

TMPDIR_RUN=""

cleanup() {
    [[ -n ${TMPDIR_RUN} ]] && rm -rf "${TMPDIR_RUN}"
}
trap cleanup EXIT

die() {
    printf '[失败] %s\n' "$*" >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || die "未找到 curl，无法下载工具包。"
command -v tar >/dev/null 2>&1 || die "未找到 tar，无法解包。"

TMPDIR_RUN="$(mktemp -d)"

printf '[信息] 下载 %s ...\n' "${TAG}"
curl -fsSL --retry 3 --connect-timeout 15 -o "${TMPDIR_RUN}/src.tar.gz" "${TARBALL}" ||
    die "下载工具包失败，未执行任何操作。"

tar -xzf "${TMPDIR_RUN}/src.tar.gz" -C "${TMPDIR_RUN}" ||
    die "解压工具包失败，未执行任何操作。"

SRC_DIR="${TMPDIR_RUN}/${SRC_NAME}-${VERSION}"
if [[ ! -r "${SRC_DIR}/fix.sh" ]]; then
    # GitHub 归档目录名可能因 Tag 前缀不同而变化，这里回退到目录探测
    SRC_DIR="$(find "${TMPDIR_RUN}" -maxdepth 1 -mindepth 1 -type d -name "${SRC_NAME}-*" 2>/dev/null | head -n 1)"
fi
[[ -n ${SRC_DIR} ]] && [[ -r "${SRC_DIR}/fix.sh" ]] || die "工具包结构异常（缺少 fix.sh），未执行任何操作。"

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        return 1
    fi
}

# 校验 fix.sh：优先使用 Release 中的 SHA256SUMS，取不到时给出提示
if curl -fsSL --connect-timeout 10 -o "${TMPDIR_RUN}/SHA256SUMS" "${SUMS}" 2>/dev/null; then
    expected="$(awk '$2 == "fix.sh" {print $1}' "${TMPDIR_RUN}/SHA256SUMS" | head -n 1)"
    if [[ -n ${expected} ]]; then
        actual="$(sha256_of "${SRC_DIR}/fix.sh" || true)"
        if [[ -z ${actual} ]]; then
            printf '[警告] 未找到 sha256sum/shasum，跳过校验；建议先下载并审查脚本。\n' >&2
        elif [[ ${actual} != "${expected}" ]]; then
            die "fix.sh 校验失败（期望 ${expected}，实际 ${actual}），已中止。"
        else
            printf '[通过] fix.sh SHA256 校验通过\n'
        fi
    fi
else
    printf '[警告] 未能获取 SHA256SUMS，跳过校验；建议先下载并审查脚本。\n' >&2
fi

printf '[信息] 启动 fix.sh %s\n' "$*"
exec bash "${SRC_DIR}/fix.sh" "$@"
