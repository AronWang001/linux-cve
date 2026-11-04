#!/usr/bin/env bash
#
# install.sh - CVE-2026-98432 修复工具的引导安装器
#
# 作用：把指定 Tag 的完整工具包下载到临时目录，用 Release 中的 SHA256SUMS
#       校验全部将执行的脚本与数据文件后，才以同样的参数调用 fix.sh。
#       本文件不含任何系统修改逻辑。
#
# 校验范围：fix.sh、install.sh、lib/*.sh、adapters/*.sh、data/*.yml。
# 校验失败、清单缺失、缺少 sha256sum/shasum、解包路径异常时一律停止，
# 不执行任何工具代码。
#
# 用法（以下命令可直接整条粘贴执行）：
#   一键修复（交互式，确认后直接执行修复）：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.3.2/install.sh | sudo bash
#
#   只读检查：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.3.2/install.sh | sudo bash -s -- --check
#
#   免交互执行（跳过确认，但不跳过白名单、公告核验与版本校验）：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.3.2/install.sh | sudo bash -s -- --yes
#
#   先下载再审查：
#     curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.3.2/install.sh -o install.sh
#     less install.sh && sudo bash install.sh
#
# License: MIT

set -Eeuo pipefail

REPO="AronWang001/linux-cve-2026-98432-fix"
VERSION="1.3.2"
TAG="v${VERSION}"
SRC_NAME="${REPO##*/}"
TARBALL="https://github.com/${REPO}/archive/refs/tags/${TAG}.tar.gz"
SUMS="https://github.com/${REPO}/releases/download/${TAG}/SHA256SUMS"
TMPDIR_RUN=""
SRC_DIR=""

# 一键模式下 fix.sh 只存在于临时目录，退出即被清理，机器上不会留下 fix.sh。
# 这里把「重新调用本工具」的完整命令交给 fix.sh，让所有「请再次执行」的提示
# 都是可以真正粘贴执行的命令，而不是指向一个已被删除的文件。
if [[ -z ${BASH_SOURCE[0]:-} ]]; then
    BOOTSTRAP_CMD="curl -fsSL https://raw.githubusercontent.com/${REPO}/${TAG}/install.sh | sudo bash -s --"
else
    SELF_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/$(basename -- "${BASH_SOURCE[0]}")"
    BOOTSTRAP_CMD="sudo bash ${SELF_PATH}"
fi

cleanup() {
    if [[ -n ${TMPDIR_RUN} ]]; then
        rm -rf "${TMPDIR_RUN}"
    fi
}
trap cleanup EXIT

die() {
    printf '[失败] %s\n' "$*" >&2
    exit 1
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        return 1
    fi
}

# 解包前检查成员名：拒绝绝对路径、..、以及指向归档外的符号链接写法
check_archive_paths() {
    local members="$1" line=""
    while IFS= read -r line; do
        [[ -n ${line} ]] || continue
        case "${line}" in
            /* | .. | ../* | */../* | */..)
                die "工具包包含不安全路径（${line}），已中止，未执行任何工具代码。"
                ;;
        esac
    done <"${members}"
}

# 清单必须覆盖所有会被加载或执行的文件
check_manifest_coverage() {
    local manifest_files="$1" missing=0 rel="" count=0

    for rel in fix.sh install.sh data/cve-2026-98432.yml; do
        if ! grep -qxF -- "${rel}" "${manifest_files}"; then
            printf '[失败] SHA256SUMS 缺少必要条目：%s\n' "${rel}" >&2
            missing=1
        fi
    done
    while IFS= read -r rel; do
        [[ -n ${rel} ]] || continue
        if ! grep -qxF -- "${rel}" "${manifest_files}"; then
            printf '[失败] SHA256SUMS 缺少必要条目：%s\n' "${rel}" >&2
            missing=1
        fi
        count=$((count + 1))
    done < <(cd "${SRC_DIR}" && find lib adapters -maxdepth 1 -type f -name '*.sh' | LC_ALL=C sort)

    if ((missing != 0)); then
        die "校验清单不完整，已中止，未执行任何工具代码。"
    fi
    printf '[信息] 校验清单覆盖 %d 个脚本与数据文件\n' "${count}"
}

# 逐条校验清单：文件必须存在、路径必须在解包目录内、哈希必须一致
verify_manifest() {
    local sums="$1" expected="" rel="" actual="" n=0

    while read -r expected rel; do
        [[ -n ${expected} && -n ${rel} ]] || continue
        # Windows/Git Bash 的 sha256sum 在二进制模式下会在路径前加 *，统一去掉
        rel="${rel#\*}"
        case "${rel}" in
            /* | .. | ../* | */../* | */..)
                die "校验清单包含不安全路径（${rel}），已中止。"
                ;;
        esac
        if [[ ! -f "${SRC_DIR}/${rel}" ]]; then
            die "工具包缺少清单中的文件：${rel}，已中止。"
        fi
        actual="$(sha256_of "${SRC_DIR}/${rel}" || true)"
        if [[ -z ${actual} ]]; then
            die "无法计算 ${rel} 的 SHA256，已中止。"
        fi
        if [[ ${actual} != "${expected}" ]]; then
            die "校验失败：${rel}（期望 ${expected}，实际 ${actual}），已中止。"
        fi
        n=$((n + 1))
    done <"${sums}"

    if ((n < 3)); then
        die "校验清单条目过少（${n} 条），已中止。"
    fi
    printf '[通过] %d 个文件 SHA256 校验通过\n' "${n}"
}

main() {
    local members="" manifest_files=""

    command -v curl >/dev/null 2>&1 || die "未找到 curl，无法下载工具包。"
    command -v tar >/dev/null 2>&1 || die "未找到 tar，无法解包。"
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
        die "未找到 sha256sum 或 shasum，无法校验工具包，已中止。"
    fi

    TMPDIR_RUN="$(mktemp -d)"

    printf '[信息] 下载 %s ...\n' "${TAG}"
    curl -fsSL --retry 3 --connect-timeout 15 -o "${TMPDIR_RUN}/src.tar.gz" "${TARBALL}" ||
        die "下载工具包失败，未执行任何操作。"

    members="${TMPDIR_RUN}/members.txt"
    tar -tzf "${TMPDIR_RUN}/src.tar.gz" >"${members}" ||
        die "无法读取工具包内容，未执行任何操作。"
    check_archive_paths "${members}"

    tar -xzf "${TMPDIR_RUN}/src.tar.gz" -C "${TMPDIR_RUN}" \
        --no-same-owner --no-same-permissions ||
        die "解压工具包失败，未执行任何操作。"

    SRC_DIR="${TMPDIR_RUN}/${SRC_NAME}-${VERSION}"
    if [[ ! -r "${SRC_DIR}/fix.sh" ]]; then
        # GitHub 归档目录名可能因 Tag 前缀不同而变化，这里回退到目录探测
        SRC_DIR="$(find "${TMPDIR_RUN}" -maxdepth 1 -mindepth 1 -type d -name "${SRC_NAME}-*" 2>/dev/null | head -n 1)"
    fi
    if [[ -z ${SRC_DIR} ]] || [[ ! -r "${SRC_DIR}/fix.sh" ]]; then
        die "工具包结构异常（缺少 fix.sh），未执行任何操作。"
    fi

    printf '[信息] 获取校验清单 %s ...\n' "${TAG}"
    if ! curl -fsSL --retry 3 --connect-timeout 15 -o "${TMPDIR_RUN}/SHA256SUMS" "${SUMS}"; then
        die "无法获取 SHA256SUMS，按 fail closed 处理，未执行任何工具代码。"
    fi
    if [[ ! -s "${TMPDIR_RUN}/SHA256SUMS" ]]; then
        die "SHA256SUMS 为空，已中止。"
    fi

    manifest_files="${TMPDIR_RUN}/manifest_files.txt"
    awk 'NF >= 2 {sub(/^\*/, "", $2); print $2}' "${TMPDIR_RUN}/SHA256SUMS" |
        LC_ALL=C sort >"${manifest_files}"
    check_manifest_coverage "${manifest_files}"
    verify_manifest "${TMPDIR_RUN}/SHA256SUMS"

    printf '[信息] 启动 fix.sh %s\n' "$*"
    export FIX_BOOTSTRAP_CMD="${BOOTSTRAP_CMD}"
    exec bash "${SRC_DIR}/fix.sh" "$@"
}

# 直接执行、或通过管道执行（curl ... | bash，此时 BASH_SOURCE 未定义）时进入 main。
# 必须带 :- 兜底：脚本启用了 set -u，未定义变量直接取值会以 unbound variable 退出。
if [[ -z ${BASH_SOURCE[0]:-} ]] || [[ ${BASH_SOURCE[0]} == "${0}" ]]; then
    main "$@"
fi
