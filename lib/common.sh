#!/usr/bin/env bash
#
# lib/common.sh - 通用基础设施：退出码、颜色、日志、路径与终端工具
#
# 本文件只定义函数与常量，不执行任何系统操作。

# 退出码（与 v1.0.0 保持兼容，新增 6 表示「官方尚未发布修复包」）
# 这些常量由 fix.sh 与 lib/*.sh 共用，单文件分析看不到使用点。
# shellcheck disable=SC2034
readonly EX_OK=0
readonly EX_ERROR=1
readonly EX_VULNERABLE=2
readonly EX_PENDING_REBOOT=3
readonly EX_UNKNOWN=4
readonly EX_CANCELLED=5
readonly EX_PATCH_NOT_RELEASED=6
readonly EX_PATCH_TESTING_ONLY=7
readonly EX_NOT_AFFECTED=8

# 统一状态机（全局唯一的状态取值），由 fix.sh 与 lib/status.sh 共用
# shellcheck disable=SC2034
readonly ST_FIXED="FIXED"
readonly ST_PENDING="PENDING_REBOOT"
readonly ST_VULN_FIXABLE="VULNERABLE_PATCH_AVAILABLE"
readonly ST_NOT_RELEASED="PATCH_NOT_RELEASED"
readonly ST_TESTING="PATCH_TESTING_ONLY"
readonly ST_NOT_AFFECTED="NOT_AFFECTED"
readonly ST_UNKNOWN="UNKNOWN"
readonly ST_UNSUPPORTED="UNSUPPORTED"

# 测试钩子：只读文件系统前缀，生产环境为空字符串
SYSROOT="${FIX_SYSROOT:-}"
SYSROOT="${SYSROOT%/}"

# 运行期全局开关，由 fix.sh 的 parse_args 写入
# shellcheck disable=SC2034
MODE="fix"
ASSUME_YES=0
USE_COLOR="auto"
SECTION_TOTAL=3

# 颜色
C_RESET=""
C_BOLD=""
C_DIM=""
C_RED=""
C_GREEN=""
C_YELLOW=""
C_BLUE=""

setup_colors() {
    if [[ ${USE_COLOR} == "never" ]] || [[ -n ${NO_COLOR:-} ]] || [[ ! -t 1 ]] || [[ ${TERM:-} == "dumb" ]]; then
        C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE=""
        return 0
    fi
    C_RESET=$'\033[0m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_YELLOW=$'\033[0;33m'
    C_BLUE=$'\033[0;36m'
}

log_info() { printf '%s[信息]%s %s\n' "${C_BLUE}" "${C_RESET}" "$*"; }
log_ok()   { printf '%s[通过]%s %s\n' "${C_GREEN}" "${C_RESET}" "$*"; }
log_warn() { printf '%s[警告]%s %s\n' "${C_YELLOW}" "${C_RESET}" "$*" >&2; }
log_err()  { printf '%s[失败]%s %s\n' "${C_RED}" "${C_RESET}" "$*" >&2; }

# 计算字符串显示宽度（CJK 字符按 2 列计），用于中英文混排的列对齐
display_width() {
    local text="$1" chars=0 bytes=0
    chars=${#text}
    bytes=$(LC_ALL=C printf '%s' "${text}" | wc -c | tr -d ' ')
    printf '%s' "$((bytes - (bytes - chars) / 2))"
}

step_title() {
    printf '\n%s==> [%s/%s] %s%s\n' "${C_BOLD}${C_BLUE}" "$1" "${SECTION_TOTAL}" "$2" "${C_RESET}"
}

kv() {
    local label="$1" value="$2" width=14 pad="" len=0
    len=$(display_width "${label}")
    while ((len < width)); do
        pad+=" "
        len=$((len + 1))
    done
    printf '  %s%s%s %s\n' "${C_DIM}" "${label}${pad}" "${C_RESET}" "${value}"
}

die() {
    log_err "$*"
    exit "${EX_ERROR}"
}

on_err() {
    local code="$1" line="$2" cmd="$3"
    log_err "脚本在第 ${line} 行意外失败（退出码 ${code}）：${cmd}"
    log_err "请将上述信息反馈至 ${PROJECT_URL}/issues"
}

# 给绝对路径加上测试前缀（生产环境为空操作）
sysfile() {
    printf '%s%s' "${SYSROOT}" "$1"
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# 读取 sysroot 下的单行文件（不存在时输出空）
read_sysfile() {
    local path=""
    path="$(sysfile "$1")"
    [[ -r ${path} ]] || return 1
    head -n 1 "${path}"
}

# 判断是否运行在容器内：容器无法可靠映射宿主机内核，必须 fail closed
detect_container() {
    local marker="" cgroup=""

    CONTAINER_KIND=""

    if [[ ${FIX_ASSUME_NOT_CONTAINER:-0} -eq 1 ]]; then
        return 1
    fi

    for marker in /.dockerenv /run/.containerenv /run/systemd/container; do
        if [[ -e "$(sysfile "${marker}")" ]]; then
            CONTAINER_KIND="container:${marker}"
            return 0
        fi
    done

    cgroup="$(sysfile /proc/1/cgroup)"
    if [[ -r ${cgroup} ]] && grep -Eqs '(docker|kubepods|libpod|lxc|containerd)' "${cgroup}"; then
        CONTAINER_KIND="container:cgroup"
        return 0
    fi

    case "${container:-}" in
        docker | podman | lxc | kubepods | containerd)
            CONTAINER_KIND="container:env"
            return 0
            ;;
    esac

    # shellcheck disable=SC2034  # 供 print_environment / write_report 读取
    CONTAINER_KIND=""
    return 1
}
