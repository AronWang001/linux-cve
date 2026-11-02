#!/usr/bin/env bash
#
# tests/lib/harness.sh - 多发行版测试的公共骨架
#
# 与 tests/test.sh 相同的思路：构造假根目录，用 PATH 注入包管理器模拟实现，
# 不接触真实系统。每个测试文件独立运行，互不影响。

HARNESS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "${HARNESS_LIB}/.." && pwd)"
REPO_DIR="$(cd "${TESTS_DIR}/.." && pwd)"
FIX_SH="${REPO_DIR}/fix.sh"
MOCK_PY="${TESTS_DIR}/lib/mocks.py"
MOCK_PM="${TESTS_DIR}/lib/mocks_pm.py"

VERBOSE=${VERBOSE:-0}
[[ ${1:-} == "-v" ]] && VERBOSE=1

C_RESET="" C_RED="" C_GREEN="" C_BOLD="" C_DIM=""
if [[ -t 1 ]] && [[ -z ${NO_COLOR:-} ]]; then
    C_RESET=$'\033[0m'
    C_RED=$'\033[0;31m'
    C_GREEN=$'\033[0;32m'
    C_BOLD=$'\033[1m'
    C_DIM=$'\033[2m'
fi

TOTAL=0
PASSED=0
FAILED=0
CASE_FAILS=0
CASE_NAME=""
declare -a FAILED_CASES=()

# ---------------------------------------------------------------------------
# 断言
# ---------------------------------------------------------------------------

fail() {
    CASE_FAILS=$((CASE_FAILS + 1))
    printf '    %s✗%s %s\n' "${C_RED}" "${C_RESET}" "$*"
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

assert_lacks() {
    if grep -Fq -- "$1" <<<"${OUT}"; then
        fail "输出不应包含「$1」"
    fi
}

assert_file() {
    [[ -e $1 ]] || fail "应存在文件：$1"
}

assert_no_file() {
    [[ -e $1 ]] && fail "不应存在文件：$1"
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
        FAILED_CASES+=("${CASE_NAME}")
        printf '    %s✗ 失败（%d 项断言）%s\n' "${C_RED}" "${CASE_FAILS}" "${C_RESET}"
    fi
    if [[ ${VERBOSE} -eq 1 ]]; then
        printf '%s\n---- 输出开始 ----\n%s\n---- 输出结束 ----%s\n' "${C_DIM}" "${OUT}" "${C_RESET}"
    fi
}

finish_suite() {
    printf '\n%s────────────────────────────────────────%s\n' "${C_BOLD}" "${C_RESET}"
    printf '用例：%d  通过：%s%d%s  失败：%s%d%s\n' \
        "${TOTAL}" "${C_GREEN}" "${PASSED}" "${C_RESET}" "${C_RED}" "${FAILED}" "${C_RESET}"
    if [[ ${FAILED} -gt 0 ]]; then
        printf '失败用例：\n'
        for name in "${FAILED_CASES[@]}"; do
            printf '  - %s\n' "${name}"
        done
        exit 1
    fi
    printf '%s全部通过%s\n' "${C_GREEN}" "${C_RESET}"
    exit 0
}

# ---------------------------------------------------------------------------
# 环境搭建
# ---------------------------------------------------------------------------

h_init() {
    local suite="$1"
    TMPROOT="$(mktemp -d)"
    TMPROOT="$(cygpath -m "${TMPROOT}" 2>/dev/null || printf '%s' "${TMPROOT}")"
    MOCKBIN="${TMPROOT}/mockbin"
    DRIVER="${TMPROOT}/driver.sh"
    mkdir -p "${MOCKBIN}"

    PYTHON_BIN=""
    local candidate=""
    for candidate in python3 python; do
        if command -v "${candidate}" >/dev/null 2>&1; then
            PYTHON_BIN="$(command -v "${candidate}")"
            break
        fi
    done
    if [[ -z ${PYTHON_BIN} ]]; then
        printf '测试需要 python3（用于模拟包管理器），未找到，退出。\n' >&2
        exit 1
    fi

    local prog=""
    for prog in dpkg dpkg-query apt-get apt-cache update-grub; do
        cat >"${MOCKBIN}/${prog}" <<EOF
#!/usr/bin/env bash
exec "${PYTHON_BIN}" "${MOCK_PY}" "${prog}" "\$@"
EOF
        chmod +x "${MOCKBIN}/${prog}"
    done

    for prog in rpm dnf yum apk pacman; do
        cat >"${MOCKBIN}/${prog}" <<EOF
#!/usr/bin/env bash
exec "${PYTHON_BIN}" "${MOCK_PM}" "${prog}" "\$@"
EOF
        chmod +x "${MOCKBIN}/${prog}"
    done

    cat >"${MOCKBIN}/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    -r) cat "${MOCK_ROOT}/uname_r" ;;
    -m) cat "${MOCK_ROOT}/uname_m" ;;
    *) printf 'Linux\n' ;;
esac
EOF
    chmod +x "${MOCKBIN}/uname"

    cat >"${MOCKBIN}/reboot" <<'EOF'
#!/usr/bin/env bash
touch "${MOCK_ROOT}/calls/reboot"
exit 0
EOF
    chmod +x "${MOCKBIN}/reboot"

    cat >"${DRIVER}" <<EOF
#!/usr/bin/env bash
source "${FIX_SH}"
require_root() { return 0; }
main "\$@"
EOF

    MOCKBIN_POSIX="$(cygpath -u "${MOCKBIN}" 2>/dev/null || printf '%s' "${MOCKBIN}")"

    # 预热模拟器：Windows/Git Bash 下首次执行新生成的脚本可能因安全软件扫描而异常缓慢，
    # 先各执行一次，避免首个用例被首次启动开销拖垮（不影响任何断言）。
    local warm=""
    for warm in dpkg dpkg-query apt-get apt-cache update-grub rpm dnf yum apk pacman uname; do
        "${MOCKBIN_POSIX}/${warm}" --version >/dev/null 2>&1 || true
    done

    # shellcheck disable=SC2329  # 由 trap EXIT 调用
    h_cleanup() {
        rm -rf "${TMPROOT}" 2>/dev/null || true
    }
    trap h_cleanup EXIT

    printf '%s\n' "${C_BOLD}${suite}${C_RESET}"
    printf '脚本: %s\n' "${FIX_SH}"
}

# 新建场景：root/ 为假根目录，state/ 为包管理器状态
h_scenario() {
    local name="$1"
    SCEN="${TMPROOT}/scen/${name}"
    rm -rf "${SCEN}"
    mkdir -p \
        "${SCEN}/root/etc/apt/sources.list.d" \
        "${SCEN}/root/etc/apt" \
        "${SCEN}/root/etc/yum.repos.d" \
        "${SCEN}/root/etc/apk" \
        "${SCEN}/root/etc/zypp/repos.d" \
        "${SCEN}/root/boot/grub2" \
        "${SCEN}/root/boot/loader/entries" \
        "${SCEN}/root/var/lib/apt/lists" \
        "${SCEN}/state/flags" \
        "${SCEN}/state/calls"

    : >"${SCEN}/state/installed.tsv"
    : >"${SCEN}/state/available.tsv"
    printf 'x86_64\n' >"${SCEN}/state/uname_m"
    printf 'x86_64\n' >"${SCEN}/state/rpm_arch"
    printf '6.1.0-49-amd64\n' >"${SCEN}/state/uname_r"
    printf '# grub\n' >"${SCEN}/root/boot/grub2/grub.cfg"
}

# 写入 os-release（从标准输入读取）
h_os_release() {
    cat >"${SCEN}/root/etc/os-release"
}

h_apt_sources() {
    local release="$1"
    printf 'deb https://deb.debian.org/debian %s main\n' "${release}" >"${SCEN}/root/etc/apt/sources.list"
    printf 'deb https://security.debian.org/debian-security %s-security main\n' "${release}" >>"${SCEN}/root/etc/apt/sources.list"
    printf 'mock apt lists\n' >"${SCEN}/root/var/lib/apt/lists/security.debian.org_debian-security_dists_${release}-security_main_binary-amd64_Packages"
}

h_yum_repo() {
    printf '[amazonlinux]\nname=Amazon Linux\nbaseurl=https://cdn.amazonlinux.com/al2023/core/latest/x86_64/mirror.list\nenabled=1\n' \
        >"${SCEN}/root/etc/yum.repos.d/amazonlinux.repo"
}

h_install_deb() {
    local pkg="$1" version="$2" release="$3"
    printf '%s\t%s\tinstalled\n' "${pkg}" "${version}" >>"${SCEN}/state/installed.tsv"
    printf '\177ELF mock kernel\n' >"${SCEN}/root/boot/vmlinuz-${release}"
    printf 'mock initramfs\n' >"${SCEN}/root/boot/initrd.img-${release}"
    printf "\tmenuentry 'Linux %s' {}\n" "${release}" >>"${SCEN}/root/boot/grub2/grub.cfg"
}

h_install_rpm() {
    local name="$1" evr="$2"
    local version="${evr%-*}" release="${evr##*-}"
    printf '%s\t%s\t%s\n' "${name}" "${version}" "${release}" >>"${SCEN}/state/installed.tsv"
    printf '\177ELF mock kernel\n' >"${SCEN}/root/boot/vmlinuz-${evr}.x86_64"
    printf 'mock initramfs\n' >"${SCEN}/root/boot/initramfs-${evr}.x86_64.img"
    printf "\tmenuentry 'Linux %s' {}\n" "${evr}" >>"${SCEN}/root/boot/grub2/grub.cfg"
}

h_install_pkg() {
    local name="$1" version="$2"
    printf '%s\t%s\n' "${name}" "${version}" >>"${SCEN}/state/installed.tsv"
}

h_avail_rpm() {
    printf '%s\t%s\n' "$1" "$2" >>"${SCEN}/state/available.tsv"
}

h_set_kernel() {
    printf '%s\n' "$1" >"${SCEN}/state/uname_r"
}

h_set_arch() {
    printf '%s\n' "$1" >"${SCEN}/state/uname_m"
    printf '%s\n' "$2" >"${SCEN}/state/rpm_arch"
}

h_flag() {
    : >"${SCEN}/state/flags/$1"
}

# 临时隐藏某个模拟命令（例如验证「没有 rpm 数据库」的 CloudLinux 场景）
h_hide_cmd() {
    local name="$1"
    [[ -f "${MOCKBIN}/${name}" ]] || return 1
    mv "${MOCKBIN}/${name}" "${MOCKBIN}/.${name}.hidden"
}

h_show_cmd() {
    local name="$1"
    [[ -f "${MOCKBIN}/.${name}.hidden" ]] || return 1
    mv "${MOCKBIN}/.${name}.hidden" "${MOCKBIN}/${name}"
}

h_run() {
    OUT="$(
        cd "${SCEN}" &&
            FIX_SYSROOT="${SCEN}/root" \
                MOCK_ROOT="${SCEN}/state" \
                PATH="${MOCKBIN_POSIX}:${PATH}" \
                FIX_NO_TTY=1 \
                bash "${DRIVER}" "$@" 2>&1
    )"
    RC=$?
}

h_run_stdin() {
    local input="$1"
    shift
    OUT="$(
        printf '%s' "${input}" | (
            cd "${SCEN}" &&
                FIX_SYSROOT="${SCEN}/root" \
                    MOCK_ROOT="${SCEN}/state" \
                    PATH="${MOCKBIN_POSIX}:${PATH}" \
                    FIX_NO_TTY=1 \
                    bash "${DRIVER}" "$@" 2>&1
        )
    )"
    RC=$?
}

# 直接执行脚本（不加载 driver），用于验证真实权限闸门
h_run_direct() {
    OUT="$(
        cd "${SCEN}" &&
            FIX_SYSROOT="${SCEN}/root" \
                MOCK_ROOT="${SCEN}/state" \
                PATH="${MOCKBIN_POSIX}:${PATH}" \
                bash "${FIX_SH}" "$@" 2>&1
    )"
    RC=$?
}
