#!/usr/bin/env bash
#
# tests/test.sh - fix.sh 的自动化测试
#
# 测试方式：在临时目录中构造一个「假 Debian 文件系统」，并通过 PATH 注入
# dpkg / dpkg-query / apt-get / apt-cache / uname / update-grub 的模拟实现，
# 因此不需要真实 Debian 机器，也不会触碰本机系统。
#
# 覆盖：环境识别、漏洞判定、修复流程、失败分支、参数处理、版本比较、
#       静态安全检查。
#
# 用法：bash tests/test.sh [-v]

# run_snippet 需要把 $() 原样交给子 shell 求值，故保留单引号
# shellcheck disable=SC2016
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${TESTS_DIR}/.." && pwd)"
FIX_SH="${REPO_DIR}/fix.sh"
MOCK_PY="${TESTS_DIR}/lib/mocks.py"

VERBOSE=0
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
declare -a FAILED_CASES=()

# ---------------------------------------------------------------------------
# 断言
# ---------------------------------------------------------------------------

CASE_FAILS=0

fail() {
    CASE_FAILS=$((CASE_FAILS + 1))
    printf '    %s✗%s %s\n' "${C_RED}" "${C_RESET}" "$*"
}

assert_rc() {
    local expected="$1"
    if [[ ${RC} -ne ${expected} ]]; then
        fail "退出码期望 ${expected}，实际 ${RC}"
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
    if [[ ! -e $1 ]]; then
        fail "应存在文件：$1"
    fi
}

assert_no_file() {
    if [[ -e $1 ]]; then
        fail "不应存在文件：$1"
    fi
}

assert_line() {
    if ! grep -Fq -- "$1" "$2" 2>/dev/null; then
        fail "文件 $2 应包含「$1」"
    fi
}

assert_not_line() {
    if grep -Fq -- "$1" "$2" 2>/dev/null; then
        fail "文件 $2 不应包含「$1」"
    fi
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
        printf '%s\n' "${C_DIM}---- 输出开始 ----"
        printf '%s\n' "${OUT}"
        printf '%s\n' "---- 输出结束 ----${C_RESET}"
    fi
}

# ---------------------------------------------------------------------------
# 测试环境搭建
# ---------------------------------------------------------------------------

TMPROOT="$(mktemp -d)"
TMPROOT="$(cygpath -m "${TMPROOT}" 2>/dev/null || printf '%s' "${TMPROOT}")"
MOCKBIN="${TMPROOT}/mockbin"
DRIVER="${TMPROOT}/driver.sh"

# shellcheck disable=SC2329  # 由 trap EXIT 调用
cleanup() {
    rm -rf "${TMPROOT}" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "${MOCKBIN}"

make_mock() {
    local name="$1"
    cat >"${MOCKBIN}/${name}" <<EOF
#!/usr/bin/env bash
exec "${PYTHON_BIN}" "${MOCK_PY}" "${name}" "\$@"
EOF
    chmod +x "${MOCKBIN}/${name}"
}

PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "${candidate}" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "${candidate}")"
        break
    fi
done
if [[ -z ${PYTHON_BIN} ]]; then
    printf '测试需要 python3（用于模拟 dpkg/apt），未找到，退出。\n' >&2
    exit 1
fi

for prog in dpkg dpkg-query apt-get apt-cache update-grub; do
    make_mock "${prog}"
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

# 若脚本误调用 reboot，留下痕迹用于断言
cat >"${MOCKBIN}/reboot" <<'EOF'
#!/usr/bin/env bash
touch "${MOCK_ROOT}/calls/reboot"
exit 0
EOF
chmod +x "${MOCKBIN}/reboot"

# 以「已获得 root」的驱动方式加载脚本，只替换权限闸门，其余代码路径全部为真实实现
cat >"${DRIVER}" <<EOF
#!/usr/bin/env bash
source "${FIX_SH}"
require_root() { return 0; }
main "\$@"
EOF

MOCKBIN_POSIX="$(cygpath -u "${MOCKBIN}" 2>/dev/null || printf '%s' "${MOCKBIN}")"

# 预热模拟器：Windows/Git Bash 下首次执行新生成的脚本可能因安全软件扫描而异常缓慢，
# 先各执行一次，避免首个用例被首次启动开销拖垮（不影响任何断言）。
for prog in dpkg dpkg-query apt-get apt-cache update-grub uname; do
    "${MOCKBIN_POSIX}/${prog}" --version >/dev/null 2>&1 || true
done

# ---------------------------------------------------------------------------
# 场景构造
# ---------------------------------------------------------------------------

SCEN=""

scenario() {
    local name="$1" release="$2" version_id=""
    SCEN="${TMPROOT}/scen/${name}"
    rm -rf "${SCEN}"
    mkdir -p "${SCEN}/root/etc/apt/sources.list.d" \
        "${SCEN}/root/boot/grub" \
        "${SCEN}/root/var/lib/apt/lists" \
        "${SCEN}/state/flags" \
        "${SCEN}/state/calls"

    case "${release}" in
        bookworm) version_id="12" ;;
        trixie) version_id="13" ;;
        *) version_id="99" ;;
    esac

    cat >"${SCEN}/root/etc/os-release" <<EOF
PRETTY_NAME="Debian GNU/Linux ${version_id} (${release})"
NAME="Debian GNU/Linux"
VERSION_ID="${version_id}"
VERSION="${version_id} (${release})"
VERSION_CODENAME=${release}
ID=debian
EOF

    printf 'deb https://deb.debian.org/debian %s main\n' "${release}" >"${SCEN}/root/etc/apt/sources.list"
    printf 'deb https://security.debian.org/debian-security %s-security main\n' "${release}" \
        >>"${SCEN}/root/etc/apt/sources.list"
    printf 'mock apt lists\n' \
        >"${SCEN}/root/var/lib/apt/lists/security.debian.org_debian-security_dists_${release}-security_main_binary-amd64_Packages"
    printf '### grub.cfg\n' >"${SCEN}/root/boot/grub/grub.cfg"

    : >"${SCEN}/state/installed.tsv"
    : >"${SCEN}/state/deps.tsv"

    if [[ ${release} == "bookworm" ]]; then
        cat >"${SCEN}/state/available.tsv" <<'EOF'
linux-image-amd64	6.1.190-1
linux-image-cloud-amd64	6.1.190-1
linux-image-6.1.0-54-amd64	6.1.190-1
linux-image-6.1.0-54-cloud-amd64	6.1.190-1
linux-image-6.12-amd64	6.12.113-1~deb12u1
linux-image-6.12.113+deb12-amd64	6.12.113-1~deb12u1
EOF
        cat >"${SCEN}/state/deps.tsv" <<'EOF'
linux-image-amd64	linux-image-6.1.0-54-amd64	6.1.190-1	6.1.0-54-amd64
linux-image-cloud-amd64	linux-image-6.1.0-54-cloud-amd64	6.1.190-1	6.1.0-54-cloud-amd64
linux-image-6.12-amd64	linux-image-6.12.113+deb12-amd64	6.12.113-1~deb12u1	6.12.113+deb12-amd64
EOF
    elif [[ ${release} == "trixie" ]]; then
        cat >"${SCEN}/state/available.tsv" <<'EOF'
linux-image-amd64	6.12.113-1
linux-image-6.12.113+deb13-amd64	6.12.113-1
EOF
        cat >"${SCEN}/state/deps.tsv" <<'EOF'
linux-image-amd64	linux-image-6.12.113+deb13-amd64	6.12.113-1	6.12.113+deb13-amd64
EOF
    else
        : >"${SCEN}/state/available.tsv"
    fi

    printf 'x86_64\n' >"${SCEN}/state/uname_m"
    printf '6.1.0-49-amd64\n' >"${SCEN}/state/uname_r"
}

set_kernel() {
    printf '%s\n' "$1" >"${SCEN}/state/uname_r"
}

set_arch() {
    printf '%s\n' "$1" >"${SCEN}/state/uname_m"
}

add_kernel() {
    local pkg="$1" version="$2" release="$3"
    printf '%s\t%s\tinstalled\n' "${pkg}" "${version}" >>"${SCEN}/state/installed.tsv"
    printf '\177ELF mock kernel\n' >"${SCEN}/root/boot/vmlinuz-${release}"
    printf 'mock initramfs\n' >"${SCEN}/root/boot/initrd.img-${release}"
    printf "\tmenuentry 'Debian GNU/Linux, kernel %s' {}\n" "${release}" >>"${SCEN}/root/boot/grub/grub.cfg"
}

set_flag() {
    : >"${SCEN}/state/flags/$1"
}

run_fix() {
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

run_fix_stdin() {
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

# 直接执行脚本（不加载驱动），用于验证真实权限闸门
run_fix_direct() {
    OUT="$(
        cd "${SCEN}" &&
            FIX_SYSROOT="${SCEN}/root" \
                MOCK_ROOT="${SCEN}/state" \
                PATH="${MOCKBIN_POSIX}:${PATH}" \
                bash "${FIX_SH}" "$@" 2>&1
    )"
    RC=$?
}

run_snippet() {
    local snippet="$1"
    OUT="$(
        MOCK_ROOT="${SCEN}/state" \
            PATH="${MOCKBIN_POSIX}:${PATH}" \
            bash -c "source '${FIX_SH}'; set +e; ${snippet}" 2>&1
    )"
    RC=$?
}

printf '%s\n' "${C_BOLD}fix.sh 测试套件${C_RESET}"
printf '脚本: %s\n' "${FIX_SH}"
printf '模拟根目录: %s\n' "${TMPROOT}"

# ---------------------------------------------------------------------------
# 一、环境识别
# ---------------------------------------------------------------------------

begin_case "1. Debian 12 Bookworm 环境识别"
scenario bookworm-fixed bookworm
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64
set_kernel 6.1.0-54-amd64
run_fix --check
assert_rc 0
assert_has "Debian GNU/Linux 12 (bookworm)"
assert_has "bookworm"
assert_has "6.1.0-54-amd64"
assert_has "判定结果：已修复"
end_case

begin_case "2. Debian 13 Trixie 环境识别"
scenario trixie-fixed trixie
add_kernel linux-image-6.12.113+deb13-amd64 6.12.113-1 6.12.113+deb13-amd64
set_kernel 6.12.113+deb13-amd64
run_fix --check
assert_rc 0
assert_has "Debian GNU/Linux 13 (trixie)"
assert_has "判定结果：已修复"
assert_has "6.12.113-1"
end_case

begin_case "3. 不支持的系统拒绝执行"
# v1.1.0 起 Ubuntu 已进入「支持检测」列表，因此用真正未收录的发行版做拒绝样本
scenario unsupported bookworm
cat >"${SCEN}/root/etc/os-release" <<'EOF'
PRETTY_NAME="Gentoo Linux"
NAME=Gentoo
VERSION_ID="2.17"
ID=gentoo
EOF
run_fix --check
assert_rc 1
assert_has "判定结果：不支持"
assert_has "不在本工具支持的发行版列表中"
assert_no_file "${SCEN}/state/calls/apt_install"

scenario debian14 bookworm
cat >"${SCEN}/root/etc/os-release" <<'EOF'
PRETTY_NAME="Debian GNU/Linux 14 (forky)"
NAME="Debian GNU/Linux"
VERSION_ID="14"
VERSION_CODENAME=forky
ID=debian
EOF
run_fix --check
assert_rc 1
assert_has "仅支持 Debian 12 (bookworm) 与 Debian 13 (trixie)"
end_case

begin_case "4. 非 root 权限提示"
scenario nonroot bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
run_fix_direct --check
assert_rc 1
assert_has "需要 root 权限运行本脚本"
assert_has "sudo bash"
end_case

begin_case "5. amd64 架构识别与其他架构拒绝"
scenario arch bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
run_fix --check
assert_rc 2
assert_has "CPU 架构：x86_64（amd64）"

set_arch aarch64
run_fix --check
assert_rc 1
assert_has "仅支持 amd64"
end_case

begin_case "6. 已修复内核识别（含 Debian 回移版本）"
scenario fixed-backport bookworm
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64
add_kernel linux-image-6.1.0-50-amd64 6.1.176-1 6.1.0-50-amd64
set_kernel 6.1.0-54-amd64
run_fix --check
assert_rc 0
assert_has "判定结果：已修复"
assert_has "达到官方修复版本 6.1.190-1"
assert_lacks "存在漏洞"
end_case

begin_case "7. 受影响内核识别"
scenario vulnerable bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
set_kernel 6.1.0-49-amd64
run_fix --check
assert_rc 2
assert_has "判定结果：存在漏洞"
assert_has "低于官方修复版本 6.1.190-1"
assert_has "预计安装：linux-image-amd64"
end_case

begin_case "8. 已安装新内核但未重启"
scenario pending bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64
set_kernel 6.1.0-49-amd64
run_fix --check
assert_rc 3
assert_has "判定结果：待重启"
assert_has "需要重启后才会生效"
assert_has "reboot"
assert_no_file "${SCEN}/state/calls/apt_install"
# 判定阶段就已待重启：本轮没有安装任何东西，不能显示「新安装内核 / 安装状态成功」
assert_has "不适用（等待重启）"
assert_has "此前已安装，本次未执行安装"
assert_lacks "新安装内核"
# 直接运行源码时，重跑提示仍指向本地 fix.sh
assert_has "sudo bash fix.sh --check"
end_case

begin_case "8b. 一键安装模式：重跑提示给出可执行的完整命令"
scenario pending-boot bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64
set_kernel 6.1.0-49-amd64
export FIX_BOOTSTRAP_CMD="curl -fsSL https://example.invalid/install.sh | sudo bash -s --"
run_fix --check
unset FIX_BOOTSTRAP_CMD
assert_rc 3
# 一键模式下机器上并没有 fix.sh，提示必须是一整条可粘贴执行的命令
assert_has "curl -fsSL https://example.invalid/install.sh | sudo bash -s -- --check"
assert_lacks "sudo bash fix.sh"
assert_has "此前已安装，本次未执行安装"
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

begin_case "8c. 一键安装模式：--help 说明工具不会留在磁盘"
scenario pending-help bookworm
export FIX_BOOTSTRAP_CMD="curl -fsSL https://example.invalid/install.sh | sudo bash -s --"
run_fix --help
unset FIX_BOOTSTRAP_CMD
assert_rc 0
assert_has "退出后即被删除"
assert_has "再次执行请使用：curl -fsSL https://example.invalid/install.sh | sudo bash -s -- --check"
end_case

# ---------------------------------------------------------------------------
# 二、修复流程与失败处理
# ---------------------------------------------------------------------------

begin_case "9. APT 更新失败处理"
scenario apt-update-fail bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
set_flag apt_update_fail
run_fix --yes
assert_rc 1
assert_has "apt-get update 执行失败"
assert_has "未安装任何内核"
assert_has "Temporary failure resolving"
assert_no_file "${SCEN}/state/calls/apt_install"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "10. 内核安装失败处理"
scenario install-fail bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
set_flag apt_install_fail
run_fix --yes
assert_rc 1
assert_has "内核安装失败"
assert_has "Unable to correct problems"
assert_has "当前仍运行 6.1.0-49-amd64"
assert_no_file "${SCEN}/state/calls/reboot"
assert_not_line "linux-image-6.1.0-54-amd64" "${SCEN}/state/installed.tsv"
end_case

begin_case "11. initramfs 生成失败处理"
scenario initramfs-fail bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
set_flag skip_initramfs
run_fix --yes
assert_rc 1
assert_has "未检测到有效的 initramfs"
assert_has "update-initramfs -c -k 6.1.0-54-amd64"
assert_lacks "修复结果"
end_case

begin_case "12. GRUB 更新失败处理"
scenario grub-fail bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
set_flag skip_grub_entry
set_flag grub_fail
run_fix --yes
assert_rc 1
assert_has "update-grub 执行失败"
assert_no_file "${SCEN}/state/calls/reboot"

scenario grub-missing bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
set_flag skip_grub_entry
printf '6.1.0-54-amd64\n' >"${SCEN}/state/grub_exclude.txt"
run_fix --yes
assert_rc 1
assert_has "仍不包含新内核"
end_case

begin_case "13. --check 只读模式"
scenario readonly bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
before="$(md5sum "${SCEN}/state/installed.tsv" 2>/dev/null | awk '{print $1}')"
run_fix --check
assert_rc 2
assert_has "模式：只读检测"
after="$(md5sum "${SCEN}/state/installed.tsv" 2>/dev/null | awk '{print $1}')"
if [[ ${before} != "${after}" ]]; then
    fail "installed 状态被修改（--check 不应改动系统）"
fi
assert_no_file "${SCEN}/state/calls/apt_update"
assert_no_file "${SCEN}/state/calls/apt_install"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "14. --help / --version / 非法参数"
scenario args bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
run_fix --help
assert_rc 0
assert_has "用法:"
assert_has "--check"
assert_has "退出码"

run_fix --version
assert_rc 0
assert_has "1.3.2"

run_fix --bogus
assert_rc 1
assert_has "未知参数"
end_case

begin_case "15. 用户取消操作"
scenario cancel bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
run_fix_stdin "n
"
assert_rc 5
assert_has "已取消，系统未做任何修改"
assert_no_file "${SCEN}/state/calls/apt_update"
assert_no_file "${SCEN}/state/calls/apt_install"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "16. 修复流程完整执行（安装成功 → 待重启）"
scenario full-fix bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
run_fix_stdin "y
"
assert_rc 3
assert_has "apt-get install"
assert_has "已安装修复内核：6.1.0-54-amd64"
assert_has "initramfs 已生成"
assert_has "引导配置已包含新内核：/boot/grub/grub.cfg"
assert_has "新内核已经安装，但当前服务器仍在运行旧内核"
assert_has "是否需要重启"
assert_has "reboot"
assert_line "linux-image-6.1.0-54-amd64	6.1.190-1	installed" "${SCEN}/state/installed.tsv"
assert_file "${SCEN}/root/boot/initrd.img-6.1.0-54-amd64"
assert_line "6.1.0-54-amd64" "${SCEN}/root/boot/grub/grub.cfg"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "17. 修复后二次验证（模拟重启后重跑）"
scenario reverify bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64
set_kernel 6.1.0-54-amd64
run_fix --check
assert_rc 0
assert_has "判定结果：已修复"
assert_has "6.1.190-1"
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

# ---------------------------------------------------------------------------
# 三、发行版 / 分支边界
# ---------------------------------------------------------------------------

begin_case "18. Debian 12 的 6.12 回移分支"
scenario bookworm-612 bookworm
add_kernel linux-image-6.12.100+deb12-amd64 6.12.100-1~deb12u1 6.12.100+deb12-amd64
set_kernel 6.12.100+deb12-amd64
run_fix --check
assert_rc 2
assert_has "内核分支"
assert_has "6.12"
assert_has "6.12.113-1~deb12u1"
assert_has "预计安装：linux-image-6.12-amd64"

run_fix --yes
assert_rc 3
assert_has "已安装修复内核：6.12.113+deb12-amd64"
end_case

begin_case "19. Debian 13 受影响内核修复"
scenario trixie-vuln trixie
add_kernel linux-image-6.12.107+deb13-amd64 6.12.107-1 6.12.107+deb13-amd64
set_kernel 6.12.107+deb13-amd64
run_fix --yes
assert_rc 3
assert_has "已安装修复内核：6.12.113+deb13-amd64"
assert_line "linux-image-6.12.113+deb13-amd64	6.12.113-1	installed" "${SCEN}/state/installed.tsv"
end_case

begin_case "20. 未知内核分支判定为无法确认"
scenario unknown-branch bookworm
add_kernel linux-image-5.10.0-30-amd64 5.10.209-2 5.10.0-30-amd64
set_kernel 5.10.0-30-amd64
run_fix --check
assert_rc 4
assert_has "判定结果：无法确认"
assert_has "不在已核实的修复版本表中"
assert_lacks "判定结果：已修复"
end_case

begin_case "21. 自编译内核（无法映射软件包）判定为无法确认"
scenario custom-kernel bookworm
run_fix --check
assert_rc 4
assert_has "判定结果：无法确认"
assert_has "可能为自编译或第三方内核"
end_case

begin_case "22. 软件源缺少修复版本时安全退出"
scenario no-fix bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
cat >"${SCEN}/state/available.tsv" <<'EOF'
linux-image-amd64	6.1.176-1
linux-image-6.1.0-50-amd64	6.1.176-1
EOF
run_fix --yes
assert_rc 1
assert_has "未找到分支 6.1 且版本 >= 6.1.190-1 的内核包"
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

begin_case "23. 元包候选过旧时回退到具体镜像包"
scenario fallback bookworm
add_kernel linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
cat >"${SCEN}/state/available.tsv" <<'EOF'
linux-image-amd64	6.1.176-1
linux-image-6.1.0-54-amd64	6.1.190-1
EOF
run_fix --check
assert_rc 2
assert_has "预计安装：linux-image-6.1.0-54-amd64"
end_case

# ---------------------------------------------------------------------------
# 四、版本比较与回移判断（单元测试）
# ---------------------------------------------------------------------------

begin_case "24. Debian 版本比较规则"
scenario version-cmp bookworm
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64

check_ge() {
    local left="$1" right="$2" expected="$3" note="$4"
    run_snippet "version_ge '${left}' '${right}'"
    if [[ ${RC} -eq 0 ]]; then
        actual="yes"
    else
        actual="no"
    fi
    if [[ ${actual} != "${expected}" ]]; then
        fail "version_ge ${left} ${right} 期望 ${expected}，实际 ${actual}（${note}）"
    fi
}

check_ge "6.1.190-1" "6.1.190-1" "yes" "相等"
check_ge "6.1.174-1" "6.1.190-1" "no" "旧版本"
check_ge "6.1.190-1" "6.1.174-1" "yes" "新版本"
check_ge "6.1.0-54" "6.1.0-9" "yes" "数字段按数值比较"
check_ge "6.12.113-1~deb12u1" "6.12.113-1" "no" "波浪号回移版本低于正式版本"
check_ge "6.12.113-1~deb12u1" "6.12.113-1~deb12u1" "yes" "回移版本相等"
check_ge "6.12.113-1~deb12u2" "6.12.113-1~deb12u1" "yes" "回移修订号递增"
check_ge "1:1.0-1" "2.0-1" "yes" "epoch 优先"
check_ge "6.1.190-1+deb12u1" "6.1.190-1" "yes" "带 +deb 后缀"
check_ge "6.12.113-1" "6.12.113-1~deb12u1" "yes" "正式版高于回移版"
end_case

begin_case "25. 修复版本基线与分支匹配"
scenario baseline bookworm
add_kernel linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64

run_snippet 'printf "%s\n" "$(fixed_version_for bookworm 6.1)"'
assert_has "6.1.190-1"

run_snippet 'printf "%s\n" "$(fixed_version_for bookworm 6.12)"'
assert_has "6.12.113-1~deb12u1"

run_snippet 'printf "%s\n" "$(fixed_version_for trixie 6.12)"'
assert_has "6.12.113-1"

run_snippet 'fixed_version_for trixie 6.1 || echo "未收录"'
assert_has "未收录"

run_snippet 'KERNEL_BRANCH=6.1; FIXED_VERSION=6.1.190-1; candidate_usable "6.12.113-1~deb12u1" && echo accept || echo reject'
assert_has "reject"

run_snippet 'KERNEL_BRANCH=6.1; FIXED_VERSION=6.1.190-1; candidate_usable "6.1.190-1" && echo accept || echo reject'
assert_has "accept"

run_snippet 'KERNEL_BRANCH=6.1; FIXED_VERSION=6.1.190-1; candidate_usable "6.1.176-1" && echo accept || echo reject'
assert_has "reject"
end_case

# ---------------------------------------------------------------------------
# 五、静态安全检查
# ---------------------------------------------------------------------------

begin_case "26. 静态安全检查（无危险操作）"
# v1.1.0 拆分为多文件，静态检查必须覆盖全部脚本
SH_FILES=("${FIX_SH}" "${REPO_DIR}/lib/"*.sh "${REPO_DIR}/adapters/"*.sh)
for f in "${SH_FILES[@]}"; do
    if ! grep -q 'set -Eeuo pipefail' "${FIX_SH}"; then
        fail "缺少 set -Eeuo pipefail"
        break
    fi
done

for f in "${SH_FILES[@]}"; do
    for pattern in \
        'apt-get[^|]*dist-upgrade' \
        'apt-get[^|]*-y[^|]*upgrade' \
        'dnf[^|]*upgrade[^|]*--all' \
        'rm[[:space:]]+-[rf]+[[:space:]]+/(boot|lib/modules|usr/lib/modules)' \
        'shutdown[[:space:]]+-r' \
        'systemctl[[:space:]]+reboot' \
        'curl[[:space:]]' \
        'wget[[:space:]]' \
        'allow-unauthenticated' \
        '--nogpgcheck'; do
        if grep -Eq -- "${pattern}" "${f}"; then
            fail "脚本 ${f#"${REPO_DIR}/"} 包含被禁止的操作：${pattern}"
        fi
    done
    if grep -Eq '^[[:space:]]*(sudo[[:space:]]+)?reboot([[:space:]]|$)' "${f}"; then
        fail "脚本 ${f#"${REPO_DIR}/"} 包含直接调用 reboot 的语句"
    fi
done

if command -v shellcheck >/dev/null 2>&1; then
    SC_OUTPUT="$(shellcheck -S style -x "${SH_FILES[@]}" 2>&1 || true)"
    if [[ -n ${SC_OUTPUT} ]]; then
        printf '%s\n' "${SC_OUTPUT}" | head -n 40
        fail "ShellCheck 报告问题"
    fi
else
    printf '    %s·%s 未安装 shellcheck，跳过静态检查（见 README 安装方式）\n' "${C_DIM}" "${C_RESET}"
fi
end_case

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

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
