#!/usr/bin/env bash
#
# tests/test_safety.sh - 安全边界与能力声明
#
# 覆盖：未启用自动修复的发行版即使 --yes 也绝不安装、--check 全程只读、
#       --report 无副作用、adapter 能力声明完整、自动修复白名单最小化、
#       静态扫描无危险操作。

# shellcheck disable=SC2016
set -uo pipefail

# shellcheck source=tests/lib/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/harness.sh"

h_init "安全边界测试"

state_digest() {
    (cd "$1" && find state -type f -print0 | sort -z | xargs -0 md5sum 2>/dev/null | md5sum)
}

# ---------------------------------------------------------------------------
# 白名单之外不得安装
# ---------------------------------------------------------------------------

begin_case "S1. Rocky Linux 即使 --yes 也不执行安装"
h_scenario rocky-yes
h_os_release <<'EOF'
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
NAME="Rocky Linux"
VERSION_ID="9.4"
ID="rocky"
ID_LIKE="rhel centos fedora"
EOF
h_install_rpm kernel 5.14.0-427.9.1.el9_4
h_avail_rpm kernel 5.14.0-427.13.1.el9_4
h_set_kernel 5.14.0-427.9.1.el9_4.x86_64
h_run --yes
assert_rc 4
assert_has "判定结果：无法确认"
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/dnf_makecache"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "S2. Ubuntu 即使 --yes 也不执行安装"
h_scenario ubuntu-yes
h_os_release <<'EOF'
PRETTY_NAME="Ubuntu 22.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION_CODENAME=jammy
ID=ubuntu
EOF
h_apt_sources jammy
h_install_deb linux-image-5.15.0-119-generic 5.15.0-119.129 5.15.0-119-generic
h_set_kernel 5.15.0-119-generic
h_run --yes
assert_rc 6
assert_no_file "${SCEN}/state/calls/apt_install"
assert_no_file "${SCEN}/state/calls/apt_update"
end_case

begin_case "S3. SUSE 官方状态不可核验时不安装"
h_scenario suse-yes
h_os_release <<'EOF'
PRETTY_NAME="openSUSE Leap 15.6"
NAME="openSUSE Leap"
VERSION_ID="15.6"
ID="opensuse-leap"
EOF
h_install_rpm kernel-default 6.4.0-150600.23.25
h_set_kernel 6.4.0-150600.23.25-default
h_run --yes
assert_rc 4
assert_has "无法确认"
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

# ---------------------------------------------------------------------------
# 只读入口
# ---------------------------------------------------------------------------

begin_case "S4. --check 全程只读"
h_scenario check-readonly
h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2023"
NAME="Amazon Linux"
VERSION_ID="2023"
ID="amzn"
EOF
h_install_rpm kernel 6.1.180-220.380.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.180-220.380.amzn2023.x86_64
BEFORE="$(state_digest "${SCEN}")"
h_run --check
assert_rc 2
AFTER="$(state_digest "${SCEN}")"
if [[ ${BEFORE} != "${AFTER}" ]]; then
    fail "--check 改动了包管理器状态"
fi
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/dnf_makecache"
end_case

begin_case "S5. --report 无副作用且不含敏感信息"
h_scenario report-safe
h_os_release <<'EOF'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian
EOF
h_apt_sources bookworm
h_install_deb linux-image-6.1.0-49-amd64 6.1.174-1 6.1.0-49-amd64
h_set_kernel 6.1.0-49-amd64
BEFORE="$(state_digest "${SCEN}")"
h_run --report "${SCEN}/report.txt"
assert_rc 2
AFTER="$(state_digest "${SCEN}")"
if [[ ${BEFORE} != "${AFTER}" ]]; then
    fail "--report 改动了包管理器状态"
fi
assert_no_file "${SCEN}/state/calls/apt_install"
assert_file "${SCEN}/report.txt"
if [[ -f ${SCEN}/report.txt ]]; then
    if grep -Eqi "password|passwd|secret|token|BEGIN [A-Z ]*PRIVATE KEY" "${SCEN}/report.txt"; then
        fail "报告包含疑似敏感信息"
    fi
fi
end_case

# ---------------------------------------------------------------------------
# adapter 能力声明
# ---------------------------------------------------------------------------

begin_case "S6. 每个 adapter 都显式声明能力与核验信息"
for f in "${REPO_DIR}/adapters/"*.sh; do
    base="${f##*/}"
    for key in ADAPTER_ID ADAPTER_DATA_DISTRO ADAPTER_NAME ADAPTER_FAMILY \
        ADAPTER_DETECT_SUPPORTED ADAPTER_AUTOFIX_DEFAULT ADAPTER_ARCHES \
        ADAPTER_ADVISORY_URL ADAPTER_UPDATE_PROCEDURE ADAPTER_NOTES; do
        if ! grep -q "^${key}=" "${f}"; then
            fail "${base} 缺少声明：${key}"
        fi
    done
    if ! grep -q '^ADAPTER_DETECT_SUPPORTED=1' "${f}"; then
        fail "${base} 未声明检测支持"
    fi
done
end_case

begin_case "S7. 自动修复白名单最小化且基线完整"
AUTOFIX_ADAPTERS="$(grep -l '^ADAPTER_AUTOFIX_DEFAULT=1' "${REPO_DIR}/adapters/"*.sh | xargs -n1 basename | sort | tr '\n' ' ')"
if [[ ${AUTOFIX_ADAPTERS} != "amazon_linux.sh debian.sh " ]]; then
    fail "自动修复白名单异常：${AUTOFIX_ADAPTERS}"
fi

# 数据文件：autofix=yes 的记录必须具备 status=fixed 与非空 fixed_version
BAD="$(awk -F'"' '
    function flush() {
        if (id != "" && af == "yes" && (st != "fixed" || fv == "")) print id
    }
    /^- /{ flush(); id=""; st=""; fv=""; af="" }
    /^  id:/{ id=$2 }
    /^  status:/{ st=$2 }
    /^  fixed_version:/{ fv=$2 }
    /^  autofix:/{ af=$2 }
    END { flush() }
' "${REPO_DIR}/data/cve-2026-98432.yml")"
if [[ -n ${BAD} ]]; then
    fail "以下基线允许自动修复但缺少修复版本：${BAD}"
fi

# 每个 adapter 的数据发行版必须至少有一条基线记录
for f in "${REPO_DIR}/adapters/"*.sh; do
    data_distro="$(grep '^ADAPTER_DATA_DISTRO=' "${f}" | head -n 1 | cut -d'"' -f2)"
    if ! grep -q "^  distro: \"${data_distro}\"$" "${REPO_DIR}/data/cve-2026-98432.yml"; then
        fail "${f##*/} 的数据发行版 ${data_distro} 没有基线记录"
    fi
done
end_case

begin_case "S8. 静态扫描：无危险操作"
SH_FILES=("${REPO_DIR}/fix.sh" "${REPO_DIR}/lib/"*.sh "${REPO_DIR}/adapters/"*.sh)
for f in "${SH_FILES[@]}"; do
    name="${f#"${REPO_DIR}/"}"
    for pattern in \
        'curl[[:space:]]' \
        'wget[[:space:]]' \
        'apt-get[^|]*dist-upgrade' \
        'dnf[^|]*upgrade[^|]*--all' \
        'rm[[:space:]]+-[rf]+[[:space:]]+/(boot|lib/modules|usr/lib/modules)' \
        'systemctl[[:space:]]+reboot' \
        'shutdown[[:space:]]+-r' \
        'allow-unauthenticated' \
        '--nogpgcheck'; do
        if grep -Eq -- "${pattern}" "${f}"; then
            fail "${name} 包含被禁止的操作：${pattern}"
        fi
    done
    if grep -Eq '^[[:space:]]*(sudo[[:space:]]+)?reboot([[:space:]]|$)' "${f}"; then
        fail "${name} 包含直接调用 reboot 的语句"
    fi
done
end_case

finish_suite
