#!/usr/bin/env bash
#
# tests/test_detection.sh - 多发行版识别与状态机
#
# 覆盖：Ubuntu 20.04/22.04/24.04、RHEL 8/9/10、Rocky 与 Alma 区分、
#       Oracle UEK 与 RHCK 区分、Amazon Linux 2 与 2023 区分、
#       Fedora/openSUSE/SUSE/Arch/Alpine 识别、x86_64 与 aarch64、
#       不支持的架构、官方未修复时绝不安装、公告不可访问、
#       缺少修复版本、容器环境、--list-distros、--report。

# shellcheck disable=SC2016
set -uo pipefail

# shellcheck source=tests/lib/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/harness.sh"

h_init "多发行版识别与状态机测试"

# ---------------------------------------------------------------------------
# Ubuntu
# ---------------------------------------------------------------------------

begin_case "D1. Ubuntu 24.04 识别，官方未修复时只检测"
h_scenario ubuntu-2404
h_os_release <<'EOF'
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
EOF
h_apt_sources noble
h_install_deb linux-image-6.8.0-45-generic 6.8.0-45.45 6.8.0-45-generic
h_set_kernel 6.8.0-45-generic
h_run --check
assert_rc 6
assert_has "Ubuntu 24.04.1 LTS"
assert_has "判定结果：官方尚未修复"
assert_has "官方尚未发布可确认的修复包"
assert_has "未启用（仅检测）"
assert_lacks "apt-get install"
end_case

begin_case "D2. Ubuntu 22.04 / 20.04 识别"
h_scenario ubuntu-2204
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
h_run --check
assert_rc 6
assert_has "Ubuntu 22.04.4 LTS"
assert_has "判定结果：官方尚未修复"

h_scenario ubuntu-2004
h_os_release <<'EOF'
PRETTY_NAME="Ubuntu 20.04.6 LTS"
NAME="Ubuntu"
VERSION_ID="20.04"
VERSION_CODENAME=focal
ID=ubuntu
EOF
h_apt_sources focal
h_install_deb linux-image-5.4.0-200-generic 5.4.0-200.220 5.4.0-200-generic
h_set_kernel 5.4.0-200-generic
h_run --check
assert_rc 6
assert_has "Ubuntu 20.04.6 LTS"
assert_has "判定结果：官方尚未修复"
end_case

# ---------------------------------------------------------------------------
# RHEL
# ---------------------------------------------------------------------------

begin_case "D3. RHEL 9 识别，未确认补丁时只检测"
h_scenario rhel9
h_os_release <<'EOF'
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
NAME="Red Hat Enterprise Linux"
VERSION_ID="9.4"
VERSION_CODENAME="plow"
ID="rhel"
ID_LIKE="fedora"
EOF
h_yum_repo
h_install_rpm kernel 5.14.0-427.13.1.el9_4
h_set_kernel 5.14.0-427.13.1.el9_4.x86_64
h_run --check
assert_rc 6
assert_has "Red Hat Enterprise Linux 9.4"
assert_has "kernel 5.14.0-427.13.1.el9_4"
assert_has "判定结果：官方尚未修复"
assert_lacks "dnf install"
end_case

begin_case "D4. RHEL 8 / 10 识别"
h_scenario rhel8
h_os_release <<'EOF'
PRETTY_NAME="Red Hat Enterprise Linux 8.10 (Ootpa)"
NAME="Red Hat Enterprise Linux"
VERSION_ID="8.10"
ID="rhel"
EOF
h_install_rpm kernel 4.18.0-553.el8_10
h_set_kernel 4.18.0-553.el8_10.x86_64
h_run --check
assert_rc 6
assert_has "Red Hat Enterprise Linux 8.10"

h_scenario rhel10
h_os_release <<'EOF'
PRETTY_NAME="Red Hat Enterprise Linux 10.0 (Coughlan)"
NAME="Red Hat Enterprise Linux"
VERSION_ID="10.0"
ID="rhel"
EOF
h_install_rpm kernel 6.12.0-55.el10
h_set_kernel 6.12.0-55.el10.x86_64
h_run --check
assert_rc 6
assert_has "Red Hat Enterprise Linux 10.0"
end_case

# ---------------------------------------------------------------------------
# 衍生版身份区分
# ---------------------------------------------------------------------------

begin_case "D5. Rocky 与 AlmaLinux 不得折叠为 RHEL"
h_scenario rocky9
h_os_release <<'EOF'
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
NAME="Rocky Linux"
VERSION_ID="9.4"
ID="rocky"
ID_LIKE="rhel centos fedora"
EOF
h_install_rpm kernel 5.14.0-427.13.1.el9_4
h_set_kernel 5.14.0-427.13.1.el9_4.x86_64
h_run --check
assert_rc 4
assert_has "Rocky Linux 9.4"
assert_has "判定结果：无法确认"
assert_lacks "Red Hat Enterprise Linux 9.4"
ROCKY_OUT="${OUT}"

h_scenario alma9
h_os_release <<'EOF'
PRETTY_NAME="AlmaLinux 9.4 (Seafoam Ocelot)"
NAME="AlmaLinux"
VERSION_ID="9.4"
ID="almalinux"
ID_LIKE="rhel centos fedora"
EOF
h_install_rpm kernel 5.14.0-427.13.1.el9_4
h_set_kernel 5.14.0-427.13.1.el9_4.x86_64
h_run --check
# v1.2.0 起 AlmaLinux 8/9/10 的修复内核只在 testing 仓库，
# 判定为 PATCH_TESTING_ONLY（退出码 7），仍然不允许自动安装。
assert_rc 7
assert_has "AlmaLinux 9.4"
assert_has "判定结果：仅测试仓库有补丁"
assert_lacks "Rocky Linux"
if grep -Fq "Rocky Linux" <<<"${ROCKY_OUT}"; then
    :
else
    fail "Rocky 输出应包含自身名称"
fi
end_case

begin_case "D6. Oracle Linux 区分 UEK 与 RHCK"
h_scenario oracle-uek
h_os_release <<'EOF'
PRETTY_NAME="Oracle Linux Server 9.4"
NAME="Oracle Linux Server"
VERSION_ID="9.4"
ID="ol"
ID_LIKE="fedora"
EOF
h_install_rpm kernel-uek 5.15.0-200.131.27.el9uek
h_set_kernel 5.15.0-200.131.27.el9uek.x86_64
h_run --check
# v1.2.0 起 OL9 的 UEKR7 有 ELSA-2026-500398 基线：能给出修复版本，
# 但未完成实机验证，仍然只检测、不安装。
assert_rc 2
assert_has "kernel-uek"
assert_has "Oracle Linux Server 9.4"
assert_has "ELSA-2026-500398"
assert_has "未启用自动修复"
assert_no_file "${SCEN}/state/calls/dnf_install"

h_scenario oracle-rhck
h_os_release <<'EOF'
PRETTY_NAME="Oracle Linux Server 9.4"
NAME="Oracle Linux Server"
VERSION_ID="9.4"
ID="ol"
ID_LIKE="fedora"
EOF
h_install_rpm kernel 5.14.0-427.13.1.el9_4
h_set_kernel 5.14.0-427.13.1.el9_4.x86_64
h_run --check
assert_rc 4
assert_has "kernel 5.14.0-427.13.1.el9_4"
assert_lacks "kernel-uek"
end_case

# ---------------------------------------------------------------------------
# Amazon Linux 身份
# ---------------------------------------------------------------------------

begin_case "D7. Amazon Linux 2 与 AL2023 独立识别"
h_scenario al2-ident
h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2"
NAME="Amazon Linux"
VERSION_ID="2"
ID="amzn"
ID_LIKE="centos rhel fedora"
EOF
h_install_rpm kernel 4.14.350-279.365.amzn2
h_avail_rpm kernel 4.14.355-287.758.amzn2
h_set_kernel 4.14.350-279.365.amzn2.x86_64
h_run --check
assert_rc 2
assert_has "Amazon Linux 2"
assert_has "预计安装：kernel"

h_scenario al2023-ident
h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2023"
NAME="Amazon Linux"
VERSION_ID="2023"
ID="amzn"
ID_LIKE="fedora"
EOF
h_install_rpm kernel6.12 6.12.100-120.180.amzn2023
h_avail_rpm kernel6.12 6.12.113-138.209.amzn2023
h_set_kernel 6.12.100-120.180.amzn2023.x86_64
h_run --check
assert_rc 2
assert_has "Amazon Linux 2023"
assert_has "预计安装：kernel6.12"
end_case

# ---------------------------------------------------------------------------
# 其他发行版识别
# ---------------------------------------------------------------------------

begin_case "D8. Fedora / openSUSE / SUSE / Arch / Alpine 识别"
h_scenario fedora
h_os_release <<'EOF'
PRETTY_NAME="Fedora Linux 44 (Workstation Edition)"
NAME="Fedora Linux"
VERSION_ID="44"
ID=fedora
EOF
h_install_rpm kernel 7.2.14-200.fc44
h_set_kernel 7.2.14-200.fc44.x86_64
h_run --check
assert_rc 4
assert_has "Fedora Linux 44"
assert_has "判定结果：无法确认"

h_scenario leap
h_os_release <<'EOF'
PRETTY_NAME="openSUSE Leap 15.6"
NAME="openSUSE Leap"
VERSION_ID="15.6"
ID="opensuse-leap"
ID_LIKE="suse opensuse"
EOF
h_install_rpm kernel-default 6.4.0-150600.23.25
h_set_kernel 6.4.0-150600.23.25-default
h_run --check
assert_rc 4
assert_has "openSUSE Leap 15.6"

h_scenario sles
h_os_release <<'EOF'
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP5"
NAME="SLES"
VERSION_ID="15.5"
ID="sles"
ID_LIKE="suse"
EOF
h_install_rpm kernel-default 5.14.21-150500.55.68
h_set_kernel 5.14.21-150500.55.68-default
h_run --check
# SLES 15 SP5 的修复包只在 LTSS 渠道：能给出 EVR 与频道，但不启用自动修复。
assert_rc 2
assert_has "SUSE Linux Enterprise Server 15 SP5"
assert_has "SUSE-SLE-Product-SLES-15-SP5-LTSS"
assert_has "未启用自动修复"
assert_lacks "openSUSE Leap"

h_scenario arch
h_os_release <<'EOF'
PRETTY_NAME="Arch Linux"
NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
EOF
printf 'https://geo.mirror.pkgbuild.com/$repo/os/$arch\n' >"${SCEN}/root/etc/pacman.conf"
h_install_pkg linux 6.12.10.arch1-1
h_set_kernel 6.12.10-arch1-1
h_run --check
assert_rc 4
assert_has "Arch Linux"
assert_has "linux 6.12.10.arch1-1"

h_scenario alpine
h_os_release <<'EOF'
NAME="Alpine Linux"
ID=alpine
VERSION_ID=3.20.3
PRETTY_NAME="Alpine Linux v3.20"
EOF
printf 'https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n' >"${SCEN}/root/etc/apk/repositories"
h_install_pkg linux-lts 6.6.44-r0
h_set_kernel 6.6.44-0-lts
h_run --check
assert_rc 4
assert_has "Alpine Linux v3.20"
assert_has "linux-lts 6.6.44-r0"
end_case

# ---------------------------------------------------------------------------
# 架构
# ---------------------------------------------------------------------------

begin_case "D9. x86_64 与 aarch64 识别"
h_scenario al2023-arm
h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2023"
NAME="Amazon Linux"
VERSION_ID="2023"
ID="amzn"
EOF
h_set_arch aarch64 aarch64
h_install_rpm kernel 6.1.185-228.391.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.185-228.391.amzn2023.aarch64
h_run --check
assert_rc 2
assert_has "CPU 架构：aarch64（arm64）"
assert_has "预计安装：kernel"
end_case

begin_case "D10. 不支持的架构拒绝修改"
h_scenario debian-arm64
h_os_release <<'EOF'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian
EOF
h_apt_sources bookworm
h_set_arch aarch64 aarch64
h_install_deb linux-image-6.1.0-49-arm64 6.1.174-1 6.1.0-49-arm64
h_set_kernel 6.1.0-49-arm64
h_run --check
assert_rc 1
assert_has "仅支持 amd64"
assert_has "判定结果：不支持"
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

# ---------------------------------------------------------------------------
# fail closed
# ---------------------------------------------------------------------------

begin_case "D11. 官方补丁未发布时绝不安装（含 --yes）"
h_scenario ubuntu-nofix-yes
h_os_release <<'EOF'
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
EOF
h_apt_sources noble
h_install_deb linux-image-6.8.0-45-generic 6.8.0-45.45 6.8.0-45-generic
h_set_kernel 6.8.0-45-generic
h_run --yes
assert_rc 6
assert_has "官方尚未发布可确认的修复包"
assert_no_file "${SCEN}/state/calls/apt_install"
assert_no_file "${SCEN}/state/calls/apt_update"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "D12. 官方状态自相矛盾时进入 UNKNOWN，绝不误报安全"
# v1.2.0 起不再联网抓取公告，改为人工核验的离线基线；「无法核验」的场景
# 由 SLES 15 SP7 代表：发布包列表与状态表互相矛盾，按 UNKNOWN fail closed。
h_scenario sles157-conflict
h_os_release <<'EOF'
PRETTY_NAME="SUSE Linux Enterprise Server 15 SP7"
NAME="SLES"
VERSION_ID="15.7"
ID="sles"
EOF
h_install_rpm kernel-default 6.4.0-150700.40.1
h_set_kernel 6.4.0-150700.40.1-default
h_run --check
assert_rc 4
assert_has "判定结果：无法确认"
assert_has "未启用（仅检测）"
assert_lacks "判定结果：已修复"
end_case

begin_case "D13. 缺少已核验修复版本时拒绝安装"
h_scenario al2023-unverified
h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2023"
NAME="Amazon Linux"
VERSION_ID="2023"
ID="amzn"
EOF
h_install_rpm kernel 7.0.0-10.20.amzn2023
h_set_kernel 7.0.0-10.20.amzn2023.x86_64
h_avail_rpm kernel 7.0.5-12.30.amzn2023
h_run --yes
assert_rc 4
assert_has "不在已核实的修复版本表中"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "D14. 容器环境判定为 UNKNOWN 且不安装"
h_scenario container
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
: >"${SCEN}/root/.dockerenv"
h_run --yes
assert_rc 4
assert_has "检测到容器环境"
assert_has "不允许自动修复"
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

# ---------------------------------------------------------------------------
# 只读入口
# ---------------------------------------------------------------------------

begin_case "D15. --list-distros 与 --report"
h_scenario readonly-tools
h_os_release <<'EOF'
PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
EOF
h_apt_sources noble
h_install_deb linux-image-6.8.0-45-generic 6.8.0-45.45 6.8.0-45-generic
h_set_kernel 6.8.0-45-generic

h_run --list-distros
assert_rc 0
assert_has "支持矩阵"
assert_has "Amazon Linux"
assert_has "仅检测"
assert_has "官方已修复"
assert_has "无法确认"

REPORT="${SCEN}/report.txt"
h_run --report "${REPORT}"
assert_rc 6
assert_file "${REPORT}"
if [[ -f ${REPORT} ]]; then
    if ! grep -Fq "PATCH_NOT_RELEASED" "${REPORT}"; then
        fail "报告应记录状态 PATCH_NOT_RELEASED"
    fi
    if ! grep -Fq "Ubuntu 24.04.1 LTS" "${REPORT}"; then
        fail "报告应记录发行版"
    fi
    if grep -qiE "password|token|private key|BEGIN OPENSSH" "${REPORT}"; then
        fail "报告不应包含敏感字段"
    fi
fi
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

begin_case "D16. 空 APT 索引（容器常见）不得中断检测"
h_scenario debian-empty-index
h_os_release <<'EOF'
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION_CODENAME=bookworm
ID=debian
EOF
h_apt_sources bookworm
# 容器镜像里 /var/lib/apt/lists 通常是空的，不能因此中断
rm -f "${SCEN}/root/var/lib/apt/lists/"*
h_install_deb linux-image-6.1.0-54-amd64 6.1.190-1 6.1.0-54-amd64
h_set_kernel 6.1.0-54-amd64
h_run --check
assert_rc 0
assert_has "判定结果：已修复"
assert_lacks "未找到可用的 APT 软件源配置"

# 加上容器标记后仍应正常输出，并给出容器判定
: >"${SCEN}/root/.dockerenv"
h_run --check
assert_rc 4
assert_has "容器环境"
end_case

finish_suite
