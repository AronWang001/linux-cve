#!/usr/bin/env bash
#
# tests/test_cloudlinux.sh - CloudLinux 7 / 7h / 8 / 8 LTS / 9 / 9 LTS / 10
#
# 与其他套件相同：假根目录 + PATH 注入的包管理器模拟，不接触真实系统。
# 重点验证：
#   * CL7 的 3.10 内核判为不受影响，且不与 CL7h 的 4.18 混用；
#   * 标准内核 kernel 与 LTS 内核 kernel-lts 是两条流，EVR 不互相套用；
#   * staged rollout 未到达时只提示、不安装；
#   * CL9/10 标准内核只在 AlmaLinux testing，任何参数都不能进入安装流程；
#   * CloudLinux 身份必须有 /etc/cloudlinux-release 或 cloudlinux-release 包交叉确认；
#   * CloudLinux for Ubuntu 22.04 不套用 RPM 判定。
#
# 用法：bash tests/test_cloudlinux.sh [-v]

set -uo pipefail

# shellcheck source=tests/lib/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/harness.sh"

h_init "CloudLinux 基线测试"

cl_os() {
    local ver="$1"
    h_os_release <<EOF
ID="cloudlinux"
VERSION_ID="${ver}"
NAME="CloudLinux"
PRETTY_NAME="CloudLinux ${ver}"
ID_LIKE="rhel fedora centos"
EOF
}

cl_release_file() {
    printf 'CloudLinux release %s (Test Build)\n' "$1" >"${SCEN}/root/etc/cloudlinux-release"
}

cl_release_pkg() {
    printf 'cloudlinux-release\t%s\t%s\n' "$1" "$2" >>"${SCEN}/state/installed.tsv"
}

# ---------------------------------------------------------------------------
# 7 / 7h
# ---------------------------------------------------------------------------

begin_case "CL7 标准内核 3.10：官方声明不受影响，退出码 8"
h_scenario cl7-std
cl_os "7.9"
cl_release_file "7.9"
cl_release_pkg "7.9" "2.12.el7"
h_set_kernel "3.10.0-1160.119.1.lve1.5.41.el7.x86_64"
h_install_rpm "kernel" "3.10.0-1160.119.1.lve1.5.41.el7"
h_run --check
assert_rc 8
assert_has "CloudLinux 7.9"
assert_has "判定结果：不受影响"
assert_has "不受"
assert_lacks "判定结果：存在漏洞"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "CL7h（4.18）：命中 4.18.0-553.180.1.lve.1，仅检测"
h_scenario cl7h
cl_os "7.9"
cl_release_file "7.9"
cl_release_pkg "7.9" "2.12.el7"
h_set_kernel "4.18.0-553.180.0.lve.1.el7.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el7"
h_avail_rpm "kernel" "4.18.0-553.180.1.lve.1.el7"
h_run --check
assert_rc 2
assert_has "CL7h"
assert_has "4.18.0-553.180.1.lve.1"
assert_has "未启用自动修复"
assert_lacks "判定结果：已修复"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

# ---------------------------------------------------------------------------
# 8 / 8 LTS
# ---------------------------------------------------------------------------

begin_case "CL8：rollout 未到达本实例时提示且不安装"
h_scenario cl8-pending
cl_os "8.10"
cl_release_file "8.10"
cl_release_pkg "8.10" "8.el8"
h_set_kernel "4.18.0-553.180.0.lve.1.el8.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_avail_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_run --check
assert_rc 2
assert_has "尚未进入 staged rollout"
assert_has "尚未推送"
assert_has "未启用自动修复"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "CL8：运行内核已达修复版本时判 FIXED"
h_scenario cl8-fixed
cl_os "8.10"
cl_release_file "8.10"
cl_release_pkg "8.10" "8.el8"
h_set_kernel "4.18.0-553.180.1.lve.1.el8.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.1.lve.1.el8"
h_run --check
assert_rc 0
assert_has "判定结果：已修复"
end_case

begin_case "CL8 LTS：kernel-lts 使用 els19 的独立 EVR"
h_scenario cl8-lts
cl_os "8.10"
cl_release_file "8.10"
cl_release_pkg "8.10" "8.el8"
h_set_kernel "5.14.0-284.1100.el8.tuxcare.11.els18.x86_64"
h_install_rpm "kernel-lts" "5.14.0-284.1100.el8.tuxcare.11.els18"
h_avail_rpm "kernel-lts" "5.14.0-284.1101.el8.tuxcare.11.els19"
h_run --check
assert_rc 2
assert_has "kernel-lts"
assert_has "5.14.0-284.1101.el8.tuxcare.11.els19"
assert_has "LTS"
assert_lacks "4.18.0-553"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

# ---------------------------------------------------------------------------
# 9 / 9 LTS / 10
# ---------------------------------------------------------------------------

begin_case "CL9 LTS：与 CL9 标准内核同为 5.14，靠包名区分且不混用"
h_scenario cl9-lts
cl_os "9.6"
cl_release_file "9.6"
cl_release_pkg "9.6" "2.el9"
h_set_kernel "5.14.0-284.1100.el9.tuxcare.11.els18.x86_64"
h_install_rpm "kernel-lts" "5.14.0-284.1100.el9.tuxcare.11.els18"
h_avail_rpm "kernel-lts" "5.14.0-284.1101.el9.tuxcare.11.els19"
h_run --check
assert_rc 2
assert_has "5.14.0-284.1101.el9.tuxcare.11.els19"
assert_has "LTS"
assert_lacks "5.14.0-687"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "CL9 标准内核：只在 AlmaLinux testing，退出码 7"
h_scenario cl9-std
cl_os "9.6"
cl_release_file "9.6"
cl_release_pkg "9.6" "2.el9"
h_set_kernel "5.14.0-687.61.1.el9_8.x86_64"
h_install_rpm "kernel" "5.14.0-687.61.1.el9_8"
h_run --check
assert_rc 7
assert_has "判定结果：仅测试仓库有补丁"
assert_has "almalinux-testing"
assert_lacks "判定结果：已修复"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "CL10 标准内核：只在 AlmaLinux testing，退出码 7"
h_scenario cl10-std
cl_os "10.1"
cl_release_file "10.1"
cl_release_pkg "10.1" "1.el10"
h_set_kernel "6.12.0-211.69.1.el10_2.x86_64"
h_install_rpm "kernel" "6.12.0-211.69.1.el10_2"
h_run --check
assert_rc 7
assert_has "判定结果：仅测试仓库有补丁"
assert_has "6.12.0-211.69.2.el10_2"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

# ---------------------------------------------------------------------------
# 身份交叉校验
# ---------------------------------------------------------------------------

begin_case "CloudLinux for Ubuntu 22.04（无 RPM）：不套用 RPM 判定"
h_scenario cl-ubuntu
cl_os "22.04"
h_hide_cmd rpm
h_run --check
h_show_cmd rpm
assert_rc 4
assert_has "判定结果：无法确认"
assert_has "Canonical"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "缺少 /etc/cloudlinux-release 与 cloudlinux-release 包：判 UNKNOWN"
h_scenario cl-no-identity
cl_os "8.10"
h_set_kernel "4.18.0-553.180.0.lve.1.el8.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_run --check
assert_rc 4
assert_has "无法交叉确认"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "os-release 与 cloudlinux-release 主版本冲突：判 UNKNOWN"
h_scenario cl-conflict
cl_os "8.10"
cl_release_file "7.9"
cl_release_pkg "8.10" "8.el8"
h_set_kernel "4.18.0-553.180.0.lve.1.el8.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_run --check
assert_rc 4
assert_has "不一致"
assert_lacks "判定结果：已修复"
end_case

# ---------------------------------------------------------------------------
# 参数与安全边界
# ---------------------------------------------------------------------------

begin_case "--allow-staged-rollout：给出风险说明但不启用 bypass 仓库"
h_scenario cl8-rollout-flag
cl_os "8.10"
cl_release_file "8.10"
cl_release_pkg "8.10" "8.el8"
h_set_kernel "4.18.0-553.180.0.lve.1.el8.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_avail_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_run --check --allow-staged-rollout
assert_rc 2
assert_has "cloudlinux-rollout-3-bypass"
assert_has "不会执行 yum"
assert_lacks "--enablerepo"
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/root/etc/yum.repos.d/cloudlinux-rollout.repo"
end_case

begin_case "--allow-staged-rollout + --yes 且 rollout 未到达：风险提示后仍不安装"
h_scenario cl8-rollout-yes
cl_os "8.10"
cl_release_file "8.10"
cl_release_pkg "8.10" "8.el8"
h_set_kernel "4.18.0-553.180.0.lve.1.el8.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_avail_rpm "kernel" "4.18.0-553.180.0.lve.1.el8"
h_run --yes --allow-staged-rollout
assert_rc 2
assert_has "尚未进入 staged rollout"
assert_has "cloudlinux-rollout-3-bypass"
assert_has "不会执行 yum"
assert_lacks "确认安装"
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/dnf_update"
assert_no_file "${SCEN}/state/calls/dnf_makecache"
assert_no_file "${SCEN}/state/calls/reboot"
assert_no_file "${SCEN}/root/etc/yum.repos.d/cloudlinux-rollout.repo"
end_case

begin_case "--allow-staged-rollout 在非 CloudLinux 上被忽略"
h_scenario non-cl-flag
h_os_release <<'EOF'
ID="ubuntu"
VERSION_ID="22.04"
NAME="Ubuntu"
PRETTY_NAME="Ubuntu 22.04.4 LTS"
EOF
h_apt_sources jammy
h_set_kernel "5.15.0-100-generic"
h_install_deb "linux-image-5.15.0-100-generic" "5.15.0-100.100" "5.15.0-100-generic"
h_run --check --allow-staged-rollout
assert_rc 6
assert_has "仅适用于 CloudLinux"
assert_no_file "${SCEN}/state/calls/apt_install"
end_case

begin_case "CL9 testing 状态下 --yes 不能绕过安全限制"
h_scenario cl9-yes
cl_os "9.6"
cl_release_file "9.6"
cl_release_pkg "9.6" "2.el9"
h_set_kernel "5.14.0-687.61.1.el9_8.x86_64"
h_install_rpm "kernel" "5.14.0-687.61.1.el9_8"
h_run --yes
assert_rc 7
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/dnf_update"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "CL7h：--check 全程只读，不刷新索引、不安装、不重启"
h_scenario cl7h-readonly
cl_os "7.9"
cl_release_file "7.9"
cl_release_pkg "7.9" "2.12.el7"
h_set_kernel "4.18.0-553.180.0.lve.1.el7.x86_64"
h_install_rpm "kernel" "4.18.0-553.180.0.lve.1.el7"
h_avail_rpm "kernel" "4.18.0-553.180.1.lve.1.el7"
h_run --check
assert_rc 2
assert_no_file "${SCEN}/state/calls/dnf_makecache"
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "--list-distros 列出 CloudLinux 且标注仅检测"
h_scenario cl-list
h_run --list-distros
assert_rc 0
assert_has "CloudLinux"
assert_has "仅检测"
assert_has "官方已修复"
end_case

finish_suite
