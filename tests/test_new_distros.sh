#!/usr/bin/env bash
#
# tests/test_new_distros.sh - Oracle Linux UEK / SUSE / AlmaLinux testing 基线
#
# 与其他套件相同：假根目录 + PATH 注入的包管理器模拟，不接触真实系统。
# 重点验证：
#   * UEK 代际与 elNuek 后缀不混用，RHCK 不被误判；
#   * SUSE 按产品/SP/flavor 精确匹配，kernel-default-base 不共用短 EVR；
#   * SP7 官方状态冲突时 fail closed；
#   * AlmaLinux 仅 testing 仓库，任何参数都不能进入安装流程。
#
# 用法：bash tests/test_new_distros.sh [-v]

set -uo pipefail

# shellcheck source=tests/lib/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/harness.sh"

h_init "Oracle Linux / SUSE / AlmaLinux 基线测试"

rpm_os() {
    local id="$1" version="$2" pretty="$3"
    h_os_release <<EOF
ID="${id}"
VERSION_ID="${version}"
NAME="${pretty}"
PRETTY_NAME="${pretty}"
EOF
}

# ---------------------------------------------------------------------------
# Oracle Linux UEK
# ---------------------------------------------------------------------------

begin_case "OL8 UEKR7：命中 el8uek 基线且不启用自动修复"
h_scenario ol8-uek7
rpm_os ol "8.10" "Oracle Linux Server 8.10"
h_set_kernel "5.15.0-200.120.3.el8uek.x86_64"
h_install_rpm "kernel-uek" "5.15.0-200.120.3.el8uek"
h_run --check
assert_rc 2
assert_has "5.15.0-325.221.6.4.el8uek"
assert_has "ELSA-2026-500398"
assert_has "未启用自动修复"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "OL8 UEKR6：使用 el8uek 的 5.4 基线，不套用 UEKR7"
h_scenario ol8-uek6
rpm_os ol "8.10" "Oracle Linux Server 8.10"
h_set_kernel "5.4.17-2136.300.1.el8uek.x86_64"
h_install_rpm "kernel-uek" "5.4.17-2136.300.1.el8uek"
h_run --check
assert_rc 2
assert_has "5.4.17-2136.360.3.1.el8uek"
assert_lacks "5.15.0-325.221.6.4"
end_case

begin_case "OL9 UEKR8：命中 el9uek，不套用 el10uek"
h_scenario ol9-uek8
rpm_os ol "9.6" "Oracle Linux Server 9.6"
h_set_kernel "6.12.0-100.30.1.el9uek.x86_64"
h_install_rpm "kernel-uek" "6.12.0-100.30.1.el9uek"
h_run --check
assert_rc 2
assert_has "6.12.0-207.111.5.4.el9uek"
assert_lacks "el10uek"
end_case

begin_case "OL10 UEKR8：命中 el10uek"
h_scenario ol10-uek8
rpm_os ol "10.0" "Oracle Linux Server 10.0"
h_set_kernel "6.12.0-100.30.1.el10uek.x86_64"
h_install_rpm "kernel-uek" "6.12.0-100.30.1.el10uek"
h_run --check
assert_rc 2
assert_has "6.12.0-207.111.5.4.el10uek"
assert_has "ELSA-2026-500399"
end_case

begin_case "OL7 UEKR6：提示 ELS 频道，仍需订阅"
h_scenario ol7-uek6
rpm_os ol "7.9" "Oracle Linux Server 7.9"
h_set_kernel "5.4.17-2136.300.1.el7uek.x86_64"
h_install_rpm "kernel-uek" "5.4.17-2136.300.1.el7uek"
h_run --check
assert_rc 2
assert_has "5.4.17-2136.360.3.1.el7uek"
assert_has "ELS"
end_case

begin_case "OL9 RHCK：没有独立勘误，保持 UNKNOWN"
h_scenario ol9-rhck
rpm_os ol "9.6" "Oracle Linux Server 9.6"
h_set_kernel "5.14.0-427.13.1.el9_4.x86_64"
h_install_rpm "kernel" "5.14.0-427.13.1.el9_4"
h_run --check
assert_rc 4
assert_has "RHCK"
assert_lacks "5.15.0-325.221.6.4"
end_case

# ---------------------------------------------------------------------------
# SUSE / openSUSE
# ---------------------------------------------------------------------------

begin_case "openSUSE Leap 16.0：命中 kernel-default 基线"
h_scenario leap160
rpm_os opensuse-leap "16.0" "openSUSE Leap 16.0"
h_set_kernel "6.12.0-160000.20.1-default"
h_install_rpm "kernel-default" "6.12.0-160000.20.1"
h_run --check
assert_rc 2
assert_has "6.12.0-160000.40.1"
assert_has "openSUSE-Leap-16.0-1973"
assert_has "未启用自动修复"
end_case

begin_case "SLES 15 SP6-LTSS：命中 6.4 基线"
h_scenario sles156
rpm_os sles "15.6" "SUSE Linux Enterprise Server 15 SP6"
h_set_kernel "6.4.0-150600.20.1-default"
h_install_rpm "kernel-default" "6.4.0-150600.20.1"
h_run --check
assert_rc 2
assert_has "6.4.0-150600.23.143.1"
assert_has "SUSE-SLE-Product-SLES-15-SP6-LTSS-2026-4934"
end_case

begin_case "SLES 15 SP6：kernel-default-base 使用独立的完整 EVR"
h_scenario sles156-base
rpm_os sles "15.6" "SUSE Linux Enterprise Server 15 SP6"
h_set_kernel "6.4.0-150600.20.1-default"
h_install_rpm "kernel-default-base" "6.4.0-150600.20.1"
h_run --check
assert_rc 2
assert_has "6.4.0-150600.23.143.1.150600.12.66.3"
end_case

begin_case "SLES 15 SP7：官方状态冲突，判 UNKNOWN 而不是已修复"
h_scenario sles157
rpm_os sles "15.7" "SUSE Linux Enterprise Server 15 SP7"
h_set_kernel "6.4.0-150700.40.1-default"
h_install_rpm "kernel-default" "6.4.0-150700.40.1"
h_run --check
assert_rc 4
assert_has "In progress"
assert_has "无法确认"
assert_lacks "判定结果：存在漏洞"
end_case

begin_case "SLE Micro 6.2：有修复包但走 transactional-update，仅检测"
h_scenario micro62
rpm_os sl-micro "6.2" "SUSE Linux Micro 6.2"
h_set_kernel "6.12.0-160000.20.1-default"
h_install_rpm "kernel-default" "6.12.0-160000.20.1"
h_run --check
assert_rc 2
assert_has "6.12.0-160000.40.1"
assert_has "transactional"
assert_has "未启用自动修复"
end_case

# ---------------------------------------------------------------------------
# AlmaLinux：只有 testing 仓库补丁
# ---------------------------------------------------------------------------

begin_case "AlmaLinux 8：仅 testing，退出码 7"
h_scenario alma8
rpm_os almalinux "8.10" "AlmaLinux 8.10"
h_set_kernel "4.18.0-500.el8.x86_64"
h_install_rpm "kernel" "4.18.0-500.el8"
h_run --check
assert_rc 7
assert_has "4.18.0-553.180.2.el8_10"
assert_has "testing"
end_case

begin_case "AlmaLinux 9：--yes 也不能绕过 testing 限制"
h_scenario alma9
rpm_os almalinux "9.5" "AlmaLinux 9.5"
h_set_kernel "5.14.0-600.el9.x86_64"
h_install_rpm "kernel" "5.14.0-600.el9"
h_run --yes
assert_rc 7
assert_has "不会启用 testing 源"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

begin_case "AlmaLinux 10：命中 el10_2 测试基线"
h_scenario alma10
rpm_os almalinux "10.0" "AlmaLinux 10.0"
h_set_kernel "6.12.0-100.el10.x86_64"
h_install_rpm "kernel" "6.12.0-100.el10"
h_run --check
assert_rc 7
assert_has "6.12.0-211.69.2.el10_2"
end_case

finish_suite
