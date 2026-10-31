#!/usr/bin/env bash
#
# tests/test_amazon_linux.sh - Amazon Linux 2 / Amazon Linux 2023 适配
#
# 覆盖：AL2 的 4.14 / 5.4 / 5.10 / 5.15 与 AL2023 的 6.1 / 6.12 / 6.18
#       各自独立基线、完整安装流程、dnf 失败、initramfs 缺失、用户取消。

# shellcheck disable=SC2016
set -uo pipefail

# shellcheck source=tests/lib/harness.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/harness.sh"

h_init "Amazon Linux 适配测试"

al2_os() {
    h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2"
NAME="Amazon Linux"
VERSION_ID="2"
ID="amzn"
ID_LIKE="centos rhel fedora"
EOF
    h_yum_repo
}

al2023_os() {
    h_os_release <<'EOF'
PRETTY_NAME="Amazon Linux 2023"
NAME="Amazon Linux"
VERSION_ID="2023"
ID="amzn"
ID_LIKE="fedora"
EOF
    h_yum_repo
}

# ---------------------------------------------------------------------------
# 判定
# ---------------------------------------------------------------------------

begin_case "A1. AL2 默认 4.14 内核受影响"
h_scenario al2-vuln
al2_os
h_install_rpm kernel 4.14.350-279.365.amzn2
h_avail_rpm kernel 4.14.355-287.758.amzn2
h_set_kernel 4.14.350-279.365.amzn2.x86_64
h_run --check
assert_rc 2
assert_has "判定结果：存在漏洞"
assert_has "4.14.355-287.758.amzn2"
assert_has "ALAS2-2026-4065"
assert_has "预计安装：kernel"
end_case

begin_case "A2. AL2 已安装修复内核"
h_scenario al2-fixed
al2_os
h_install_rpm kernel 4.14.355-287.758.amzn2
h_avail_rpm kernel 4.14.355-287.758.amzn2
h_set_kernel 4.14.355-287.758.amzn2.x86_64
h_run --check
assert_rc 0
assert_has "判定结果：已修复"
assert_has "已达到官方修复版本 4.14.355-287.758.amzn2"
end_case

begin_case "A3. AL2 5.10 额外内核使用独立基线"
h_scenario al2-510
al2_os
h_install_rpm kernel 5.10.270-268.1090.amzn2
h_avail_rpm kernel 5.10.271-272.1121.amzn2
h_set_kernel 5.10.270-268.1090.amzn2.x86_64
h_run --check
assert_rc 2
assert_has "5.10.271-272.1121.amzn2"
assert_has "ALAS2KERNEL-5.10-2026-137"
assert_lacks "4.14.355-287.758.amzn2"
end_case

begin_case "A4. AL2 5.15 额外内核使用独立基线"
h_scenario al2-515
al2_os
h_install_rpm kernel 5.15.210-150.240.amzn2
h_avail_rpm kernel 5.15.222-158.256.amzn2
h_set_kernel 5.15.210-150.240.amzn2.x86_64
h_run --check
assert_rc 2
assert_has "5.15.222-158.256.amzn2"
assert_has "ALAS2KERNEL-5.15-2026-120"
assert_lacks "5.10.271-272.1121.amzn2"
end_case

begin_case "A5. AL2023 默认 6.1 内核已修复"
h_scenario al2023-61
al2023_os
h_install_rpm kernel 6.1.189-236.400.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.189-236.400.amzn2023.x86_64
h_run --check
assert_rc 0
assert_has "判定结果：已修复"
assert_has "ALAS2023-2026-3365"
end_case

begin_case "A6. AL2023 6.18 内核受影响"
h_scenario al2023-618
al2023_os
h_install_rpm kernel6.18 6.18.50-120.150.amzn2023
h_avail_rpm kernel6.18 6.18.56-125.164.amzn2023
h_set_kernel 6.18.50-120.150.amzn2023.x86_64
h_run --check
assert_rc 2
assert_has "6.18.56-125.164.amzn2023"
assert_has "ALAS2023-2026-3251"
end_case

# ---------------------------------------------------------------------------
# 完整修复流程
# ---------------------------------------------------------------------------

begin_case "A7. AL2023 6.12 完整安装流程（dnf）"
h_scenario al2023-fix
al2023_os
h_install_rpm kernel6.12 6.12.100-120.180.amzn2023
h_avail_rpm kernel6.12 6.12.113-138.209.amzn2023
h_set_kernel 6.12.100-120.180.amzn2023.x86_64
h_run_stdin "y
"
assert_rc 3
assert_has "执行 dnf install kernel6.12-6.12.113-138.209.amzn2023"
assert_has "已安装修复内核：6.12.113-138.209.amzn2023"
assert_has "initramfs 已生成"
assert_has "引导配置已包含新内核"
assert_has "新内核已经安装，但当前服务器仍在运行旧内核"
assert_has "是否需要重启"
assert_file "${SCEN}/state/calls/dnf_install"
assert_file "${SCEN}/state/calls/dnf_makecache"
assert_no_file "${SCEN}/state/calls/reboot"
assert_has "仓库来源"
assert_has "amazonlinux"
end_case

begin_case "A8. dnf 元数据刷新失败时停止"
h_scenario al2023-makecache-fail
al2023_os
h_install_rpm kernel 6.1.180-220.380.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.180-220.380.amzn2023.x86_64
h_flag dnf_makecache_fail
h_run --yes
assert_rc 1
assert_has "dnf makecache 执行失败"
assert_has "未安装任何内核"
assert_no_file "${SCEN}/state/calls/dnf_install"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "A9. dnf 安装失败时停止"
h_scenario al2023-install-fail
al2023_os
h_install_rpm kernel 6.1.180-220.380.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.180-220.380.amzn2023.x86_64
h_flag dnf_install_fail
h_run --yes
assert_rc 1
assert_has "内核安装失败（dnf install 返回非零）"
assert_has "当前仍运行 6.1.180-220.380.amzn2023"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "A10. initramfs 缺失时停止"
h_scenario al2023-initramfs
al2023_os
h_install_rpm kernel 6.1.180-220.380.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.180-220.380.amzn2023.x86_64
h_flag skip_initramfs
h_run --yes
assert_rc 1
assert_has "未检测到有效的 initramfs"
assert_lacks "修复结果"
assert_no_file "${SCEN}/state/calls/reboot"
end_case

begin_case "A11. 用户取消时不执行任何安装"
h_scenario al2023-cancel
al2023_os
h_install_rpm kernel 6.1.180-220.380.amzn2023
h_avail_rpm kernel 6.1.189-236.400.amzn2023
h_set_kernel 6.1.180-220.380.amzn2023.x86_64
h_run_stdin "n
"
assert_rc 5
assert_has "已取消，系统未做任何修改"
assert_no_file "${SCEN}/state/calls/dnf_makecache"
assert_no_file "${SCEN}/state/calls/dnf_install"
end_case

finish_suite
