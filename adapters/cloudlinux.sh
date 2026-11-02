# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: CloudLinux（7 / 7h / 8 / 8 LTS / 9 / 9 LTS / 10）
#
# 2026-10-30 官方公告：https://blog.cloudlinux.com/cve-2026-98432-linux-kernel-ipv4-tcp-flaw-status-for-cloudlinux
#   CL7（3.10）        不受影响：漏洞代码从 4.4 才引入
#   CL7h / CL8（4.18） 4.18.0-553.180.1.lve.1，staged rollout
#   CL8/9 LTS（ELS）   kernel-lts-5.14.0-284.1101.el{8,9}.tuxcare.11.els19，staged rollout
#   CL9 / CL10         5.14.0-687.61.2.el9_8 / 6.12.0-211.69.2.el10_2，仅在 AlmaLinux testing
#   CL for Ubuntu 22.04 内核来自 Canonical，官方修复仍在进行中
#
# 关键约束：
#   * 标准内核 kernel 与 LTS 内核 kernel-lts 是两条完全不同的流，EVR 不能混用；
#   * cloudlinux-rollout-3-bypass 是官方灰度旁路，本工具不默认启用、也不写入 repo 文件；
#   * ELS 需要 TuxCare 订阅与仓库资格，无授权时只提示，不添加源、不下载 RPM；
#   * 本版本未在真实 CloudLinux 上完成安装/引导/重启验证，因此全部只做检测。

ADAPTER_ID="cloudlinux"
ADAPTER_DATA_DISTRO="cloudlinux"
ADAPTER_NAME="CloudLinux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_STRICT_BASELINE=1
ADAPTER_RELEASES="7,8,9,10"
ADAPTER_SUPPORTED_TEXT="仅覆盖 CloudLinux 7（标准/7h）、8（标准/LTS）、9（标准/LTS）、10（标准）；CloudLinux for Ubuntu 22.04 不做 RPM 判定"
ADAPTER_ARCHES="amd64"
ADAPTER_KERNEL_FLAVORS="kernel,kernel-lts"
ADAPTER_ADVISORY_URL="https://blog.cloudlinux.com/cve-2026-98432-linux-kernel-ipv4-tcp-flaw-status-for-cloudlinux"
ADAPTER_UPDATE_PROCEDURE="yum update cloudlinux-release，再按官方渠道升级内核（staged rollout）"
ADAPTER_NOTES="CL7 3.10 不受影响；标准内核与 kernel-lts 分开建基线；rollout bypass 不默认启用；ELS 需订阅资格。"
