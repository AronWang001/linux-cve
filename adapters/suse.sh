# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: openSUSE Leap / SUSE Linux Enterprise / openSUSE Tumbleweed
#
# 官方 CVE 页面拒绝自动访问（403），无法取得可核验状态；
# 且 SUSE 存在多内核并存与启动项选择问题，未完成适配，故只检测。

ADAPTER_ID="suse"
ADAPTER_DATA_DISTRO="suse"
ADAPTER_NAME="SUSE / openSUSE"
ADAPTER_FAMILY="suse"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel-default,kernel-default-base"
ADAPTER_ADVISORY_URL="https://www.suse.com/security/cve/CVE-2026-98432.html"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="需同时处理多内核并存与 bootloader 选择，本次未完成核验。"
