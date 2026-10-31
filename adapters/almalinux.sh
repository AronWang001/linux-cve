# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: AlmaLinux
#
# errata.full.json 中无该 CVE 记录，但「缺少勘误」不等于「确认未修复」，
# 因此状态为 UNKNOWN，只检测。

ADAPTER_ID="almalinux"
ADAPTER_DATA_DISTRO="almalinux"
ADAPTER_NAME="AlmaLinux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel"
ADAPTER_ADVISORY_URL="https://errata.almalinux.org/"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="不把 AlmaLinux 自动等同于 RHEL。"
