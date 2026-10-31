# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Red Hat Enterprise Linux 8 / 9 / 10
#
# Red Hat 安全数据 API 显示 kernel 与 kernel-rt 均为 Affected，
# 且 affected_release 为空 —— 官方尚未发布修复包，因此只检测。

ADAPTER_ID="rhel"
ADAPTER_DATA_DISTRO="rhel"
ADAPTER_NAME="Red Hat Enterprise Linux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_RELEASES="8,9,10"
ADAPTER_SUPPORTED_TEXT="仅支持 RHEL 8 / 9 / 10"
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel,kernel-rt"
ADAPTER_ADVISORY_URL="https://access.redhat.com/security/cve/cve-2026-98432"
ADAPTER_UPDATE_PROCEDURE="官方尚未发布可确认修复包，仅检测"
ADAPTER_NOTES="不与其他 RHEL 衍生版共用基线。"
