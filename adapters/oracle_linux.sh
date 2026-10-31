# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Oracle Linux
#
# UEK 与 RHCK 是完全不同的包与基线，必须分开判断：
#   * 运行内核 release 含 uek -> kernel-uek（UEK）
#   * 否则                  -> kernel（RHCK）
# 本次未取得两者任一修复 EVR，故只检测。

ADAPTER_ID="oracle"
ADAPTER_DATA_DISTRO="oracle"
ADAPTER_NAME="Oracle Linux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel-uek,kernel"
ADAPTER_ADVISORY_URL="https://linux.oracle.com/security/"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="UEK 与 RHCK 分别核验，禁止混用基线。"
