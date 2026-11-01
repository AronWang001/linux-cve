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
#
# 2026-10-16 官方发布三个 UEK 勘误（ELSA-2026-500397/500398/500399）：
#   UEKR6 5.4.17-2136.360.3.1（el7uek / el8uek）
#   UEKR7 5.15.0-325.221.6.4（el8uek / el9uek）
#   UEKR8 6.12.0-207.111.5.4（el9uek / el10uek）
# RHCK 没有独立勘误，不能套用 UEK 的修复版本。
#
# 本版本只做精确检测与基线展示：未在真实 Oracle Linux 虚拟机上完成
# 安装、引导与重启验证，因此不启用自动修复。

ADAPTER_ID="oracle"
ADAPTER_DATA_DISTRO="oracle"
ADAPTER_NAME="Oracle Linux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_STRICT_BASELINE=1
ADAPTER_RELEASES="7,8,9,10"
ADAPTER_SUPPORTED_TEXT="仅覆盖 Oracle Linux 7/8/9/10；UEK 按代际与发行版后缀分别建基线，RHCK 仅检测"
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel-uek,kernel"
ADAPTER_ADVISORY_URL="https://linux.oracle.com/cve/CVE-2026-98432.html"
ADAPTER_UPDATE_PROCEDURE="dnf install kernel-uek-<EVR>（未启用自动修复）"
ADAPTER_NOTES="UEKR6/R7/R8 分别建基线；OL7 仅 x86_64 UEKR6 ELS 频道；RHCK 无独立勘误，保持 UNKNOWN。"
