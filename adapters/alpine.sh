# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Alpine Linux
#
# secdb 中无该 CVE 记录，且不同内核 flavor（linux-lts / linux-virt / linux-edge）
# 不能视为同一包，故只检测。

ADAPTER_ID="alpine"
ADAPTER_DATA_DISTRO="alpine"
ADAPTER_NAME="Alpine Linux"
ADAPTER_FAMILY="alpine"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="linux-lts,linux-virt,linux-edge"
ADAPTER_ADVISORY_URL="https://security.alpinelinux.org/"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="按实际内核 flavor 分别核验，不可混为一谈。"
