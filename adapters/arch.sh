# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Arch Linux
#
# 滚动发行版，不能用固定版本号判断是否修复；安全追踪器中也没有该 CVE 条目。
# 因此只检测，禁止 pacman 安装。

ADAPTER_ID="arch"
ADAPTER_DATA_DISTRO="arch"
ADAPTER_NAME="Arch Linux"
ADAPTER_FAMILY="arch"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64"
ADAPTER_KERNEL_FLAVORS="linux,linux-lts,linux-zen,linux-hardened"
ADAPTER_ADVISORY_URL="https://security.archlinux.org/"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="滚动更新语义，禁止按固定版本号判定。"
