# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Ubuntu 20.04 / 22.04 / 24.04
#
# 官方 CVE 页面当前为 "work in progress"，没有可确认的修复包。
# 因此本 adapter 明确关闭自动修复：只识别、只检测、只展示官方状态。

ADAPTER_ID="ubuntu"
ADAPTER_DATA_DISTRO="ubuntu"
ADAPTER_NAME="Ubuntu"
ADAPTER_FAMILY="debian"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_RELEASES="20.04,22.04,24.04"
ADAPTER_SUPPORTED_TEXT="仅支持 Ubuntu 20.04 / 22.04 / 24.04"
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="generic,aws,gcp,azure,kvm,oracle"
ADAPTER_ADVISORY_URL="https://ubuntu.com/security/CVE-2026-98432"
ADAPTER_UPDATE_PROCEDURE="官方尚未发布可确认修复包，仅检测"
ADAPTER_NOTES="独立 Ubuntu 基线，不复用 Debian 的回移版本。"
