# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Rocky Linux
#
# Errata 站点为前端应用，本次未取得可机读的该 CVE 勘误；
# 按 fail closed 处理：只检测，禁止自动修复。不得按 RHEL 结论等同。

ADAPTER_ID="rocky"
ADAPTER_DATA_DISTRO="rocky"
ADAPTER_NAME="Rocky Linux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel"
ADAPTER_ADVISORY_URL="https://errata.rockylinux.org/"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="独立身份识别，不继承 RHEL 的修复结论。"
