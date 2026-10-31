# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Fedora Linux
#
# 主线修复位于 7.3-rc7；Fedora 当前 kernel 7.2.14 是否回移无法确认，
# Bodhi 也未返回针对 kernel 的该 CVE 更新，故只检测。

ADAPTER_ID="fedora"
ADAPTER_DATA_DISTRO="fedora"
ADAPTER_NAME="Fedora Linux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel"
ADAPTER_ADVISORY_URL="https://bodhi.fedoraproject.org/updates/?cves=CVE-2026-98432"
ADAPTER_UPDATE_PROCEDURE="未完成自动修复适配，仅检测"
ADAPTER_NOTES="需按受支持的 Fedora 版本分别核验，本次未完成。"
