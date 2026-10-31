# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Debian 12/13
#
# 本文件只声明身份与能力，不做任何系统操作。
# 版本基线与自动修复许可在 data/cve-2026-98432.yml 中逐条记录。

ADAPTER_ID="debian"
ADAPTER_DATA_DISTRO="debian"
ADAPTER_NAME="Debian GNU/Linux"
ADAPTER_FAMILY="debian"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=1
ADAPTER_RELEASES="12,13"
ADAPTER_SUPPORTED_TEXT="仅支持 Debian 12 (bookworm) 与 Debian 13 (trixie)"
ADAPTER_ARCHES="amd64"
ADAPTER_KERNEL_FLAVORS="amd64,cloud-amd64,rt-amd64"
ADAPTER_ADVISORY_URL="https://security-tracker.debian.org/tracker/CVE-2026-98432"
ADAPTER_UPDATE_PROCEDURE="apt-get update && apt-get install linux-image-<flavor>"
ADAPTER_NOTES="仅支持 Debian 12 (bookworm) 与 Debian 13 (trixie) 的 amd64 内核。"
