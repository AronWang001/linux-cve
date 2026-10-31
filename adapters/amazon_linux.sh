# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: Amazon Linux 2 / Amazon Linux 2023
#
# AL2 与 AL2023 必须独立适配：两者的包名、EVR 与仓库渠道完全不同。
# 本 adapter 同时覆盖 AL2（release=2）与 AL2023（release=2023），
# 具体基线由 data/cve-2026-98432.yml 按 release + 内核分支选择。

ADAPTER_ID="amazon"
ADAPTER_DATA_DISTRO="amazon"
ADAPTER_NAME="Amazon Linux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=1
ADAPTER_RELEASES="2,2023"
ADAPTER_SUPPORTED_TEXT="仅支持 Amazon Linux 2 与 Amazon Linux 2023"
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel,kernel6.12,kernel6.18"
ADAPTER_ADVISORY_URL="https://alas.aws.amazon.com/"
ADAPTER_UPDATE_PROCEDURE="dnf install <package>-<EVR>（AL2 使用 yum）"
ADAPTER_NOTES="仅 AL2 与 AL2023；AL2 的 4.14/5.4/5.10/5.15 与 AL2023 的 kernel/kernel6.12/kernel6.18 各自独立基线。"
