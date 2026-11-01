# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: AlmaLinux
#
# 2026-10-30 官方公告：修复内核已进入 testing 仓库，等待社区验证后才会
# 进入 production 仓库。测试仓库版本：
#   AlmaLinux 8  kernel-4.18.0-553.180.2.el8_10
#   AlmaLinux 9  kernel-5.14.0-687.61.2.el9_8
#   AlmaLinux 10 kernel-6.12.0-211.69.2.el10_2
#
# 测试仓库有包不等于生产仓库已发布，本适配器不会启用 testing 源，
# 也不会安装测试内核，状态统一为 PATCH_TESTING_ONLY。

ADAPTER_ID="almalinux"
ADAPTER_DATA_DISTRO="almalinux"
ADAPTER_NAME="AlmaLinux"
ADAPTER_FAMILY="rpm"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_STRICT_BASELINE=1
ADAPTER_RELEASES="8,9,10"
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel"
ADAPTER_ADVISORY_URL="https://almalinux.org/blog/2026-10-30-cve-2026-98432/"
ADAPTER_UPDATE_PROCEDURE="等待官方 production 仓库发布后手工升级"
ADAPTER_NOTES="官方仅提供 testing 仓库补丁，禁止启用 testing 源或自动安装。"
