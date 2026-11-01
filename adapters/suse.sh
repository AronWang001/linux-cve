# shellcheck shell=bash
# shellcheck disable=SC2034
#
# 本文件由 fix.sh 在识别发行版时 source，是片段而不是独立脚本：
#   * 没有 shebang，因此用 shell 指令声明解释器；
#   * ADAPTER_* 变量由 lib/*.sh 与 fix.sh 读取，单文件分析看不到使用点，
#     故在此关闭「变量未使用」误报（SC2034）。
#
# adapter: openSUSE Leap / SUSE Linux Enterprise / SLE Micro
#
# 2026-10-29 官方发布 9 份 SUSE-SU 公告，逐产品列出修复包：
#   openSUSE Leap 16.0 / SLES 16.0      kernel-default >= 6.12.0-160000.40.1
#   SLES 15 SP4-LTSS                   kernel-default >= 5.14.21-150400.24.246.1
#   SLES 15 SP5-LTSS                   kernel-default >= 5.14.21-150500.55.195.1
#   SLES 15 SP6-LTSS                   kernel-default >= 6.4.0-150600.23.143.1
#   SLE Micro 6.2                      kernel-default >= 6.12.0-160000.40.1
#
# 注意：
#   * kernel-default-base 的 EVR 比 kernel-default 更长，不能共用同一基线；
#   * LTSS 需要对应订阅与仓库资格；
#   * SLES 15 SP7 的发布包列表与状态表互相矛盾（状态仍为 In progress），按 UNKNOWN；
#   * SLE Micro 使用 transactional-update，不能套用普通 zypper 流程。
#
# 本版本只做精确检测与基线展示，不启用自动修复。

ADAPTER_ID="suse"
ADAPTER_DATA_DISTRO="suse"
ADAPTER_NAME="SUSE / openSUSE"
ADAPTER_FAMILY="suse"
ADAPTER_DETECT_SUPPORTED=1
ADAPTER_AUTOFIX_DEFAULT=0
ADAPTER_STRICT_BASELINE=1
ADAPTER_RELEASES="15.4,15.5,15.6,15.7,16.0,6.2"
ADAPTER_SUPPORTED_TEXT="仅覆盖 openSUSE Leap 16.0、SLES 15 SP4-SP7、SLES 16.0、SLES for SAP 16.0、SLE Micro 6.2"
ADAPTER_ARCHES="amd64,arm64"
ADAPTER_KERNEL_FLAVORS="kernel-default,kernel-default-base,kernel-azure,kernel-rt,kernel-64kb,kernel-kvmsmall"
ADAPTER_ADVISORY_URL="https://www.suse.com/security/cve/CVE-2026-98432.html"
ADAPTER_UPDATE_PROCEDURE="zypper patch（未启用自动修复）"
ADAPTER_NOTES="flavor 与 LTSS 频道分别核验；SP7 官方状态冲突，按 UNKNOWN；Micro 走事务式更新。"
