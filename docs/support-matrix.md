# 支持矩阵（v2.0）

三类能力分别声明、分别验收，**不得合并为一个「支持」**：

1. **检测**：能否采集资产并用官方数据判定 `VulnState`。
2. **修复版本查询**：能否给出该 release 的官方固定版本与公告链接。
3. **自动修复**：`plan`/`fix` 是否开放，以及是否已通过真实环境验收。

状态取值：`✅ 已验证` / `🟡 待验证`（代码就绪，缺实机验证）/ `⚠️ 受限`（部分场景）/ `❌ 不开放`。

| 发行版 | Release | 检测 | 修复版本查询 | 自动修复 | 情报源 | 备注 |
|--------|---------|------|--------------|----------|--------|------|
| Debian | 12 bookworm | 🟡 | 🟡 | 🟡 待实机 | Debian Tracker JSON | 首期目标 |
| Debian | 13 trixie | 🟡 | 🟡 | 🟡 待实机 | Debian Tracker JSON | 首期目标 |
| Ubuntu | 22.04 jammy | 🟡 | 🟡 | 🟡 待实机 | Ubuntu OVAL + USN | 首期目标 |
| Ubuntu | 24.04 noble | 🟡 | 🟡 | 🟡 待实机 | Ubuntu OVAL + USN | 首期目标 |
| Amazon Linux | 2023 | 🟡 | 🟡 | 🟡 待实机 | AL2023 updateinfo | 首期目标 |
| Amazon Linux | 2 | 🟡 Legacy | ⚠️ 未验证 | ❌ 不开放 | AL2 updateinfo（**未验证**） | EOL 2026-06-30，见 §2 |
| RHEL | 8 / 9 | 🟡 | 🟡 | ❌ 后续 | Red Hat OVAL + Security API + CSAF-VEX | 检测与建议先行 |
| Rocky Linux | 8 / 9 | 🟡 | 🟡 | ❌ 后续 | 继承 RHEL + 自身 updateinfo | 不直接等同 RHEL |
| AlmaLinux | 8 / 9 | 🟡 | 🟡 | ❌ 后续 | 继承 RHEL + 自身 updateinfo | 不直接等同 RHEL |
| Oracle Linux | 8 / 9 | 🟡 | 🟡 | ❌ 后续 | Oracle OVAL + ELSA | UEK 与 RHCK 分开 |
| SUSE / openSUSE | 15.x / Leap | 🟡 | 🟡 | ❌ 后续 | SUSE CSAF（唯一 A 级签名源） | 产品树映射复杂 |
| Alpine | 3.19–3.21 | 🟡 | ⚠️ 部分 | ❌ 后续 | Alpine secdb | 未收录 ≠ 不受影响 |
| Fedora | 现行 | 🟡 | 🟡 | ❌ 后续 | Bodhi + updateinfo | 生命周期短 |
| Arch | 滚动 | 🟡 | ⚠️ 仅当前 | ❌ **不开放** | Arch 追踪器 | 见 §3 |
| CloudLinux | 8 / 9 | ⚠️ | ⚠️ | ❌ 不开放 | 自有公告 | 数据源稳定性待评估 |

---

## 1. 首期自动修复的准入条件

发行版同时满足以下全部条件才开放 `fix`：

1. 检测与修复版本查询均通过实机验证（非模拟）。
2. 包管理器具备可靠的事务预演（`apt-get --dry-run`、`dnf --assumeno`）。
3. 变更集闸门可在该管理器上解析并通过。
4. 修复后复检确认 `VulnState == FIXED`。
5. 生命周期为 `active`。

未通过的项目在 `linux-cve support` 输出中显式为 `no`，`plan` 直接返回 `UNSUPPORTED`。

---

## 2. Amazon Linux 2（Legacy）`[修订 6]`

- AL2 标准支持已于 **2026-06-30** 结束。
- 定位：**Legacy 兼容**，只做检测与报告，`lifecycle_state='legacy'`。
- `plan` / `fix` 在 AL2 上一律 `UNSUPPORTED`（退出码 4），报告附「系统已过支持期，建议规划迁移」提示。
- 检测能力保留的理由：存量 AL2 主机多，能看清风险优于看不到；但不得暗示持续打补丁可长期维持。
- **AL2 的 updateinfo 数据源尚未完成动态解析验证**（阶段 0 仅确认 `mirror.list` 可访问），因此 AL2 的修复版本查询标记 `unverified`，`RemediationState` 最高只能到 `UNKNOWN`。这与「关闭自动修复」是两条独立约束。

## 3. Arch Linux `[修订 5]`

- `pacman -Sp` 只输出下载 URL，不含依赖闭包、事务顺序、删除/替换信息，**不能作为变更集预演依据**。
- 滚动发行版仓库不留旧版本，无法保证可复现的固定版本。
- 结论：Arch 仅提供检测 + 人工修复建议（受影响包清单 + `pacman -Syu` 提示）。`plan`/`fix` 返回 `UNSUPPORTED`。

## 4. 包管理器能力

| 管理器 | 固定版本安装 | 事务预演 | 锁检测 | 自动修复 |
|--------|--------------|----------|--------|----------|
| apt/dpkg | `pkg=version` | `--dry-run` 解析 Inst/Conf/Remv | `lock-frontend` | ✅ 首期 |
| dnf/rpm | `pkg-epoch:ver-rel` | `--assumeno` 事务表 | `/var/lib/rpm/.rpm.lock` | ✅ 首期（AL2023） |
| yum/rpm | 同上 | 较弱 | 同上 | ❌ |
| zypper | `pkg=version` | `--dry-run` | zypp 锁 | ❌ 后续 |
| apk | `pkg=version` | `--simulate` | `/lib/apk/db/lock` | ❌ 后续 |
| pacman | 无法固定旧版本 | 无可靠预演 | `db.lck` | ❌ 不开放 |
