# 从 v1.x 迁移到 v2.0.0

v1.x 与 v2 不是同一个工具的两个版本，而是**两个工具**：v1 只回答「本机内核是否受
CVE-2026-98432 影响」，v2 回答「本机任意已安装包是否有已知漏洞」。
v2 覆盖了 v1 的全部能力，但接口、数据与退出码都不兼容。

## 1. 一句话结论

- **用法变了**：不再有 `fix.sh` / `install.sh` 一键脚本，改为 `linux-cve` 子命令。
- **流程变了**：必须先同步情报（`feed update`），再扫描（`scan`）；v1 是脚本内置基线。
- **退出码变了**：v1 的 3 是「待重启」，v2 的 3 是「发现受影响项」。**这是最容易踩的坑。**
- **数据不迁移**：v1 没有数据库，v2 的库是全新的，从零同步即可。

## 2. 操作步骤

```bash
# 1. 停掉 v1 的定时任务（如果有）
crontab -l | grep -i cve-2026-98432     # 确认
crontab -e                              # 删掉相关行

# 2. 装 v2
curl -fsSL https://github.com/AronWang001/linux-cve-2026-98432-fix/releases/download/v2.0.0/install.sh | sudo bash

# 3. 首次同步情报（Debian 约 18 秒，CSAF 源按需加 --since）
sudo linux-cve feed update --all

# 4. 扫描
sudo linux-cve scan

# 5. 需要自动修复时，先显式开启（默认关闭）
sudo tee /etc/linux-cve/config.toml >/dev/null <<'EOF'
[remediation]
allow_auto_fix = true
EOF
sudo linux-cve plan        # 预演
sudo linux-cve fix --yes   # 执行并复检
```

v1 的 `--check`（只读检测）对应 `linux-cve scan --dry-run`：
同样不写库、不改系统。

## 3. 退出码对照

**这一节是迁移的重点**：`0` 与 `1` 之外，其余含义几乎全变了。

| v1 退出码 | v1 含义 | v2 对应 |
| --- | --- | --- |
| 0 | `FIXED`（内核已修复） | 0 `OK`（无受影响项且覆盖完整） |
| 1 | 不支持的环境 / 运行错误 | 1 `ERROR`；不支持的环境改为 4 `UNSUPPORTED` |
| 2 | `VULNERABLE_PATCH_AVAILABLE` | 3 `FINDINGS`（**码值变了**） |
| 3 | `PENDING_REBOOT` | **3 现在是「发现受影响项」**，待重启看 JSON 的 `reboot_state` |
| 4 | `UNKNOWN` | 9 `COVERAGE`（数据不全）；单条未知看 `vuln_state` |
| 5 | 用户取消 | 无对应（v2 用 `--yes` 表达确认，取消即不执行） |
| 6 | `PATCH_NOT_RELEASED` | 单条结论 `NO_FIX`，不再单独占退出码 |
| 7 | `PATCH_TESTING_ONLY` | 无对应（v2 不区分 testing 仓库） |
| 8 | `NOT_AFFECTED` | 单条结论 `NOT_AFFECTED`，退出码为 0 |

已经写了 `case $? in ...` 的脚本，请按上表逐条核对，不要只改 0/1。

## 4. 能力对照

| 场景 | v1.x | v2.0.0 |
| --- | --- | --- |
| 目标 | 单条 CVE（CVE-2026-98432），仅内核 | 任意 CVE，任意已安装包 |
| 发行版 | Debian 12/13、Amazon Linux 2/2023 自动修复；其余仅检测 | Debian 12/13 自动修复；Ubuntu/Alpine/Arch/RHEL/SUSE 检测 |
| 情报来源 | 脚本内置基线 + 运行时查询 | 六个官方源，内容寻址存储 + 快照替换 |
| 判定维度 | 单一状态枚举 | `VulnState` × `RemediationState` × `RebootState` |
| 证据 | 公告 URL | 公告 + Artifact SHA256 + 原始定位 + 解析器版本 |
| 签名 | 无 | A 级源 GPG 分离签名，指纹硬编码 |
| 修复 | `fix.sh` 装内核包 | `plan` / `fix`，五道闸门 + 执行后复检 + 附带变更核对 |
| 报告 | `--report` 生成 TXT | `report` 生成 Markdown（`--out` 存文件） |
| 语言 | Bash | Go（纯 Go，无 cgo，可交叉编译） |

## 5. v1 里仍然成立的东西

- **不自动重启**：v2 同样不做，`reboot_state` 只报告。
- **不修改应用配置**：v2 只做包升级。
- **「未收录」不等于「不受影响」**：v1 用 `UNKNOWN`，v2 用 `UNKNOWN` + 退出码 9，
  语义一致且更严格。
- **发行版白名单**：v1 的白名单变成 v2 的支持矩阵（`linux-cve support`），
  未登记的 release 仍然一律不猜测。

## 6. 回退

v2 不改动系统里任何 v1 的痕迹（v1 是解压即用的脚本）。想回退：

```bash
# 移除 v2 的数据（可选，v2 不写 /etc 之外的配置）
sudo rm -rf /var/lib/linux-cve /etc/linux-cve
# 重新下载 v1.3.2
curl -fsSL https://github.com/AronWang001/linux-cve-2026-98432-fix/releases/download/v1.3.2/fix.sh -o fix.sh
```

已经用 v2 做过的包升级不会自动回退——那是包管理器的事，不是本工具的职责。
