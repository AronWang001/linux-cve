# linux-cve v2.0.0

v2.0.0 是完整重写。v1.x 只回答一个问题——本机内核是否受 CVE-2026-98432 影响；
v2 用同一套判定模型回答「本机任意已安装包是否有已知漏洞」，情报来自六个官方源。

## 安装

```bash
curl -fsSL https://github.com/AronWang001/linux-cve-2026-98432-fix/releases/download/v2.0.0/install.sh | sudo sh
```

脚本按架构下载发布包、校验 SHA256、安装到 `/usr/local/bin`，不写配置、不改 `/etc`。

```bash
sudo linux-cve feed update --all   # 首次同步（Debian 约 18 秒）
sudo linux-cve scan                # 扫描
sudo linux-cve report              # Markdown 报告
```

自动修复默认关闭，需要显式开启：

```toml
# /etc/linux-cve/config.toml
[remediation]
allow_auto_fix = true
```

## 亮点

- **六个官方情报源**：Debian Tracker、Ubuntu OVAL、Alpine secdb、Arch Tracker、
  Red Hat CSAF、SUSE CSAF。实测入库 **481,139 条公告 / 2,062,599 条修复记录**。
- **两个源做了 GPG 验签**（Red Hat、SUSE）：每份文档都有分离签名，指纹硬编码，
  换钥必须改代码发版。
- **三状态维度**：`VulnState` × `RemediationState` × `RebootState`。
  「已修复」与「补丁已生效」是两件事，报告里分开写。
- **发行版原生版本比较**：dpkg 的 `~` 回移、rpm 的 epoch 优先级按原生语义实现，
  不用语义化版本近似。
- **覆盖不足返回退出码 9**：数据不全时不会报告「零漏洞」。
- **受控自动修复**：`plan` 预演 → 五道闸门 → 执行 → 强制复检 → 附带变更核对。

## 实测（Debian 13，2026-11-24）

| 项目 | 结果 |
| --- | --- |
| 六源入库 | 481,139 公告 / 2,062,599 修复 / SQLite 1.5GB / 原始发布物 6.1GB |
| Debian 全量 | 210,415 公告 / 222,161 修复 / 17.9s |
| Ubuntu OVAL noble | 270.8MB XML / 37,611 公告 / 48,617 修复 / 20.0s |
| Alpine secdb 3.20 | 8,299 公告 / 8,344 修复 / 3.1s |
| Arch Tracker | 8,035 公告 / 7,401 修复 / 303 不受影响 / 1.8s |
| Red Hat CSAF（2026） | 66,991 公告 / 810,817 修复 / 26,327 不受影响 / 失败 0 |
| SUSE CSAF（2026） | 149,788 公告 / 965,304 修复 / 失败 0 |
| 扫描 | 判定 124,470 条：受影响 10,230、已修复 100,985、未知 13,255；覆盖 `COVERED` |
| 自动修复 | `libcap2`、`libcap2-bin` 升级后复检通过，重扫受影响降为 10,228 |

## 支持矩阵（摘要）

| 发行版 | 检测 | 自动修复 |
| --- | --- | --- |
| Debian 13 | ✅ 实机验证 | ✅ 实机验证 |
| Debian 12 | 🟡 数据就绪 | ✅ 开放 |
| Debian 11 | 🟡（EOL） | ❌ |
| Ubuntu 22.04 / 24.04 | 🟡 | ❌（ESM 不在覆盖范围） |
| Alpine 3.19–3.21 | 🟡 | ❌（均已 EOL） |
| Arch | 🟡 | ❌（无固定版本语义） |
| RHEL 8 / 9 / 10 | 🟡 | ❌ |
| SLES 15.6 / 16.0、Leap 15.6 / 16.0 | 🟡 | ❌ |

`🟡` = 解析器与数据已用真实发布物验证，但尚未在该发行版实机运行。
未登记的 release 一律 `UNKNOWN`，不按「最新的那个」兜底。

## 从 v1.x 升级

**退出码变了**，脚本必须逐条核对：

| v1 | v1 含义 | v2 |
| --- | --- | --- |
| 0 | 内核已修复 | 0 无受影响项且覆盖完整 |
| 2 | 有补丁可用 | 3 `FINDINGS` |
| 3 | 待重启 | **3 现在是「发现受影响项」** |
| 4 | `UNKNOWN` | 9 `COVERAGE` |
| 6 / 7 / 8 | 未发布 / 仅 testing / 不受影响 | 单条结论，不再单独占退出码 |

完整对照与操作步骤见 [docs/migration-v1-v2.md](docs/migration-v1-v2.md)。

## 校验

```bash
sha256sum -c SHA256SUMS
```

发布包的 SHA256 记录在 `SHA256SUMS` 中，二进制由 GitHub Actions 在
`CGO_ENABLED=0` 下交叉编译（纯 Go，无 cgo 依赖）。
