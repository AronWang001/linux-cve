# Linux CVE Tool v2.0.0

**简体中文** | [English](README.en.md)

对照六个官方漏洞情报源，检查一台 Linux 服务器上已安装的软件包当前是否存在已知漏洞，
给出「受影响 / 已修复 / 不受影响 / 未知」的分项结论，并在许可证可覆盖的发行版上
执行受控的自动修复与复检。

v2.0.0 是完整重写：v1.x 只回答「本机内核是否受 CVE-2026-98432 影响」，
v2 用同一套判定模型覆盖任意 CVE、任意已安装包。

**这个工具不做什么**（比「做什么」更重要）：

- 不把「情报源没收录」当成「不受影响」。没有证据就是 `UNKNOWN`，退出码会体现出来。
- 不用语义化版本近似发行版比较规则。dpkg 的 `~` 回移、rpm 的 epoch 优先级都按原生语义实现。
- 不把 HTTPS 传输或哈希校验冒充成厂商签名。签名状态与完整性状态分列记录。
- 不在数据不全时报告「零漏洞」。覆盖不足返回专用退出码 9，脚本不会把它读成安全。
- 不自动重启服务器。

当前版本 **v2.0.0**，变更见 [CHANGELOG.md](CHANGELOG.md)。

## 快速开始

```bash
# 1. 采集本机资产（软件包、内核、发行版）
sudo linux-cve inventory

# 2. 同步漏洞情报（首次较慢，之后增量）
sudo linux-cve feed update --all

# 3. 扫描
sudo linux-cve scan

# 4. 看明细与报告
sudo linux-cve list --vulnerable
sudo linux-cve report --save /var/log/linux-cve/report.md

# 5. 预演修复（不改系统），确认后执行
sudo linux-cve plan
sudo linux-cve fix --yes
```

`scan` 的退出码可以直接用于 CI：

| 退出码 | 含义 |
| --- | --- |
| 0 | 扫描完成，未发现受影响项，且情报覆盖完整 |
| 3 | 扫描完成，发现受影响项 |
| 9 | 扫描完成，但情报覆盖不足（结论不能当作安全依据） |
| 1 / 2 / 4 / 5 / 6 / 7 / 130 | 运行时错误 / 参数错误 / 环境不支持 / 权限不足 / 修复失败 / 完整性校验失败 / 中断 |

## 六个情报源

| 源 | 信任级 | 形式 | 实测规模（2026-11-24，单库实测） |
| --- | --- | --- | --- |
| Debian Security Tracker | B（HTTPS+SHA256） | 单文件 JSON，约 90MB | 210,415 公告 / 222,161 修复 |
| Ubuntu OVAL | B | 按 codename 的 bzip2 OVAL | noble：270.8MB XML → 37,611 公告 / 48,617 修复（20.0s） |
| Alpine secdb | B | 按 release×仓库的 JSON | 3.20：8,299 公告 / 8,344 修复（3.1s） |
| Arch Security Tracker | B | 单文件 JSON | 8,035 公告 / 7,401 修复 / 303 不受影响（1.8s） |
| Red Hat CSAF | A（GPG 分离签名） | 每份 RHSA 一个 JSON + `.asc` | 全量 32,407 份；2026 切片 10,409 份 → 66,991 公告 / 810,817 修复 / 26,327 不受影响 |
| SUSE CSAF | A（GPG 分离签名） | 每份公告一个 JSON + `.asc` | 全量 45,765 份；2026 切片 13,561 份 → 149,788 公告 / 965,304 修复 |

六个源同时入库后的实测量级：**481,139 条公告、2,062,599 条修复记录**，
SQLite 1.5GB，原始发布物 6.1GB（23,978 个按 sha256 寻址的不可变文件）。
CSAF 源体积大，用 `feed update rhel-csaf --since 2026` 控制到年度切片。

A 级源的签名指纹固化在代码里（`internal/feed/registry.go`），换钥必须显式改代码，
不会静默接受任意密钥。详见 [docs/data-sources.md](docs/data-sources.md)。

## 三个状态维度

一条判定由三个相互正交的维度组成，禁止合并成单一枚举：

| 维度 | 取值 | 回答的问题 |
| --- | --- | --- |
| `VulnState` | `VULNERABLE` / `FIXED` / `NOT_AFFECTED` / `UNKNOWN` / `UNSUPPORTED` | 现在有没有这个洞 |
| `RemediationState` | `FIX_AVAILABLE` / `NO_FIX` / `FIX_PENDING_MIRROR` / `MANUAL_REQUIRED` / `BLOCKED` / `NOT_APPLICABLE` / `UNKNOWN` | 能不能修、怎么修 |
| `RebootState` | `NOT_REQUIRED` / `REQUIRED` / `UNKNOWN` | 补丁是否已生效 |

「已修复」只表示本机版本不低于官方声明的修复版本；是否真正生效取决于服务重启与主机重启，
这是两件不同的事，报告里分开写。

## 命令

| 命令 | 作用 |
| --- | --- |
| `inventory [--json] [--save]` | 采集软件包 / 内核 / 发行版 |
| `feed update [源...] [--all] [--since N]` | 同步情报；`--since` 只对 CSAF 源生效 |
| `feed status [--json]` | 各情报源的信任级、签名状态、最近成功时间 |
| `scan [--json] [--dry-run]` | 判定并写库；`--dry-run` 只打印 |
| `list [--vulnerable] [--state S] [--json] [--limit N]` | 列出最近一次扫描结果 |
| `show <CVE> [--json]` | 单个 CVE 的判定依据（哪个源、哪份文件、什么规则） |
| `plan [--package P] [--json]` | 生成修复计划，不改系统 |
| `fix [--yes] [--dry-run] [--package P] [--json]` | 执行计划并复检；不带 `--yes` 等同 `plan` |
| `report [--out 路径]` | 输出 Markdown 报告 |
| `support [--json]` | 支持矩阵与自动修复许可 |
| `db status` / `db migrate` | 数据库状态与迁移 |
| `version [--json]` | 版本信息 |

完整参数与输出示例见 [docs/cli.md](docs/cli.md)。

## 支持矩阵

| 发行版 | 版本 | 检测 | 自动修复 |
| --- | --- | --- | --- |
| Debian | 13 trixie | ✅ 实机 + 容器 | ✅ 实机验证 |
| Debian | 12 bookworm | 🟡 数据就绪 | ✅ 开放 |
| Debian | 11 bullseye | 🟡（已 EOL） | ❌ 生命周期结束 |
| Ubuntu | 24.04 noble | ✅ 容器验证 | ❌（ESM 不在覆盖范围） |
| Ubuntu | 22.04 jammy | 🟡 | ❌（ESM 不在覆盖范围） |
| Alpine | 3.20 | ✅ 容器验证 | ❌（已 EOL） |
| Alpine | 3.19 / 3.21 | 🟡 | ❌（均已 EOL） |
| Arch | rolling | ✅ | ❌（无固定版本语义，`pacman` 无可靠预演） |
| RHEL | 8 / 9 / 10 | ✅ | ❌ |
| SLES | 15.6 / 16.0 | ✅ | ❌ |
| openSUSE Leap | 15.6 / 16.0 | ✅ | ❌ |

「容器验证」= 在官方镜像内运行同一个二进制、真实同步官方情报后真实扫描，
CI 每次提交都重跑；它不等于裸机验收（共用宿主内核）。未登记的 release 一律按
`UNKNOWN` 处理，不按「最新的那个」兜底。完整生命周期日期见
[docs/support-matrix.md](docs/support-matrix.md)。

## 从源码构建

```bash
go build -o linux-cve ./cmd/linux-cve     # Go 1.24+
go test ./...
```

纯 Go 实现，无 cgo 依赖（SQLite 用 `modernc.org/sqlite`），可直接交叉编译到
amd64 / arm64 的 Linux。

## 数据与隐私

- 全部判定在本机完成，不上传资产清单。
- 数据库默认在 `/var/lib/linux-cve/cve.db`，情报原始文件按内容寻址存放在
  `/var/lib/linux-cve/artifacts/`，只读、不可变。
- 只访问上表中的官方源与厂商公钥地址。

## 已知限制

- 情报源的「未收录」不等于「不受影响」。报告与退出码会显式区分，但无法消除这一不确定。
- 发行版公告按源码包发布的情况（Debian/Ubuntu）需要源码包桥接；桥接失败会单独计数并在
  报告中标注，不计入「不受影响」。
- Debian 的 `status=open`（确认受影响、暂无补丁）会被判为 `VULNERABLE` + `NO_FIX`，
  这类记录在老旧 CVE 上数量很大，属于事实而非噪声。
- RHEL 的 VEX 文档单份可达 16.8MB（78,041 份），本期改抓 RHSA，VEX 独有的
  `under_investigation` 语义只能从 RHSA 的同类字段近似。
- 自动修复只覆盖 Debian 12/13，且执行后必须复检；复检不通过时返回退出码 6。
  实机验收：Debian 13 上把 `libcap2`、`libcap2-bin` 从 `1:2.75-10+b1` 升到
  `1:2.75-10+deb13u1+b3`，复检通过，随后重扫受影响项从 10,230 降到 10,228。
- SUSE 的 VEX 源（`csaf-vex`）本期不接入，因此 SUSE 只有「受影响 + 有修复版本」
  与「已修复」，没有「不受影响」声明；RHEL 的 VEX 也未接入，但 RHSA 里带
  `known_not_affected`，故有 26,327 条不受影响记录。

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/cli.md](docs/cli.md) | 命令、参数、输出与退出码 |
| [docs/data-sources.md](docs/data-sources.md) | 六个情报源的实测结构、字段语义与解析取舍 |
| [docs/security-model.md](docs/security-model.md) | 信任分级、签名与完整性、故障语义 |
| [docs/support-matrix.md](docs/support-matrix.md) | 生命周期与自动修复许可 |
| [docs/architecture.md](docs/architecture.md) | 分层与数据流 |
| [docs/data-model.md](docs/data-model.md) | 数据库表结构 |
| [docs/troubleshooting.md](docs/troubleshooting.md) | 常见故障与排查 |
| [docs/migration-v1-v2.md](docs/migration-v1-v2.md) | 从 v1.x 迁移 |
| [docs/phase3.0-design.md](docs/phase3.0-design.md) | 阶段 3 架构决策（冻结） |

## 许可

见 [LICENSE](LICENSE)。
