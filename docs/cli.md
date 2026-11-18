# CLI 契约与退出码

## 1. 命令表

| 命令 | 作用 | 阶段 |
|------|------|------|
| `linux-cve scan` | 采集资产 + 匹配情报，输出漏洞清单 | 3 |
| `linux-cve list` | 列出上一次扫描结果（支持 `--severity`、`--state`） | 3 |
| `linux-cve show <CVE>` | 展示单条 CVE 的判定依据与证据 | 3 |
| `linux-cve plan [CVE...]` | 生成修复计划与变更集预演，不执行 | 5 |
| `linux-cve fix [CVE...]` | 执行修复（需确认或 `--yes`），自动复检 | 5 |
| `linux-cve report` | 输出 TXT / JSON 报告 | 6 |
| `linux-cve feed update` | 更新情报库 | 3 |
| `linux-cve feed status` | 展示各源更新时间、信任等级、校验状态 | 3 |
| `linux-cve support` | 打印支持矩阵（检测 / 修复查询 / 自动修复三列） | 4 |
| `linux-cve db status` | 展示数据库路径、Schema 版本、迁移记录 | 1 |
| `linux-cve db migrate` | 应用未执行的迁移 | 1 |
| `linux-cve version` | 打印版本、提交、构建时间、Go 版本 | 1 |
| `linux-cve help [cmd]` | 帮助 | 1 |

阶段 1 只实现 `version`、`help`、`db status`、`db migrate`；其余子命令已注册但返回 `NOT_IMPLEMENTED`（退出码 8），不会静默成功。

## 2. 统一退出码

| 码 | 名称 | 含义 |
|----|------|------|
| 0 | `OK` | 成功；`scan` 无漏洞也返回 0 |
| 1 | `ERROR` | 未分类运行时错误 |
| 2 | `USAGE` | 参数错误、未知子命令 |
| 3 | `FINDINGS` | 命令成功但发现漏洞（`scan`/`list` 专用，便于脚本判定） |
| 4 | `UNSUPPORTED` | 当前发行版/release/包管理器不支持该操作（含 AL2、Arch 的 fix） |
| 5 | `PERMISSION` | 需要 root 或权限不足 |
| 6 | `REMEDIATION_FAILED` | 执行失败或执行后复检未通过 |
| 7 | `INTEGRITY` | 数据库校验失败、迁移校验和不符、情报签名校验失败 |
| 8 | `NOT_IMPLEMENTED` | 该阶段尚未实现 |
| 130 | `INTERRUPTED` | 被 SIGINT 中断 |

映射规则：`apperr.Error.Code` 显式携带退出码；未包装的错误一律映射为 `1`；退出码只由 `cmd/linux-cve` 一处 `os.Exit`，其他包只返回 error。

## 3. 配置

加载顺序（后者覆盖前者）：内置默认值 → 配置文件 → 环境变量 → 命令行参数。

- 默认配置路径：`/etc/linux-cve/config.toml`（Windows 或非 root 时回退到 `$XDG_CONFIG_HOME/linux-cve/config.toml`）
- 环境变量前缀：`LINUX_CVE_`（如 `LINUX_CVE_DB_PATH`、`LINUX_CVE_LOG_LEVEL`）
- 命令行：`--config`、`--db`、`--log-level`、`--log-format`、`--offline`、`--json`

配置项（`config.Config`）：

```toml
[general]
db_path = "/var/lib/linux-cve/linux-cve.db"
data_dir = "/var/lib/linux-cve"
offline = false
[logging]
level = "info"     # debug|info|warn|error
format = "text"    # text|json
[feed]
http_timeout = "60s"
max_age = "72h"
[remediation]
allow_auto_fix = false
max_collateral_packages = 5
```

`allow_auto_fix = false` 时 `fix` 必须显式 `--yes` 也不放行——配置层是硬开关，命令行不能绕过。

## 4. 示例

```
$ linux-cve version
linux-cve 2.0.0-dev (commit none, built unknown, go1.27.4, linux/amd64)

$ linux-cve db migrate
applied 1 migration(s); schema version = 1

$ linux-cve db status
database    : /var/lib/linux-cve/linux-cve.db
schema      : 1
migrations  : 0001_init (2026-11-18T02:41:20Z)
pending     : none
feed sources: 0 registered

$ linux-cve scan
error: cli: scan 尚未实现（阶段 3）
$ echo $?
8
```
