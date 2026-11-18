# CLI 契约与退出码

## 1. 命令表

| 命令 | 作用 | 阶段 |
|------|------|------|
| `linux-cve inventory [--json] [--save]` | 采集本机资产（发行版、内核、软件包清单），可持久化 | 2 |
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

阶段 2 已实现 `inventory` 命令；阶段 1 已实现 `version`、`help`、`db status`、`db migrate`；其余子命令已注册但返回 `NOT_IMPLEMENTED`（退出码 8），不会静默成功。

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

## 3. inventory 命令契约

`linux-cve inventory [--json] [--save]`

采集动作严格只读：只执行 `uname`、`dpkg-query` / `rpm -qa` / `apk list` / `pacman -Qi` 等查询命令，绝不刷新软件源或修改系统状态。

| 参数 | 作用 |
|------|------|
| `--json` | 以 JSON 输出采集结果（snake_case 字段，见下方契约） |
| `--save` | 将采集结果在单事务内持久化到数据库（需先 `db migrate`） |

退出码：

| 场景 | 退出码 |
|------|--------|
| 采集成功 | 0 |
| 未登记发行版 | 4（`UNSUPPORTED`，错误信息含已识别事实） |
| 参数错误 | 2（`USAGE`） |
| 采集/序列化/数据库错误 | 1（`ERROR`） |

stdout 与 stderr 严格分离：正常结果与 JSON 走 stdout，错误信息走 stderr。采集失败绝不静默返回成功。

### 3.1 `--json` 输出契约

JSON 输出使用独立 CLI DTO（`internal/app/inventory_dto.go`），不直接暴露 domain 模型的 Go 默认序列化。字段统一 snake_case，顺序稳定（struct 声明顺序），可演进性由 `schema_version` 保证。

```json
{
  "schema_version": 1,
  "collected_at": "2026-01-01T00:00:00Z",
  "distro": {
    "id": "debian",
    "os_id": "debian",
    "name": "Debian GNU/Linux 12",
    "release": "12",
    "codename": "bookworm",
    "arch": "amd64",
    "manager": "dpkg"
  },
  "kernel": {
    "running": "6.1.0-37-amd64",
    "package": "linux-image-6.1.0-37-amd64",
    "version": "6.1.140-1",
    "evidence": "dpkg package linux-image-6.1.0-37-amd64 matches uname -r"
  },
  "packages": [
    {
      "kind": "binary",
      "name": "bash",
      "arch": "amd64",
      "version": "5.2.15-2+b7",
      "source_name": "bash",
      "source_version": "5.2.15-2",
      "manager": "dpkg",
      "origin_channel": "unknown",
      "vendor": "GNU",
      "install_time": "2026-01-01T00:00:00Z",
      "entry_hash": "..."
    }
  ],
  "hash": "...",
  "warnings": []
}
```

空值语义约定：

- 空数组统一输出 `[]`，不使用 `null`（`packages`、`warnings` 等）。
- 空字符串显式输出 `""`（`source_name`、`vendor`、`kernel.package`、`kernel.evidence` 等），不省略字段。
- 时间字段统一 UTC RFC3339；零值（未知）输出空串 `""`，不伪造时间。
- `origin_channel` 无法证明时恒为 `"unknown"`，不得猜测。

版本演进：`schema_version` 每次字段增删/改名/类型变更时递增；下游按版本号解析，旧字段移除前保留一个版本周期。

## 4. 配置

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

## 5. 示例

```
$ linux-cve version
linux-cve 2.0.0-dev (commit none, built unknown, go1.27.4, linux/amd64)

$ linux-cve db migrate
applied 2 migration(s); schema version = 2

$ linux-cve db status
database    : /var/lib/linux-cve/linux-cve.db
schema      : 2
migrations  : 0001_init (2026-11-18T02:41:20Z), 0002_inventory (2026-11-18T02:41:20Z)
pending     : none
feed sources: 0 registered

$ linux-cve inventory
distro       : debian
release      : 12
codename     : bookworm
arch         : x86_64
kernel       : 6.1.0-37-amd64
kernel pkg   : linux-image-6.1.0-37-amd64 (6.1.140-1)
packages     : 1284
collected at : 2026-11-18T09:00:00Z
hash         : 9f2c...

$ linux-cve scan
error: cli: scan 尚未实现（阶段 3）
$ echo $?
8
```
