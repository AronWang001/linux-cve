# CLI 契约

命令、参数、输出与退出码。这是与脚本、CI、监控对接的唯一契约；
`docs/data-sources.md` 讲数据从哪来，这里只讲「怎么用」与「怎么判断结果」。

## 1. 三条硬规则

1. **stdout 只放业务输出**，日志固定写 stderr。`linux-cve scan --json | jq` 永远能解析。
2. **所有 `--json` 输出带 `schema_version`**，字段只增不改；变更需要升版本号。
3. **退出码是唯一机器契约**。任何「数据不全」都必须体现为退出码，不能靠人读文字。

## 2. 全局参数

```
linux-cve [全局参数] <命令> [命令参数]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `--config <路径>` | `/etc/linux-cve/config.toml` | 配置文件；不存在则用内置默认值 |
| `--db <路径>` | `/var/lib/linux-cve/cve.db` | 数据库文件 |
| `--log-level <级别>` | `info` | `debug` / `info` / `warn` / `error` |
| `--log-format <格式>` | `text` | `text` / `json` |
| `--offline` | 关 | 只用本地已同步的情报，不发起网络请求 |

优先级：内置默认值 < 配置文件 < 环境变量 < 命令行参数。

环境变量：`LINUX_CVE_CONFIG`、`LINUX_CVE_DB_PATH`、`LINUX_CVE_DATA_DIR`、
`LINUX_CVE_LOG_LEVEL`、`LINUX_CVE_LOG_FORMAT`、`LINUX_CVE_OFFLINE`、
`LINUX_CVE_ALLOW_AUTO_FIX`、`LINUX_CVE_MAX_COLLATERAL_PACKAGES`。

`LINUX_CVE_ALLOW_AUTO_FIX=false` 是硬开关：即使支持矩阵允许、即使写了 `--yes`，
`fix` 也只会预演。它优先于命令行，用于在受管主机上彻底禁用自动修复。

数据目录默认 `/var/lib/linux-cve/`：`cve.db` 是数据库，`artifacts/` 是
按 sha256 内容寻址的原始情报文件（只读、不可变），`artifacts/*.lock` 是同步锁。

## 3. 命令表

| 命令 | 作用 | 需要 root |
| --- | --- | --- |
| `inventory [--json] [--save]` | 采集软件包 / 内核 / 发行版 | 否 |
| `feed update [源...] [--all] [--since N] [--release R] [--json]` | 同步情报 | 否（写库需权限） |
| `feed status [--json]` | 各源信任级、签名状态、最近成功时间 | 否 |
| `scan [--json] [--dry-run]` | 采集 + 判定 + 写库 | 否 |
| `list [--vulnerable] [--state S] [--limit N] [--json]` | 最近一次扫描的明细 | 否 |
| `show <CVE> [--json]` | 单个 CVE 的判定依据与证据链 | 否 |
| `plan [--package P] [--json]` | 生成修复计划，不改系统 | 否 |
| `fix [--yes] [--dry-run] [--package P] [--json]` | 执行并复检 | **是** |
| `report [--out 路径]` | 输出 Markdown 报告 | 否 |
| `support [--json]` | 支持矩阵与自动修复许可 | 否 |
| `db status` / `db migrate` | 数据库状态与迁移 | 否 |
| `version [--json]` | 版本、提交、构建时间 | 否 |
| `help [命令]` | 帮助 | 否 |

## 4. 逐步说明

### 4.1 inventory

```bash
linux-cve inventory            # 打印资产概览
linux-cve inventory --json     # 机器可读
linux-cve inventory --save     # 落库（scan 会自己采集，一般不需要单独存）
```

采集项：发行版 ID 与 release（来自 `/etc/os-release`）、架构、内核版本、
已安装包清单（dpkg / rpm / apk，含源码包名与来源渠道）。

输出包含 `entry_hash`：同一台机器在包不变时哈希不变，可用于判断「有没有变过」。

### 4.2 feed update

```bash
linux-cve feed update --all                 # 全部源
linux-cve feed update debian-tracker        # 指定源
linux-cve feed update rhel-csaf --since 2026   # CSAF 源只取 2026 年及以后
linux-cve feed update ubuntu-oval --release noble
linux-cve feed update alpine-secdb --release 3.20
```

- 源名见 `feed status` 的 ID 列：`debian-tracker`、`ubuntu-oval`、`alpine-secdb`、
  `arch-tracker`、`rhel-csaf`、`suse-csaf`。
- `--release` 只对按 release 分文件的源有效（Ubuntu 用 codename，Alpine 用 `3.20`）。
  不给会直接报错，不会去猜一个「最像的」release。
- `--since` 只对按文档发布的 CSAF 源有效，用于控制体积：RHEL 全量约 11GB，
  2026 切片约 3.6GB。
- 同步是**替换快照**语义：一次成功的同步完成后，旧快照整体失效，
  不会出现新旧数据混在一张表里的中间态。
- 同源并发会被文件锁挡住（`artifacts/<源>.lock`），30 分钟未释放视为过期可回收。

成功输出形如：

```
debian-tracker: 公告 210415 / 修复 222161 / 不受影响 0（17.9s）
debian-tracker：公告 210415、修复 222161（用时 17.9s）
```

### 4.3 feed status

```
情报库：公告 481139 条，修复记录 2062599 条

情报源                    信任     解析器      状态        最近成功
alpine-secdb           B      就绪       ok        2026-11-24T13:50:12Z
arch-tracker           B      就绪       ok        2026-11-24T13:49:46Z
debian-tracker         B      就绪       ok        2026-11-24T12:59:13Z
rhel-csaf              A      就绪       ok        2026-11-24T13:30:48Z
suse-csaf              A      就绪       ok        2026-11-24T13:44:58Z
ubuntu-oval            B      就绪       ok        2026-11-24T13:50:37Z
```

`状态` 是 `ok` / `unknown`（从未成功）/ `failed`（最近一次失败）。
`解析器` 列只有「就绪」与原因两种取值，不显示「部分支持」。

### 4.4 scan

```bash
sudo linux-cve scan            # 判定并写库（scan 记录成为 list/plan/fix 的输入）
linux-cve scan --dry-run       # 只判定，不写库
linux-cve scan --json | jq '.counts'
```

文本输出：

```
扫描：debian  13  架构 x86_64
覆盖：COVERED（该发行版所需的全部情报源均可用且未过期）
生命周期：active —— 常规安全支持期内

判定 124470 条：受影响 10230、已修复 100985、不受影响 0、未知 13255
统计：参与判定包 455 个，其中 206 个在情报库中无任何记录（属覆盖缺口，不代表安全）

受影响明细（前 20 条，完整清单用 list）：
  low      linux-libc-dev          CVE-2004-0230            本机 6.12.115-2                修复 -                         NO_FIX
```

「覆盖」是**按目标发行版算的**：Debian 机器上没同步 RHEL 情报不算缺口，
同步过的 Debian 情报过期了才算。两者混在一起会让干净机器永远拿不到退出码 0。

`--json` 结构：

```json
{
  "schema_version": 1,
  "scan_id": "scan-20261124T125935Z-4cb1954c",
  "distro": "debian", "release": "13", "arch": "amd64",
  "coverage": "COVERED", "coverage_detail": "该发行版所需的全部情报源均可用且未过期",
  "counts": {"total": 124470, "vulnerable": 10230, "fixed": 100985,
             "not_affected": 0, "unknown": 13255, "no_data": 206, "evaluated": 455},
  "findings": [{"cve_id": "...", "package": "...", "installed_version": "...",
                "fixed_version": "...", "vuln_state": "FIXED",
                "remediation_state": "NOT_APPLICABLE", "reboot_state": "NOT_REQUIRED",
                "confidence": "CONFIRMED", "severity": "unknown",
                "advisory_id": "...", "source_id": "debian-tracker"}]
}
```

### 4.5 list

```bash
linux-cve list                       # 全部（可能很长）
linux-cve list --vulnerable          # 只看受影响
linux-cve list --state FIXED --limit 20
```

`--limit` 只影响显示条数，头部仍报总数：

```
扫描 scan-20261124T125935Z-4cb1954c（debian 13）共 124470 条，显示前 3 条（--limit）：
```

### 4.6 show

```bash
linux-cve show CVE-2024-26581
```

输出每个「CVE × 包」的判定，含证据链——哪个源、哪份公告、哪条规则、
比较结果。`show` 是自证入口：任何一条结论都应能追到原始公告。

```
CVE：CVE-2024-26581
包：linux-libc-dev（amd64）
本机版本：6.12.115-2
修复版本：6.7.7-1
严重度：unknown
检测结论：FIXED
修复可行性：NOT_APPLICABLE
证据可信度：CONFIRMED
公告：CVE-2024-26581/linux/13（debian-tracker）
证据链：[{"SourceID":"debian-tracker","Signature":"not-applicable","Integrity":"verified",
         "MatchKind":"fixed_version","Detail":"本机 6.12.115-2 已达到或超过官方修复版本 6.7.7-1", ...}]
```

### 4.7 plan

```bash
linux-cve plan                         # 全部受影响包的预演
linux-cve plan --package libcap2       # 只看某个包
linux-cve plan --json
```

```
修复计划（基于扫描 scan-20261124T125935Z-4cb1954c）
目标：debian 13，包管理器 dpkg，生命周期 active
参与判定 124470 条，计划覆盖 4898 个 CVE、60 个包

包                            严重度        本机版本                       目标版本                       覆盖 CVE
libcap2                                 1:2.75-10+b1               1:2.75-10+deb13u1          1
```

计划规则：

- 同一个包的多个 CVE 合并成一步，目标版本取其中最高的修复版本。
- 按严重度从高到低排序，同严重度按包名，保证每次输出一致。
- 不可执行的项不会「消失」，而是记入「未纳入计划的判定」并写明原因
  （`NO_FIX` / `MANUAL_REQUIRED` / 生命周期已结束 / 发行版不开放自动修复）。
- `--package` 只缩小范围，不改变判定。

### 4.8 fix

```bash
sudo linux-cve fix                     # 等同 plan，不动系统
sudo linux-cve fix --yes               # 执行全部
sudo linux-cve fix --yes --package libcap2,libcap2-bin   # 只修这两个包
```

五道闸门全过才会真的动系统：

1. 支持矩阵里该发行版/release 的「自动修复」为开放；
2. 生命周期不是 `eol` / `unknown`；
3. 包管理器有可靠的升级语义（dpkg / dnf / apk，**不含 pacman**）；
4. `allow_auto_fix` 配置未被关掉；
5. 命令行显式 `--yes`。

执行后**必须复检**：重新采集已安装版本，按发行版原生规则比较。复检不通过返回退出码 6，
不会因为 `apt-get` 返回 0 就宣布成功。

实机输出（Debian 13，只修两个包）：

```
[1/2] 升级 libcap2 → 1:2.75-10+deb13u1
[2/2] 升级 libcap2-bin → 1:2.75-10+deb13u1
成功 libcap2 → 1:2.75-10+deb13u1：Processing triggers for libc-bin (2.41-12) ...
成功 libcap2-bin → 1:2.75-10+deb13u1：0 upgraded, 0 newly installed, 0 to remove and 102 not upgraded.

复检结果：
  OK  libcap2                      目标 1:2.75-10+deb13u1        实际 1:2.75-10+deb13u1+b3     已不低于目标版本
  OK  libcap2-bin                  目标 1:2.75-10+deb13u1        实际 1:2.75-10+deb13u1+b3     已不低于目标版本

结论：计划内全部包已达到目标版本。
```

注意实际版本 `1:2.75-10+deb13u1+b3` 比目标多了 `+b3`：那是 Debian 的 binNMU 后缀，
在 dpkg 语义下高于目标版本，判定为「已不低于目标」。用语义化版本比较会把它判成
「未知版本」——这正是不能用 semver 近似发行版规则的原因。

### 4.9 report

```bash
linux-cve report                      # Markdown 到 stdout
linux-cve report --out /var/log/linux-cve/report.md
```

报告分五节：结论计数、覆盖范围（逐源状态与说明）、受影响明细、
未知项说明、修复建议。可以直接贴进工单。

### 4.10 support

```
发行版              版本         代号       生命周期         自动修复     结束支持
debian           12         bookworm active       开放       2028-06-30
debian           13         trixie   active       开放       2030-06-30
rhel             9                   active       不开放      2032-05-31
```

「生命周期」与「自动修复」是两件事：RHEL 9 在支持期内，但本期不开放自动修复。
未列出的 release 一律 `unknown`，不按「最新的那个」兜底。

## 5. 退出码

| 码 | 名称 | 何时出现 |
| --- | --- | --- |
| 0 | `OK` | 成功；`scan` 无受影响项**且**覆盖完整 |
| 1 | `ERROR` | 未分类运行时错误 |
| 2 | `USAGE` | 参数错误、未知子命令 |
| 3 | `FINDINGS` | `scan` 发现受影响项 |
| 4 | `UNSUPPORTED` | 发行版/release 不受支持，或计划被闸门阻止 |
| 5 | `PERMISSION` | 需要 root 而未以 root 运行 |
| 6 | `REMEDIATION_FAILED` | 修复执行失败或复检未通过 |
| 7 | `INTEGRITY` | 情报完整性/签名校验失败 |
| 8 | `NOT_IMPLEMENTED` | 已注册但未实现（v2.0.0 已无此情况） |
| 9 | `COVERAGE` | 扫描完成但覆盖不足，结论不能当作安全依据 |
| 130 | `INTERRUPTED` | Ctrl-C |

`scan` 的判定顺序是**发现漏洞 > 覆盖不足 > 成功**：有洞就是 3，不会因为覆盖不足变成 9
（有洞这件事比数据不全更紧急）。

CI 用法：

```bash
linux-cve feed update --all || exit $?
linux-cve scan --json > scan.json
case $? in
  0) echo "无受影响项且数据完整" ;;
  3) echo "发现受影响项"; jq '.counts' scan.json ;;
  9) echo "情报覆盖不足，结论不可作为安全依据"; exit 9 ;;
esac
```

## 6. 退出码不能表达的东西

- 某个包在情报库里没有记录，但它是本机从第三方源装的：工具会把它计入
  `no_data`，逐包清单在 `list` 里体现，不在退出码里。
- 已修复但需要重启才生效：`reboot_state` 字段体现，不影响退出码。
  想让「待重启」也算失败，读 JSON 自己判断。
