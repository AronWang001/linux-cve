# 故障排查

按「看到什么 → 为什么 → 怎么办」组织。所有现象都来自实际踩过的坑，
不是设想的清单。

## 1. 情报同步

### `feed update ubuntu-oval` 报「需要 --release」

```
ubuntu-oval：cli.feed: Ubuntu OVAL 需要 --release <codename 形式>；本机是 debian/13
```

按 release 分文件的源（Ubuntu、Alpine）**不会**替你去猜一个 release。
Ubuntu 用 codename，不是版本号：

```bash
linux-cve feed update ubuntu-oval --release noble
linux-cve feed update alpine-secdb --release 3.20
```

`--release 24.04` 会失败——上游文件名就是 `com.ubuntu.noble.cve.oval.xml.bz2`。

### `feed update` 卡在「等待锁」

```
另一个进程正在更新该情报源
```

每个源一把文件锁 `artifacts/<源>.lock`，防止两个进程同时替换同一份快照。
超过 30 分钟未释放视为进程已死，可被回收。

如果确认没有进程在跑（`ps aux | grep linux-cve`），可以直接删锁文件：

```bash
rm /var/lib/linux-cve/artifacts/<源>.lock
```

### 签名校验失败

```
gpg: 签名校验失败：公钥环中找不到指纹 ...
```

A 级源（`rhel-csaf`、`suse-csaf`）的指纹**硬编码在代码里**
（`internal/feed/registry.go`），这是故意的：厂商换钥必须显式改代码发版，
不能自动接受新钥匙。

真遇到换钥时：核对厂商公告里的新指纹，改常量，重新编译。不要临时放宽校验。

### 同步失败率过高

```
异常记录 3/5 超过阈值，整批拒绝
```

半套情报比没有情报更危险——覆盖状态看起来仍然是 `COVERED`。
所以出错率超阈值整批拒绝，旧快照保持有效（`feed status` 里显示上一次的
`last_success_at`）。

看具体原因：`--log-level debug`，或 `feed update <源> 2>&1 | head -40`。

## 2. 扫描

### 退出码 9（COVERAGE）

扫描完成，但**该发行版所需的情报源**没到位：从未成功同步，或超过
`feed.max_age`（默认 72 小时）而过期。

```bash
linux-cve feed status          # 看哪个源是 unknown / failed
linux-cve report | head -20    # 看覆盖章节的逐源说明
```

退出码 9 的含义是「结论不能当作安全依据」，不是「没有漏洞」。

### 大量包显示「情报库中无任何记录」

```
统计：参与判定包 455 个，其中 206 个在情报库中无任何记录
```

三个来源：

1. **源码包桥接失败**（Debian/Ubuntu 公告按源码包发布）——已经做了桥接，
   实测 239 个包是按源码名命中的，桥接失效的情况为 0；
2. **第三方源 / 手工 `.deb` / 本地编译的包**——官方情报源里本来就没有；
3. **该发行版的情报源未同步**——先看退出码是不是 9。

这 206 个不会被算进「不受影响」，也不会被算进「受影响」，它们是覆盖缺口。

### 扫描很慢 / 占用内存

全量 Debian Tracker 是 210,415 条公告、222,161 条修复记录。v2 按源码包推进、
按批落库，内存只需容纳一个包；但 12 万条判定的写库仍然要花时间。
首次扫描慢是正常的，它会写入一份完整快照。

`findings` 表随扫描次数线性增长（每次扫描一份全量判定）。只保留最近几次扫描
可以显著减小库体积：

```sql
DELETE FROM findings WHERE scan_id NOT IN
  (SELECT id FROM scans ORDER BY started_at DESC LIMIT 5);
```

## 3. 修复

### `fix --yes` 退出码 4，提示「配置未开启自动修复」

```
状态：不可执行 —— 配置未开启自动修复（remediation.allow_auto_fix = false）
```

这是**默认行为**。自动修复会改系统，必须显式开启：

```toml
# /etc/linux-cve/config.toml
[remediation]
allow_auto_fix = true
max_collateral_packages = 5
```

或者环境变量 `LINUX_CVE_ALLOW_AUTO_FIX=true`。命令行 `--yes` 不能绕过这一条：
两者是「允许」与「确认」，缺一不可。

### `fix` 退出码 5（PERMISSION）

升级软件包需要 root。用 `sudo`，或用 `--dry-run` 看计划。

### `fix` 退出码 6（REMEDIATION_FAILED）

两种原因，输出的最后一段会区分：

- **执行失败**：某一步包管理器返回非 0，`fix` 立即停止，不会继续后面的步骤
  （继续跑只会让系统停在一个更难解释的中间态）。
- **复检未通过**：命令成功了，但版本没到位。常见于本地 pin、
  优先级文件（`/etc/apt/preferences`）、或仓库镜像还是旧版本。
  这种情况**不会**因为 `apt-get` 返回 0 就宣布成功。

- **附带变更超限**：升级顺带装了超过 `max_collateral_packages` 个新包。
  输出里列出了具体包名，需要人工确认这些依赖是否可接受。

### 修复后状态仍是「待重启」

`RebootState=REQUIRED` 表示补丁已安装但未生效（内核、glibc、systemd 等）。
这不影响 `VulnState`（版本已经不低于修复版本），但**工具不会重启你的服务器**。
什么时候重启由你决定。

## 4. 数据库

### `db migrate` 报 schema 版本不一致

```
数据库 schema 版本 3 高于程序支持的 2
```

用旧版本的二进制打开了新库。装回匹配的版本，或备份后重建：

```bash
mv /var/lib/linux-cve/cve.db /var/lib/linux-cve/cve.db.bak
linux-cve db migrate
linux-cve feed update --all
```

反向（库比程序旧）是安全的：`db migrate` 会补上缺失的迁移。

### 迁移校验和不匹配

```
迁移 0003 的校验和与记录不一致
```

已应用的迁移文件被改过。这在发布版里不该出现——说明二进制来源可疑，
先核对发布包的 GPG 签名与 SHA256。

### 磁盘占用

| 内容 | 实测量级 |
| --- | --- |
| `cve.db`（六源 2026 切片） | 1.5GB |
| `artifacts/`（原始发布物） | 6.1GB / 23,978 个文件 |
| RHEL 全量（不加 `--since`） | 约 11GB |
| SUSE 全量 | 约 8GB |

CSAF 源按年切片能省一个数量级：

```bash
linux-cve feed update rhel-csaf --since 2026
```

`artifacts/` 是内容寻址的不可变存储，删除会导致已有公告失去原始证据
（`show` 仍能显示归一化结果，但无法回溯字节）。要清理就连同旧快照一起清。

## 5. 输出与集成

### `scan --json | jq` 解析失败

stdout 只放业务输出，日志在 stderr。若仍失败，检查是否有包装脚本把
stderr 重定向进了 stdout（`2>&1`）。

### 报告里「情报源」一节与 `feed status` 不一致

报告是**按扫描时的目标发行版**过滤的：与目标发行版无关的源会标注
「与目标发行版无关，不参与覆盖判定」。`feed status` 列的是全部源。

### 时间显示不对

所有时间戳都是 UTC（`...Z`）。`feed.max_age` 也按 UTC 计算。
系统时钟漂移会让「刚同步的情报」立刻显示过期——装 `chrony` 或 `systemd-timesyncd`：

```bash
timedatectl status
```
