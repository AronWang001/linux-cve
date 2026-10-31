# Debian CVE-2026-98432 Fix

Debian 12 / Debian 13 的 CVE-2026-98432 Linux 内核漏洞**检测 + 一键修复**脚本。

只用 Debian 官方软件源安装官方修复内核：不编译内核、不删旧内核、不自动重启、不动业务配置。

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.0.0/fix.sh -o fix.sh && chmod +x fix.sh && sudo bash fix.sh
```

> 安装内核后**必须重启**才会真正生效。脚本不会替你重启，重启前主机仍然受影响。

**English**: A Bash tool that detects and fixes CVE-2026-98432 (Linux IPv4 `inet_opt` / `ireq_opt` use-after-free) on Debian 12 Bookworm and Debian 13 Trixie (amd64). It only installs the official kernel update from Debian's APT repositories, never compiles kernels, never removes old kernels, never reboots automatically, and never touches SSH, firewall, network or application configs. Requirements: Debian 12/13, amd64, root. Run `sudo bash fix.sh --check` for a read-only assessment.

---

## 目录

- [漏洞背景](#漏洞背景)
- [修复版本对照表](#修复版本对照表)
- [支持范围](#支持范围)
- [检测逻辑](#检测逻辑)
- [修复原理](#修复原理)
- [安装与使用](#安装与使用)
- [重启要求与二次验证](#重启要求与二次验证)
- [退出码](#退出码)
- [测试](#测试)
- [常见错误处理](#常见错误处理)
- [已知限制与兼容性](#已知限制与兼容性)
- [项目结构](#项目结构)
- [License](#license)

---

## 漏洞背景

CVE-2026-98432 位于 Linux 内核 IPv4 协议栈：

- `tcp_v4_syn_recv_sock()` 会把 `ireq->ireq_opt` 的所有权转移给子 socket（`newinet->inet_opt`），但没有复制；
- 同一请求 socket 上重传的 SYN 可能由另一个 CPU 并发处理，`tcp_v4_send_synack()` / `inet_csk_route_req()` 只在 `rcu_read_lock()` 下读取该指针；
- 子 socket 不具备 `SOCK_RCU_FREE`，`inet_sock_destruct()` 用普通 `kfree()` 释放 `inet_opt`，于是 `ip_options_build()` 中出现**释放后使用（UAF）**；
- 请求 socket 迁移（`net.ipv4.tcp_migrate_req=1` 或 BPF `SK_REUSEPORT_SELECT_OR_MIGRATE`）路径上，`tcp_v4_reqsk_destructor()` 同样存在该问题。

上游修复将两处 `kfree()` 改为 `kfree_rcu()`。具体危害、利用条件与影响范围请以 Debian 安全公告和 CVE 记录为准。

- Debian Security Tracker: <https://security-tracker.debian.org/tracker/CVE-2026-98432>
- CVE 记录: <https://www.cve.org/CVERecord?id=CVE-2026-98432>

## 修复版本对照表

本项目的判定基线**逐一核对自 Debian Security Tracker**（核对日期：2026-11-01）：

| 发行版 | 源码包 | 内核分支 | 修复版本 | 官方公告 |
| --- | --- | --- | --- | --- |
| Debian 12 Bookworm | `linux` | 6.1 | `6.1.190-1` | [DLA-4841-1](https://security-tracker.debian.org/tracker/DLA-4841-1) |
| Debian 12 Bookworm | `linux-6.12` | 6.12 | `6.12.113-1~deb12u1` | [DLA-4850-1](https://security-tracker.debian.org/tracker/DLA-4850-1) |
| Debian 13 Trixie | `linux` | 6.12 | `6.12.113-1` | [DSA-6568-1](https://security-tracker.debian.org/tracker/DSA-6568-1) |

注意：

- 这三个版本**不能混用**。Debian 的回移版本 `6.12.113-1~deb12u1` 按 `dpkg` 规则**低于** `6.12.113-1`，用 trixie 的基线去判断 bookworm 会把已修复的机器误判为存在漏洞。
- 判定的是**正在运行的内核所对应的软件包版本**，不是「最新安装的版本」，也不是内核主版本号。
- 如果官方后续发布更高的修订版本（例如 `6.1.190-2`、`6.12.113-1~deb12u2`），脚本的 `>= 基线` 比较仍然成立；若基线本身被官方上调，请按 [更新修复基线](#更新修复基线) 修改。

## 支持范围

| 项目 | 支持情况 |
| --- | --- |
| Debian 12 (bookworm) | ✅ 支持，内核分支 6.1 / 6.12 |
| Debian 13 (trixie) | ✅ 支持，内核分支 6.12 |
| 架构 | ✅ `amd64` / `x86_64`；其他架构明确拒绝 |
| 其他发行版 | ❌ 明确拒绝（Ubuntu、Kali、Raspberry Pi OS 等一律不处理） |
| Debian testing / sid / 其他版本 | ❌ 明确拒绝（未纳入本项目核实范围） |

启动后会依次检查：root 权限、`/etc/os-release` 发行版与版本号、CPU 架构、运行内核版本、运行内核对应的 `linux-image` 软件包版本、APT 源配置与 security 源、待重启标记。任何一项无法确认都会给出提示并退出，**不会**在不确定的环境里修改系统。

## 检测逻辑

1. `uname -r` 取运行内核 release，例如 `6.1.0-49-amd64`、`6.12.113+deb13-amd64`。
2. 映射到软件包 `linux-image-<release>`，从 dpkg 数据库读出版本（回退方案：`dpkg -S /boot/vmlinuz-<release>`）。
3. 由 release 取 `major.minor` 得到内核分支（`6.1` / `6.12`）。
4. 按「发行版 + 分支」查上表得到修复版本。
5. 用 `dpkg --compare-versions` 比较（遵循 epoch、`~`、`+deb12u1` 等 Debian 版本规则）。
6. 输出四种状态之一：

| 状态 | 含义 | 退出码 |
| --- | --- | --- |
| 已修复 | 运行内核软件包版本 ≥ 官方修复版本 | 0 |
| 待重启 | 修复版本内核已安装，但仍运行旧内核 | 3 |
| 存在漏洞 | 运行内核版本低于修复版本 | 2 |
| 无法确认 | 分支未收录、软件包无法映射、信息不足 | 4 |

「无法确认」是**独立结果**，不会被当成「已修复」，也不会被当成「存在漏洞」——避免误报。

## 修复原理

确认存在漏洞后，脚本只做一件事：**从当前已配置的 Debian 官方源安装对应分支的内核元包**。

| 发行版 | 内核分支 | 目标元包 |
| --- | --- | --- |
| Debian 12 | 6.1 | `linux-image-amd64` |
| Debian 12 | 6.12 | `linux-image-6.12-amd64` |
| Debian 13 | 6.12 | `linux-image-amd64` |

- 运行 `-cloud-amd64` / `-rt-amd64` 内核时，自动选择 `linux-image-cloud-amd64` / `linux-image-6.12-rt-amd64` 等对应变体。
- 若元包候选版本不可用（例如镜像尚未同步），回退到同分支的具体镜像包并挑选 ≥ 修复版本的最高版本。
- 安装前会校验候选版本：**分支必须一致且版本必须 ≥ 修复版本**，否则直接退出，不会装一个「看起来成功」的旧内核。

执行顺序：`apt-get update` → 复核候选版本 → `apt-get install`（`--force-confdef/--force-confold`，不覆盖已有配置）→ 校验 dpkg 实际安装结果 → 校验 initramfs → 校验 GRUB → 输出重启提示。

**明确不会做的事**：

- ❌ 使用第三方内核源、自编译内核
- ❌ 删除旧内核
- ❌ 自动 `reboot`
- ❌ `apt-get upgrade` / `dist-upgrade` 升级无关软件包
- ❌ 修改 SSH、防火墙、网络、HAProxy、V2bX、Xray 等业务配置
- ❌ 把「apt 返回 0」当作「漏洞已修复」

## 安装与使用

### 1. 一键安装（推荐，普通用户）

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.0.0/fix.sh -o fix.sh && chmod +x fix.sh && sudo bash fix.sh
```

### 2. root 用户

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.0.0/fix.sh -o fix.sh && bash fix.sh
```

### 3. 不落地文件执行（带非空校验）

```bash
S="$(curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.0.0/fix.sh)" \
  && [ -n "$S" ] \
  && printf '%s' "$S" | sudo bash -s -- --check
```

`curl -f` 在 HTTP 错误时不输出内容，`[ -n "$S" ]` 再挡一道：**下载失败时不会执行任何内容**。去掉 `--check` 即为修复模式。

### 4. 先审查再运行（生产环境建议）

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.0.0/fix.sh -o fix.sh
less fix.sh            # 逐行审查
sha256sum fix.sh       # 与 Release 中的 SHA256SUMS 比对
sudo bash fix.sh --check
```

### 5. 参数

```
-c, --check       仅检测并输出状态，不修改系统（只读）
-y, --yes         跳过交互确认（无人值守场景）
-h, --help        显示帮助
-V, --version     显示版本
    --no-color    禁用彩色输出
```

默认运行时：展示环境与判定结果 → 展示修复计划 → 提示「即将更新 Linux 内核」→ 输入 `Y` 才继续。

交互确认从 `/dev/tty` 读取，因此 `curl ... | bash` 场景也能正常提问；无终端时（cron/CI）请显式使用 `--yes`，否则按取消处理。

## 重启要求与二次验证

内核安装成功后脚本**不会重启**，并会明确输出：

- 原运行内核版本
- 新安装内核版本
- 安装状态
- 是否需要重启（需要）
- 可复制的 `reboot` 命令

> 新内核已经安装，但当前服务器仍在运行旧内核。需要安排维护窗口重启服务器，才能让修复后的内核正式生效。重启前本机仍然受 CVE-2026-98432 影响。

重启后重新执行 `sudo bash fix.sh --check` 做二次验证，预期输出 `判定结果：已修复`（退出码 0）。

## 退出码

| 退出码 | 含义 |
| --- | --- |
| 0 | 已修复（或 `--help` / `--version` 正常结束） |
| 1 | 运行错误 / 环境不支持 / 安装或校验失败 |
| 2 | 存在漏洞（需要修复） |
| 3 | 待重启（修复内核已安装，仍运行旧内核） |
| 4 | 无法确认 |
| 5 | 用户取消 |

适合接入监控：`sudo bash fix.sh --check; echo $?`。

## 测试

```bash
bash tests/test.sh        # 静默模式
bash tests/test.sh -v     # 打印每个用例的完整输出
```

测试不依赖真实 Debian 机器，也不会改动本机：

- 在临时目录构造「假 Debian 文件系统」（`/etc/os-release`、`/etc/apt/sources.list`、`/boot`、`/var/lib/apt/lists`）；
- 通过 `PATH` 注入 `dpkg`、`dpkg-query`、`apt-get`、`apt-cache`、`uname`、`update-grub` 的模拟实现；
- 模拟器中的版本比较器按 dpkg 语义实现（epoch、`~`、数字段、修订号），并用已知向量校验；
- 修复流程只替换权限闸门（测试进程非 root），其余代码路径与生产完全一致。

覆盖的 26 个用例包括：Debian 12/13 识别、非 Debian 拒绝、非 root 提示、amd64 识别与 arm64 拒绝、已修复/受影响/待重启判定、`--check` 只读、`--help`/非法参数、用户取消、APT 更新失败、安装失败、initramfs 失败、GRUB 失败、完整修复流程、重启后二次验证、6.12 回移分支、未知分支、自编译内核、软件源缺修复版本、元包候选过旧回退、版本比较规则、基线匹配、静态安全检查。

静态检查：

```bash
shellcheck -S style fix.sh tests/test.sh
```

## 常见错误处理

| 提示 | 原因 | 处理 |
| --- | --- | --- |
| `需要 root 权限运行本脚本` | 非 root 执行 | 使用 `sudo bash fix.sh` |
| `不是 Debian，本工具拒绝执行` | Ubuntu / Kali / 衍生版等 | 本工具只处理 Debian，请按对应发行版公告升级内核 |
| `仅支持 Debian 12 (bookworm) 与 Debian 13 (trixie)` | 版本过新/过旧 | 手工按 <https://security-tracker.debian.org> 处理 |
| `仅支持 amd64` | arm64 / armhf 等 | 暂不支持，需手工升级内核 |
| `未发现 security 源` | sources.list 缺少 `*-security` | 补上 security 源后重试 |
| `软件源中未找到分支 6.1 且版本 >= 6.1.190-1 的内核包` | 镜像未同步 / 未启用 security 源 / 索引过期 | `apt-get update` 后重试；换官方源 `deb.debian.org` + `security.debian.org` |
| `apt-get update 执行失败` | 网络/代理/DNS/源不可达 | 修复网络后重试，脚本未做任何安装 |
| `内核安装失败` | `/boot` 空间不足、dpkg 锁、依赖损坏 | 看上方 APT 报错；`df -h /boot`、`dpkg --audit` |
| `未检测到有效的 initramfs` | `update-initramfs` 失败 | 手工 `update-initramfs -c -k <版本>`，再跑一次脚本 |
| `update-grub 执行失败` | GRUB 配置异常 | 检查 `/etc/default/grub`、`/etc/grub.d/`，手工 `update-grub` |
| `判定结果：无法确认` | 自编译内核 / 第三方内核 / 分支未收录 | 手工确认内核来源与官方公告 |
| `待重启` | 修复内核已装但未重启 | 安排维护窗口 `reboot` |

## 已知限制与兼容性

- **仅 amd64**：arm64/armhf 未纳入（内核包名与元包命名不同，未做验证，不做猜测）。
- **仅覆盖 6.1 与 6.12 分支**：其他分支（如 Debian 12 早期 5.10、testing 的 7.x）报告「无法确认」，不猜结论。
- **依赖 dpkg 数据库**：脱离 dpkg 管理的内核（自编译、第三方 deb 手工安装）无法判定。
- **不改用 backports/第三方源**：只认 `-security` 与 stable 源提供的版本。
- **GRUB 检测是文本匹配**：在 `grub.cfg` 中查找新内核 release 字符串；使用 systemd-boot 等引导器时只告警、不阻断。
- **不处理 livepatch**：内核 livepatch 场景不在范围内。
- **不自动重启**：这是设计选择，不是缺陷。
- **不检测「重启后是否又回退到旧内核」**：若引导顺序异常导致重启后仍进入旧内核，再次运行脚本仍会显示「存在漏洞」，请检查 GRUB 默认项。

### 更新修复基线

官方若上调修复版本，修改 `fix.sh` 中的 `fixed_version_for()`（并在 README 表格与 CHANGELOG 中同步），然后重跑 `bash tests/test.sh`。

## 项目结构

```
debian-cve-2026-98432-fix/
├── fix.sh              # 主脚本（检测 + 修复 + 二次验证）
├── README.md
├── CHANGELOG.md
├── LICENSE             # MIT
├── .gitignore
└── tests/
    ├── test.sh         # 26 个用例的测试入口
    └── lib/
        └── mocks.py    # dpkg / apt 模拟器 + Debian 版本比较
```

## License

[MIT](LICENSE) © 2026 Aron Wang
