# CVE-2026-98432 多发行版检测与修复工具

[![test](https://github.com/AronWang001/debian-cve-2026-98432-fix/actions/workflows/test.yml/badge.svg)](https://github.com/AronWang001/debian-cve-2026-98432-fix/actions/workflows/test.yml)

检测当前 Linux 发行版的**运行内核**是否受 CVE-2026-98432 影响，并仅在「官方修复包已核验 + 适配完成 + 用户确认」的发行版上执行内核更新。

> **English overview**: A Bash tool that maps the running kernel to its distribution package, checks CVE-2026-98432 against a manually verified advisory baseline, and installs the official kernel update only on distributions where the fixed package, repository channel, package manager flow and tests have all been verified. Everything else is detect-only and fails closed. Debian 12/13 and Amazon Linux 2/2023 support automatic remediation; Ubuntu and RHEL are detect-only because no fixed package has been published; Rocky, AlmaLinux, Oracle Linux, Fedora, SUSE, Arch and Alpine are detected but not enabled for automatic remediation. No reboot is ever performed automatically.

> **v1.1.0 的重要变化**：从「仅 Debian」扩展为多发行版。**能识别一个系统不等于支持自动修复** —— 请以本文的支持矩阵为准。

---

## 一、漏洞背景

| 项目 | 内容 |
|---|---|
| 编号 | CVE-2026-98432 |
| 位置 | Linux 内核 IPv4 子系统（`tcp_v4_syn_recv_sock` / `tcp_v4_reqsk_destructor`） |
| 类型 | 释放后使用（Use-After-Free），可导致内核内存破坏或系统崩溃 |
| 触发 | 并发处理重传的 TCP SYN，或启用 `tcp_migrate_req` 的请求套接字迁移 |
| 影响 | 远程攻击者可造成拒绝服务，严重时可致内存破坏（Red Hat 评为 Critical，CVSS 8.1–9.8，各发行版评分不同） |
| 上游修复 | `ipv4: free inet_opt and ireq_opt after an RCU grace period`（mainline 7.3-rc7） |
| 公开时间 | 2026-10-15 |

各发行版是否受影响、修复版本是什么，**必须分别以各自官方公告为准**，本工具不做跨发行版推导。

---

## 二、支持矩阵

基线核验日期：**2026-11-01**。可用 `sudo bash fix.sh --list-distros` 查看当前内置状态。

### 1. 支持自动检测 + 自动修复

| 发行版 | 内核分支 | 修复包命中方式 | 官方修复版本 | 官方公告 |
|---|---|---|---|---|
| Debian 12 (bookworm) | 6.1 | `linux-image-amd64` 等元包 | `6.1.190-1` | [DLA-4841-1](https://security-tracker.debian.org/tracker/DLA-4841-1) |
| Debian 12 (bookworm) | 6.12 | `linux-image-6.12-amd64` | `6.12.113-1~deb12u1` | [DLA-4850-1](https://security-tracker.debian.org/tracker/DLA-4850-1) |
| Debian 13 (trixie) | 6.12 | `linux-image-amd64` 等元包 | `6.12.113-1` | [DSA-6568-1](https://security-tracker.debian.org/tracker/DSA-6568-1) |
| Amazon Linux 2 | 4.14 | `kernel` | `4.14.355-287.758.amzn2` | [ALAS2-2026-4065](https://alas.aws.amazon.com/AL2/ALAS2-2026-4065.html) |
| Amazon Linux 2 | 5.4 | `kernel` | `5.4.302-229.503.amzn2` | [ALAS2KERNEL-5.4-2026-135](https://alas.aws.amazon.com/AL2/ALAS2KERNEL-5.4-2026-135.html) |
| Amazon Linux 2 | 5.10 | `kernel` | `5.10.271-272.1121.amzn2` | [ALAS2KERNEL-5.10-2026-137](https://alas.aws.amazon.com/AL2/ALAS2KERNEL-5.10-2026-137.html) |
| Amazon Linux 2 | 5.15 | `kernel` | `5.15.222-158.256.amzn2` | [ALAS2KERNEL-5.15-2026-120](https://alas.aws.amazon.com/AL2/ALAS2KERNEL-5.15-2026-120.html) |
| Amazon Linux 2023 | 6.1 | `kernel` | `6.1.189-236.400.amzn2023` | [ALAS2023-2026-3365](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3365.html) |
| Amazon Linux 2023 | 6.12 | `kernel6.12` | `6.12.113-138.209.amzn2023` | [ALAS2023-2026-3335](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3335.html) |
| Amazon Linux 2023 | 6.18 | `kernel6.18` | `6.18.56-125.164.amzn2023` | [ALAS2023-2026-3251](https://alas.aws.amazon.com/AL2023/ALAS2023-2026-3251.html) |

- Debian 仅支持 **amd64**；Amazon Linux 支持 **x86_64 与 aarch64**（公告同时覆盖两种架构）。
- AL2 与 AL2023 完全独立：AL2 的四个内核对全部使用包名 `kernel`，必须按完整 EVR 区分；AL2023 的 6.12/6.18 是独立包 `kernel6.12` / `kernel6.18`。
- Debian 12 的 `6.12.113-1~deb12u1` 是回移版本，**不得**与 Debian 13 的 `6.12.113-1` 混用。

### 2. 支持检测，但官方尚未发布修复包（只检测，不安装）

| 发行版 | 官方状态 | 官方页面 |
|---|---|---|
| Ubuntu 20.04 LTS (focal) | Vulnerable, work in progress in 5.15.0-203.213 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| Ubuntu 22.04 LTS (jammy) | Vulnerable, work in progress in 5.15.0-203.213 | 同上 |
| Ubuntu 24.04 LTS (noble) | Vulnerable, work in progress in 6.8.0-149.149 | 同上 |
| RHEL 8 | kernel / kernel-rt：`Affected`，`affected_release` 为空 | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |
| RHEL 9 | kernel / kernel-rt：`Affected`，`affected_release` 为空 | 同上 |
| RHEL 10 | kernel：`Affected`，`affected_release` 为空 | 同上 |

「work in progress」中的版本号是**仍在开发的分支版本**，不是修复版本，本工具不会把它当作修复基线。这类系统只输出状态，不调用任何安装命令。

### 3. 支持识别，但未完成自动修复适配（只检测）

| 发行版 | 未启用自动修复的原因 |
|---|---|
| Rocky Linux | Errata 站点为前端应用，未取得可机读的该 CVE 勘误；不按 RHEL 结论等同处理 |
| AlmaLinux | `errata.full.json` 中无该 CVE 记录，但「缺少勘误」不等于「确认未修复」 |
| Oracle Linux | UEK 与 RHCK 必须分别核验，本次未取得两者任一修复 EVR（已能区分两种内核） |
| Fedora Linux | 主线修复在 7.3-rc7；当前 kernel 7.2.14 是否回移无法确认 |
| openSUSE Leap / SUSE Linux Enterprise | 官方 CVE 页面拒绝自动访问（403），且存在多内核并存与启动项选择问题 |
| Arch Linux | 滚动发行版，安全追踪器无该 CVE 条目，不能用固定版本号判断 |
| Alpine Linux | secdb 中无该 CVE 记录，且 `linux-lts` / `linux-virt` / `linux-edge` 不可混为一谈 |

这些系统会完整输出：发行版、版本、架构、运行内核、对应的内核软件包与官方公告链接，但不允许进入安装路径。

### 4. 暂不支持

| 情况 | 行为 |
|---|---|
| 未收录的发行版（如 Gentoo） | `UNSUPPORTED`，退出码 1，不做任何修改 |
| Debian 12/13 以外的 Debian 版本 | `UNSUPPORTED`，退出码 1 |
| Debian 上的非 amd64 架构 | `UNSUPPORTED`，退出码 1 |
| 容器环境 | `UNKNOWN`，退出码 4（容器内的 `uname -r` 是宿主机内核，不可靠） |
| 自编译 / 第三方内核 | `UNKNOWN`，退出码 4 |

---

## 三、检测原理

1. **发行版识别**：解析 `/etc/os-release` 的 `ID`、`VERSION_ID`、`VERSION_CODENAME`，**不依赖 `ID_LIKE`** 折叠身份 —— Ubuntu 不会被当成 Debian，Rocky/AlmaLinux/Oracle 不会被当成 RHEL。发行版专属信息再进一步区分：Oracle 用 `uek` 标记区分 UEK 与 RHCK，Amazon Linux 用 `VERSION_ID`（2 / 2023）区分 AL2 与 AL2023。
2. **架构**：`uname -m` 规范化（`x86_64→amd64`、`aarch64→arm64`），再与包管理器报告的架构交叉确认；不一致时判为 `UNKNOWN`。
3. **内核 → 软件包映射**：不是只看 `uname -r`，也不是取「机器上最新的内核包」，而是把运行内核精确映射到已安装的软件包：
   - Debian：`dpkg-query -W linux-image-<release>`，回退 `dpkg -S /boot/vmlinuz-<release>`；
   - RPM 系：`rpm -qa` 取 `version-release`，与 `uname -r` 的 `<version>-<release>.<arch>` 精确匹配（排除 devel/headers/tools/modules/debug/livepatch 等）；
   - Alpine：按实际 flavor（`linux-lts` / `linux-virt` / `linux-edge`）匹配 `apk` 版本；
   - Arch：按实际 flavor 匹配 `pacman` 的 `pkgver-pkgrel`。
4. **漏洞判定**：按「发行版 + 版本 + 内核分支」查本地已核验基线（`data/cve-2026-98432.yml`），用**对应包管理器语义**比较版本：
   - Debian/Ubuntu：`dpkg --compare-versions`
   - RPM/SUSE：`epoch:version-release` 的 rpmvercmp 语义
   - Alpine：`-rN` 修订号与 `_alpha/_beta/_pre/_rc/_p` 后缀
   - Arch：`pkgver-pkgrel`
5. **状态机**：输出六个状态之一（见下一节），并把状态映射为退出码。

**基线的性质**：`data/cve-2026-98432.yml` 是**人工核验后维护**的版本基线，不是实时在线同步。每条记录都带 `verified`（核验日期）、`advisory`（公告编号）、`advisory_url`、`autofix` 与 `notes`。核验日期在输出与 `--report` 中都会显示。

---

## 四、状态机与退出码

| 状态 | 含义 | 退出码 |
|---|---|---|
| `FIXED` | 当前**运行**内核已达到官方修复标准 | 0 |
| `PENDING_REBOOT` | 修复内核已安装，但仍在运行旧内核 | 3 |
| `VULNERABLE_PATCH_AVAILABLE` | 官方修复包可用且可获取，当前内核仍受影响 | 2 |
| `PATCH_NOT_RELEASED` | 官方尚未发布可确认的修复包，只展示，不安装 | 6 |
| `UNKNOWN` | 公告、内核来源、包映射或版本无法确认 | 4 |
| `UNSUPPORTED` | 系统、版本、架构或内核 flavor 不支持 | 1 |

补充约定：

- `PATCH_NOT_RELEASED` 绝不会显示为 `FIXED`；
- `UNKNOWN` 绝不会升级为 `VULNERABLE_PATCH_AVAILABLE`；
- 只有 `VULNERABLE_PATCH_AVAILABLE` **且** adapter 显式允许自动修复时，才会进入安装流程；
- 已安装修复内核但未重启，一律显示 `PENDING_REBOOT`；
- 用户取消返回 5。

---

## 五、自动修复原理

仅在 Debian 12/13 与 Amazon Linux 2/2023 上可用，流程固定为：

1. 显示当前系统、运行内核、检测结果与**官方公告依据**；
2. 显示计划安装的包名、目标版本、仓库来源、预计变更的包与重启要求；
3. 用户输入 `Y` 确认（`--yes` 只跳过确认，**不能**绕过发行版白名单、公告核验与版本校验）；
4. 刷新元数据（`apt-get update` / `dnf makecache` / `yum makecache`）；
5. **再次**校验候选版本：必须分支一致且 ≥ 修复基线；
6. 只安装内核相关包（`apt-get install <内核包>` / `dnf install <包>-<EVR>`），不做全系统升级；
7. 回查包数据库（dpkg / rpm）确认真实安装版本；
8. 校验内核镜像、initramfs（`/boot/initrd.img-*` 或 `/boot/initramfs-*.img`）；
9. 识别实际 bootloader（GRUB / GRUB2 / systemd-boot）并检查启动项；
10. 输出重启提示，**不自动重启**。

安全边界（硬性）：

- 只使用发行版官方源或用户已配置的仓库，不新增第三方源、不下载来源不明的内核、不自行编译；
- 不删除旧内核、不自动重启、不做不必要的全系统升级；
- 不修改 SSH、防火墙、网络、HAProxy、V2bX、Xray 或任何业务配置；
- 包管理器返回 0 不等于修复成功 —— 必须通过包数据库与引导配置复核；
- RPM 系不会擅自重建引导配置（避免破坏云厂商启动项），缺失启动项时停止并给出人工命令。

---

## 六、安装与使用

> **v1.1.0 起入口仍是 `fix.sh`，但它会加载同目录下的 `lib/`、`adapters/`、`data/`。**
> 因此**不能只下载单个 `fix.sh`**，请使用下面的引导安装器或整包克隆。

### 方式一：引导安装器（固定 v1.1.0 Tag，推荐）

引导脚本会下载该 Tag 的完整包到临时目录、校验 `fix.sh` 的 SHA256，然后以相同参数调用 `fix.sh`：

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.1.0/install.sh -o install.sh
less install.sh                       # 先审查
sudo bash install.sh --check          # 只读体检
sudo bash install.sh                  # 交互式修复（仅白名单发行版）
```

不落地执行（下载失败时不会执行任何内容）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/AronWang001/debian-cve-2026-98432-fix/v1.1.0/install.sh) --check
```

### 方式二：整包克隆后本地执行

```bash
git clone --branch v1.1.0 --depth 1 https://github.com/AronWang001/debian-cve-2026-98432-fix.git
cd debian-cve-2026-98432-fix
sudo bash fix.sh --check              # 只读体检
sudo bash fix.sh                      # 交互式修复（仅白名单发行版）
```

### 校验下载完整性

Release 页面提供 `SHA256SUMS`：

```bash
curl -fsSLO https://github.com/AronWang001/debian-cve-2026-98432-fix/releases/download/v1.1.0/SHA256SUMS
sha256sum -c SHA256SUMS
```

> 请固定在 `v1.1.0` Tag 上执行。不要直接使用 `main` 分支的原始文件：`main` 可能包含尚未发布的改动。
> 下载失败时 `&&` 会短路，不会执行空脚本；执行前请先阅读脚本内容。

### 参数

| 参数 | 说明 |
|---|---|
| `-c`, `--check` | 只读检测，不刷新索引、不安装、不修改系统 |
| `-y`, `--yes` | 跳过交互确认（不能绕过白名单与版本校验） |
| `--list-distros` | 显示支持矩阵：检测支持 / 自动修复支持 / 官方补丁状态 / 核验日期 |
| `--report [文件]` | 生成检测报告（不含密码、令牌、私钥），默认写入当前目录 |
| `--no-color` | 禁用彩色输出（日志采集场景） |
| `-h`, `--help` | 帮助 |
| `-V`, `--version` | 版本信息 |

### 典型用法

```bash
sudo bash fix.sh --check          # 体检：当前是否受影响、官方是否已修复
sudo bash fix.sh --report         # 生成报告，便于工单留档
sudo bash fix.sh                  # 交互式修复（仅白名单发行版）
sudo bash fix.sh --list-distros   # 查看各发行版支持状态
```

### 二次验证

重启后重新执行：

```bash
sudo bash fix.sh --check
```

- 显示 `FIXED` 才算修复完成；
- 仍显示 `PENDING_REBOOT` 或仍运行旧内核时，请检查 bootloader 默认启动项、云厂商启动配置（如 GRUB 默认项、`grubenv`、实例的启动参数）。

---

## 七、重启要求

**内核安装成功 ≠ 漏洞已修复。** 新内核安装后，服务器仍在运行旧内核，必须安排维护窗口重启：

```bash
reboot
```

本工具**永远不会**自动重启服务器。重启前主机仍受 CVE-2026-98432 影响。

---

## 八、测试

测试全部在隔离环境执行，不在生产服务器上安装旧内核、卸载内核或模拟漏洞。

| 套件 | 用例数 | 覆盖内容 |
|---|---|---|
| `tests/test.sh` | 26 | v1.0.0 的 Debian 回归：环境识别、四态判定、APT 更新/安装/initramfs/GRUB 失败、`--check`、取消、完整安装、回移分支、版本比较、静态检查 |
| `tests/test_detection.sh` | 16 | Ubuntu 20.04/22.04/24.04、RHEL 8/9/10、Rocky/Alma 区分、Oracle UEK/RHCK 区分、AL2/AL2023 区分、Fedora/SUSE/Arch/Alpine 识别、x86_64/aarch64、架构拒绝、未修复不安装、公告不可达、缺基线、容器、空 APT 索引不中断、`--list-distros`/`--report` |
| `tests/test_amazon_linux.sh` | 11 | AL2 4.14/5.10/5.15 与 AL2023 6.1/6.12/6.18 独立基线、完整安装、dnf 失败、initramfs 缺失、取消 |
| `tests/test_version.sh` | 5 | RPM EVR（epoch/release/波浪号）、apk 修订号与后缀、pacman、dpkg 回移、未知家族 |
| `tests/test_safety.sh` | 8 | 非白名单发行版 `--yes` 也不安装、`--check` 只读、`--report` 无副作用、adapter 能力声明、白名单最小化、静态扫描 |

测试环境：

- 本地：Windows + Git Bash，构造假根目录 + PATH 注入 `dpkg/apt/rpm/dnf/yum/apk/pacman/uname` 模拟实现；
- CI：ubuntu-latest 运行全部套件与 ShellCheck 0.11.0；
- **真实发行版容器**（只读识别冒烟）：Debian 12/13、Ubuntu 22.04/24.04、Rocky 9、AlmaLinux 9、Fedora、openSUSE Leap 15.6、Alpine 3.20、Arch、Amazon Linux 2/2023。

**测试限制**：容器测试只验证发行版识别与容器内的 fail closed，不能替代真实内核启动验证；Amazon Linux 的 dnf 安装流程、重启后生效、bootloader 行为由模拟测试覆盖，**未在真实 AWS 实例上执行内核安装**。详见「已知限制」。

---

## 九、已知限制

1. **基线是人工维护的**：`data/cve-2026-98432.yml` 记录核验日期，不做实时在线解析；公告更新后需人工复核并更新基线。
2. **自动修复仅覆盖 Debian 12/13 与 Amazon Linux 2/2023**；其余发行版只检测。未完成真实内核安装验证的发行版不会被标记为「完整支持」。
3. **架构**：Debian 仅 amd64；Amazon Linux 覆盖 x86_64/aarch64；其余发行版在检测层面识别 amd64/arm64。
4. **容器内不判定**：容器中的 `uname -r` 是宿主机内核，工具会明确返回 `UNKNOWN`。
5. **自编译/第三方内核**无法映射到发行版软件包，返回 `UNKNOWN`，不会猜测。
6. **livepatch 不处理**：Amazon Linux 的 `kernel-livepatch` 不在判定范围内，修复以重启进入新内核为准。
7. **RPM 系不自动重建引导配置**：缺失启动项时停止并给出手工命令。
8. **发行版衍生关系不继承**：Rocky/AlmaLinux/Oracle 不沿用 RHEL 结论，Oracle UEK 与 RHCK 分别判断。

---

## 十、安全注意事项

- 脚本需要 root 权限，请从**本仓库的固定 Tag** 下载并先审查内容；
- 校验下载文件（见 Release 页面的 `SHA256SUMS`）：

```bash
sha256sum -c SHA256SUMS
```

- 不要把本工具放进无人值守的定时任务里自动重启；它不会自动重启，也不应该被包装成自动重启；
- 生产环境建议先在同等配置的测试机执行 `--check` 与一次真实升级；
- 若官方公告与本工具基线不一致，**以官方公告为准**，并等待基线更新。

---

## 十一、常见错误处理

| 现象 | 原因 | 处理 |
|---|---|---|
| `UNKNOWN` + 「无法映射到已安装的内核软件包」 | 自编译内核、第三方内核，或容器环境 | 使用发行版官方内核；容器请到宿主机执行 |
| `UNSUPPORTED` + 「不在本工具支持的发行版列表中」 | 发行版未收录 | 参考官方公告手工处理，或用 `--list-distros` 查看支持范围 |
| `PATCH_NOT_RELEASED` | 官方尚未发布修复包 | 关注官方公告；发布后更新基线再执行 |
| 「软件源中未找到分支 X 且版本 >= Y 的内核包」 | 未启用 security 源 / 索引过期 | 检查发行版官方源配置后重试 |
| `apt-get update 执行失败` | 网络或源配置问题 | 按提示检查网络与 `/etc/apt/sources.list` |
| `未检测到有效的 initramfs` | 内核包 postinst 未完成 | 按提示执行 `update-initramfs -c -k <release>`，或 RPM 系 `dracut -f` |
| `GRUB 配置中未找到新内核` | 引导配置未更新 | Debian 会自动重试 `update-grub`；RPM 系请手工执行 `grub2-mkconfig` |
| `需要 root 权限运行本脚本` | 未使用 sudo | 使用 `sudo bash fix.sh` |

---

## 十二、更新基线

1. 打开对应官方公告（Debian Security Tracker / ALAS / Ubuntu / Red Hat / …）；
2. 确认 **内核包名、EVR、仓库渠道、架构** 四项；
3. 修改 `data/cve-2026-98432.yml` 中对应记录的 `fixed_version`、`advisory`、`advisory_url`、`verified`、`notes`；
4. 只有完成适配与测试后，才把 `autofix` 改为 `yes`；
5. 运行全部测试并更新 `CHANGELOG.md`。

---

## 十三、项目结构

```
install.sh                  引导安装器：下载指定 Tag 的整包、校验 SHA256、转调 fix.sh
fix.sh                      入口：参数、流程编排、状态机出口
lib/
  common.sh                 退出码、颜色、日志、路径、容器识别
  detect.sh                 发行版/版本/架构/内核识别
  version.sh                dpkg / rpm / apk / pacman 版本比较
  advisory.sh               基线加载与查询
  kernel.sh                 运行内核 ↔ 软件包映射
  package_manager.sh        apt / dnf / yum 抽象
  install.sh                计划、安装、安装后校验、重启提示
  status.sh                 六态状态机
  report.sh                 --list-distros 与 --report
adapters/                   11 个发行版 adapter（身份 + 能力声明）
data/cve-2026-98432.yml     已核验的官方修复基线（含核验日期与公告链接）
tests/                      5 个测试套件 + 模拟器 + 容器冒烟
```

---

## 十四、License

MIT License，见 [LICENSE](LICENSE)。

本项目与 Debian、Canonical、Amazon、Red Hat、SUSE、Arch、Alpine 等项目无隶属关系，仅为运维工具。
