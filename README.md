# CVE-2026-98432 检测与修复工具

**简体中文** | [English](README.en.md)

检测 Linux 服务器当前运行的内核是否受 CVE-2026-98432 影响，并在已完成适配与核验的发行版上安装官方修复内核包。工具覆盖发行版识别、内核到软件包的映射、漏洞状态判定、内核安装与安装后复核，不修改业务配置，不自动重启服务器。

自动修复仅覆盖 Debian 12/13 与 Amazon Linux 2/2023。Ubuntu 与 Red Hat Enterprise Linux 只做检测，官方尚未发布可确认的修复包。其余发行版只做识别与信息输出，不进入安装流程。具体状态见[发行版支持矩阵](#发行版支持矩阵)。

当前版本 v1.1.2，变更记录见 [CHANGELOG.md](CHANGELOG.md)。

## 漏洞背景

| 项目 | 内容 |
| --- | --- |
| 编号 | CVE-2026-98432 |
| 组件 | Linux 内核 IPv4 子系统（`tcp_v4_syn_recv_sock`、`tcp_v4_reqsk_destructor`） |
| 类型 | 释放后使用（use-after-free） |
| 触发条件 | 并发处理重传的 TCP SYN，或启用 `tcp_migrate_req` 的请求套接字迁移时，`inet_opt` 与 `ireq_opt` 可能在 RCU 宽限期结束前被释放 |
| 影响 | 内核内存破坏，可导致拒绝服务。具体影响范围与利用条件以各发行版公告为准 |
| 上游修复 | `ipv4: free inet_opt and ireq_opt after an RCU grace period`（mainline 7.3-rc7） |
| 公开时间 | 2026-10-15 |

各发行版是否受影响、修复版本是多少，以该发行版的官方公告为准。本工具不依据其他发行版的结论推导，也不根据上游版本号推断发行版修复状态，不评估 CVSS 分数与实际攻击复杂度。

## 主要功能

- 发行版识别：读取 `/etc/os-release` 的 `ID`、`VERSION_ID`、`VERSION_CODENAME`，并叠加发行版专属信息（如 Oracle 的 UEK 标记、Amazon Linux 的版本号）。不使用 `ID_LIKE` 折叠身份，Ubuntu 不会被当作 Debian，Rocky Linux、AlmaLinux、Oracle Linux 不会被当作 RHEL。
- 架构识别：规范化 `uname -m` 的结果（`x86_64` 记为 `amd64`、`aarch64` 记为 `arm64`），再与包管理器报告的架构交叉核对；不一致时判定为 `UNKNOWN`。
- 内核映射：把运行内核精确映射到已安装的内核软件包，而不是取机器上最新的内核包。
- 状态判定：按发行版、版本、内核分支查询本地核验基线，并使用对应包管理器的版本比较语义。
- 自动修复：仅在白名单发行版上安装官方修复内核，安装后回查包数据库、内核镜像、initramfs 与启动项。
- 报告输出：`--report` 生成检测结论与依据，`--list-distros` 输出支持矩阵。

## 系统要求

- 操作系统：自动修复支持 Debian 12 (bookworm)、Debian 13 (trixie)、Amazon Linux 2、Amazon Linux 2023；检测支持 Ubuntu 20.04/22.04/24.04、RHEL 8/9/10；识别支持 Rocky Linux、AlmaLinux、Oracle Linux、Fedora、openSUSE Leap、SUSE Linux Enterprise、Arch Linux、Alpine Linux。发行版版本不在适配范围内时返回 `UNSUPPORTED`。
- 架构：自动修复会校验架构，Debian 仅 amd64，Amazon Linux 2/2023 为 x86_64 与 aarch64。检测与识别型发行版不做架构拦截，但仍要求运行内核能映射到发行版软件包。
- 权限：需要 root。仅 `--list-distros` 可以普通用户执行。
- 依赖：Bash 4.0 及以上、coreutils、`awk`、`sed`、`grep`、`tar`、`find`；发行版对应的包管理工具（`dpkg`/`apt-get`/`apt-cache`、`rpm`/`dnf`/`yum`、`apk`、`pacman`、`zypper`）；引导安装器额外需要 `curl` 与 `sha256sum`（或 `shasum`）。
- 网络：需要访问发行版官方软件源；使用引导安装器时还需要访问 GitHub。

## 安装与执行

### 一键执行

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash
```

`install.sh` 是引导安装器，本身不修改系统：它把对应 Tag 的源码归档下载到临时目录，解包后校验 `fix.sh` 的哈希，然后以相同参数执行 `fix.sh`。检测完成后显示修复计划，输入 `Y` 确认才安装内核。确认提示从 `/dev/tty` 读取，管道执行也能正常交互；`sudo` 可能要求输入密码。

校验范围有限：只比对 Release 中 `SHA256SUMS` 记录的 `fix.sh` 哈希，归档包整体以及 `lib/`、`adapters/`、`data/` 等文件不逐一校验。`SHA256SUMS` 无法获取时跳过校验并给出警告；系统缺少 `sha256sum` 与 `shasum` 时同样跳过；哈希不一致时直接中止，不执行任何系统操作。正式环境使用前建议先下载脚本自行审查。

### 只读检查

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash -s -- --check
```

只读取系统状态，不刷新包索引、不安装软件包、不修改配置。`--check` 约束的是检测与修复阶段，不影响 `install.sh` 自身的下载行为。本地包索引为空时，候选版本会显示为未知，需要先自行执行 `apt-get update` 或 `dnf makecache`。

### 免交互执行

```bash
curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash -s -- --yes
```

`--yes` 只跳过确认提示，不跳过发行版白名单、公告核验与版本校验。非白名单发行版即使指定 `--yes` 也不会进入安装流程。

### 下载后审查再执行

```bash
curl -fsSLO https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh
less install.sh
sudo bash install.sh --check
sudo bash install.sh
```

### 克隆仓库后执行

`fix.sh` 依赖同目录的 `lib/`、`adapters/` 与 `data/`，不能单独下载使用：

```bash
git clone --branch v1.1.2 --depth 1 https://github.com/AronWang001/linux-cve-2026-98432-fix.git
cd linux-cve-2026-98432-fix
sudo bash fix.sh --check
sudo bash fix.sh
```

### 校验发布包

`SHA256SUMS` 同时记录 `fix.sh` 与 `install.sh`，两个文件都要放在同一目录才能完成校验：

```bash
mkdir -p /tmp/cve-verify && cd /tmp/cve-verify
base=https://github.com/AronWang001/linux-cve-2026-98432-fix/releases/download/v1.1.2
curl -fsSLO "${base}/SHA256SUMS"
curl -fsSLO "${base}/install.sh"
curl -fsSLO "${base}/fix.sh"
sha256sum -c SHA256SUMS
```

正常输出为 `fix.sh: OK` 与 `install.sh: OK`。系统没有 `sha256sum` 时可用 `shasum -a 256 -c SHA256SUMS`。

## 参数与退出码

### 参数

| 参数 | 说明 |
| --- | --- |
| `-c`, `--check` | 只读检测：不刷新索引、不安装软件包、不修改系统 |
| `-y`, `--yes` | 跳过交互确认，不能绕过白名单、公告核验与版本校验 |
| `--list-distros` | 输出支持矩阵：检测支持、自动修复支持、官方补丁状态、核验日期。不需要 root |
| `--report [文件]` | 生成检测报告，默认写入当前目录的 `cve-2026-98432-report-<时间戳>.txt`；报告不含密码、令牌与私钥 |
| `--no-color` | 禁用彩色输出，适合日志采集 |
| `-h`, `--help` | 显示帮助 |
| `-V`, `--version` | 显示版本信息 |

### 退出码

| 状态 | 含义 | 退出码 |
| --- | --- | --- |
| `FIXED` | 当前运行内核已达到官方修复版本 | 0 |
| `PENDING_REBOOT` | 修复内核已安装，但仍运行旧内核 | 3 |
| `VULNERABLE_PATCH_AVAILABLE` | 官方修复包可用，运行内核仍受影响 | 2 |
| `PATCH_NOT_RELEASED` | 官方尚未发布可确认的修复包，只输出状态，不安装 | 6 |
| `UNKNOWN` | 公告、内核来源、包映射或版本无法确认 | 4 |
| `UNSUPPORTED` | 系统、版本、架构或内核 flavor 不受支持 | 1 |
| 用户取消 | 确认阶段输入非 `y`，系统未做修改 | 5 |
| 运行错误 | 缺少依赖、非 root、参数错误、安装或校验失败 | 1 |

只有状态为 `VULNERABLE_PATCH_AVAILABLE`、适配层允许自动修复且基线记录 `autofix: yes` 时，才会进入安装流程。退出码 1 同时用于不支持的环境和运行期错误，区分依据是输出中的判定结果。

### 重启后复检

内核安装完成后，运行内核仍是旧内核，需要安排重启：

```bash
sudo reboot
```

重启后重新执行 `--check`，判定为 `FIXED` 才算修复完成。若仍显示 `PENDING_REBOOT` 或仍运行旧内核，检查引导程序默认启动项、`grubenv` 与云厂商的启动配置。

## 发行版支持矩阵

基线核验日期为 2026-11-01。数据来自各发行版官方公告与安全追踪器，人工核对后写入 `data/cve-2026-98432.yml`，不是实时在线同步。执行 `sudo bash fix.sh --list-distros` 可查看工具内置的当前状态，普通用户直接执行 `bash fix.sh --list-distros` 也可以。

### 自动检测与自动修复

| 发行版 | 内核分支 | 内核包 | 官方修复版本 | 官方公告 |
| --- | --- | --- | --- | --- |
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

Debian 12 的 `6.12.113-1~deb12u1` 是回移版本，不与 Debian 13 的 `6.12.113-1` 混用。Amazon Linux 2 的四个分支包名都是 `kernel`，按完整 EVR 区分；Amazon Linux 2023 的 6.12 与 6.18 是独立包 `kernel6.12`、`kernel6.18`，基线互不通用。

### 仅检测：官方尚未发布修复包

| 发行版 | 官方状态 | 官方页面 |
| --- | --- | --- |
| Ubuntu 20.04 LTS | Vulnerable, work in progress in 5.15.0-203.213 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| Ubuntu 22.04 LTS | Vulnerable, work in progress in 5.15.0-203.213 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| Ubuntu 24.04 LTS | Vulnerable, work in progress in 6.8.0-149.149 | [Ubuntu CVE](https://ubuntu.com/security/CVE-2026-98432) |
| RHEL 8 | kernel 与 kernel-rt 均为 `Affected`，`affected_release` 为空 | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |
| RHEL 9 | kernel 与 kernel-rt 均为 `Affected`，`affected_release` 为空 | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |
| RHEL 10 | kernel 为 `Affected`，`affected_release` 为空 | [Red Hat CVE](https://access.redhat.com/security/cve/cve-2026-98432) |

表中 work in progress 的版本号是仍在开发的包版本，不是已发布的修复包，工具不会把它当作修复基线。这些系统返回 `PATCH_NOT_RELEASED`（退出码 6），只输出状态，不调用安装命令。

### 仅识别：状态无法确认

| 发行版 | 未启用自动修复的原因 |
| --- | --- |
| Rocky Linux | Errata 站点为前端应用，未取得该 CVE 的可机读勘误；不按 RHEL 结论等同处理 |
| AlmaLinux | `errata.full.json` 中无该 CVE 记录，缺少勘误不等于确认未修复 |
| Oracle Linux | UEK 与 RHCK 需分别核验，目前未取得任一内核的修复 EVR |
| Fedora Linux | 上游修复位于 mainline 7.3-rc7，当前发行版内核是否回移无法确认 |
| openSUSE Leap / SUSE Linux Enterprise | 官方 CVE 页面拒绝自动访问，且存在多内核并存与启动项选择问题 |
| Arch Linux | 滚动发行版，安全追踪器无该 CVE 条目，不能用固定版本号判断 |
| Alpine Linux | secdb 中无该 CVE 记录，且 `linux-lts`、`linux-virt`、`linux-edge` 不可混为一谈 |

这些系统会输出发行版、版本、架构、运行内核、对应内核软件包与官方公告入口，状态为 `UNKNOWN`（退出码 4），不进入安装路径。

### 不支持的情况

| 情况 | 行为 |
| --- | --- |
| 未收录的发行版 | `UNSUPPORTED`，退出码 1，不做任何修改 |
| 适配范围外的版本（如 Debian 11、Ubuntu 18.04） | `UNSUPPORTED`，退出码 1 |
| 自动修复型发行版上的架构不符 | `UNSUPPORTED`，退出码 1，例如 Debian 上的 arm64 |
| 容器环境 | `UNKNOWN`，退出码 4。容器内的 `uname -r` 是宿主机内核，不能作为判定依据 |
| 自编译或第三方内核 | `UNKNOWN`，退出码 4 |

## 检测与修复流程

### 判定步骤

1. 解析 `/etc/os-release` 与发行版专属信息，确定发行版、版本与内核 flavor。
2. 规范化架构，并与包管理器报告的架构交叉核对。
3. 将运行内核映射到已安装的内核软件包，读取其版本。
4. 查询 `data/cve-2026-98432.yml` 中对应的核验记录，取得修复版本、公告编号与是否允许自动修复。
5. 用对应包管理器的版本语义比较运行内核与修复版本，输出六种状态之一。

### 修复步骤

1. 输出当前系统、运行内核、判定结果与官方公告依据。
2. 输出计划安装的包名、目标版本、软件源与预计变更。
3. 等待用户确认，`--yes` 跳过此步。
4. 刷新包管理器元数据（`apt-get update`、`dnf makecache` 或 `yum makecache`）。
5. 再次校验候选版本，要求分支一致且不低于修复基线。
6. 只安装内核相关包，不执行全系统升级。
7. 回查包数据库，确认真实安装的版本与内核镜像。
8. 校验 initramfs（`/boot/initrd.img-*` 或 `/boot/initramfs-*.img`）。
9. 识别实际使用的引导程序（GRUB、GRUB2 或 systemd-boot），检查启动项是否包含新内核。
10. 输出重启提示，不自动重启。

包管理器返回 0 不作为成功依据。包数据库或内核镜像校验不通过、initramfs 缺失、启动项未包含新内核且无法自动修复时，以退出码 1 结束并给出手工排查命令；完全未识别到引导程序时只给出警告，需在重启前自行确认启动项。

### 安全边界

工具的行为边界：

- 只使用发行版官方源或用户已配置的仓库，不新增第三方源，不编译内核。
- 不删除旧内核，不执行全系统升级，不自动重启。
- 不修改 SSH、防火墙、网络、代理或业务配置。
- RPM 系不重建引导配置；启动项缺失时停止并输出手工命令。
- `--check` 不修改系统；`--report` 只额外写入一个报告文件，字段取自白名单，不含凭据。

使用前须知：

- 一键命令以 root 身份下载并执行远程脚本。脚本来源为 GitHub 仓库与 Release，传输过程使用 HTTPS，但不提供代码签名。生产环境建议先下载、审查，再执行。
- 内核更新涉及重启，会影响在线业务，应在维护窗口执行。生产环境建议先在同等配置的测试机上执行 `--check`，并完成一次真实升级后再推广。
- 安装修复内核不等于漏洞已修复。重启进入新内核并重新检测为 `FIXED` 才算完成。
- 修复基线由人工维护，官方公告与基线不一致时以官方公告为准，等基线更新后再执行。

## 测试

### 测试套件

| 套件 | 用例数 | 覆盖内容 |
| --- | --- | --- |
| `tests/test.sh` | 26 | Debian 回归：环境识别、状态判定、包索引刷新与安装失败、initramfs 与引导失败、`--check`、用户取消、完整安装、回移分支、版本比较、静态检查 |
| `tests/test_detection.sh` | 16 | Ubuntu 20.04/22.04/24.04、RHEL 8/9/10、Rocky 与 AlmaLinux 区分、Oracle UEK 与 RHCK 区分、AL2 与 AL2023 区分、Fedora/SUSE/Arch/Alpine 识别、x86_64 与 aarch64、架构拒绝、未修复不安装、公告不可达、缺少基线、容器环境、空 APT 索引不中断、`--list-distros` 与 `--report` |
| `tests/test_amazon_linux.sh` | 11 | AL2 4.14/5.10/5.15 与 AL2023 6.1/6.12/6.18 的独立基线、完整安装、dnf 失败、initramfs 缺失、用户取消 |
| `tests/test_version.sh` | 5 | RPM EVR（epoch、release、`~`）、apk 修订号与后缀、pacman、dpkg 回移版本、未知版本家族 |
| `tests/test_safety.sh` | 8 | 非白名单发行版指定 `--yes` 也不安装、`--check` 只读、`--report` 无副作用、适配层能力声明完整、白名单最小化、静态扫描 |

合计 66 个用例。

### 测试环境

- 本地：Windows + Git Bash，构造假根目录并注入 `dpkg`、`apt-get`、`rpm`、`dnf`、`yum`、`apk`、`pacman`、`uname` 的模拟实现。
- CI：GitHub Actions 执行 5 个测试套件与 ShellCheck 0.11.0（`-S style -x`），另有 12 个发行版容器的只读识别冒烟任务。
- 容器冒烟覆盖：Debian 12/13、Ubuntu 22.04/24.04、Rocky Linux 9、AlmaLinux 9、Fedora、openSUSE Leap 15.6、Alpine 3.20、Arch Linux、Amazon Linux 2/2023。

### 测试未覆盖的部分

测试使用模拟的包管理器输出，验证判定逻辑、安装流程与失败处理，不执行真实内核安装。容器冒烟只验证发行版识别与容器内的拒绝行为（`UNKNOWN`），不验证内核升级、initramfs 生成、引导项更新与重启后生效。Amazon Linux 的完整流程未在真实 AWS 实例上执行过。

## 已知限制

1. 自动修复仅覆盖 Debian 12/13 与 Amazon Linux 2/2023，其余发行版只做检测或识别。
2. 未在真实 AWS 实例上执行 Amazon Linux 的内核安装；其 `dnf`/`yum` 流程、重启后生效与引导行为由模拟测试覆盖。
3. Debian 仅支持 amd64；其他发行版的自动修复能力以支持矩阵为准。
4. 容器环境不判定，返回 `UNKNOWN`。
5. 自编译或第三方内核无法映射到发行版软件包，返回 `UNKNOWN`。
6. Amazon Linux 的 `kernel-livepatch` 不在判定范围内，修复以重启进入新内核为准。
7. RPM 系不自动重建引导配置，启动项缺失时停止并给出人工命令。
8. 发行版衍生关系不继承结论，Rocky Linux、AlmaLinux、Oracle Linux 不使用 RHEL 的判定结果。
9. 基线更新需要人工核对官方公告后提交，工具本身不抓取公告。

## 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `UNKNOWN`，提示无法映射到已安装的内核软件包 | 自编译内核、第三方内核，或在容器内执行 | 使用发行版官方内核；容器请在宿主机执行 |
| `UNSUPPORTED`，提示不在支持的发行版或版本范围内 | 发行版未收录，或版本超出适配范围 | 参考官方公告手工处理，或用 `--list-distros` 查看支持范围 |
| `PATCH_NOT_RELEASED` | 官方尚未发布修复包 | 关注官方公告，发布后更新基线再执行 |
| 提示软件源中未找到满足版本要求的内核包 | 未启用 security 源或索引过期 | 检查发行版官方源配置，执行 `apt-get update` 或 `dnf makecache` 后重试 |
| `apt-get update 执行失败` | 网络或源配置问题 | 按提示检查网络与 `/etc/apt/sources.list` |
| 未检测到有效的 initramfs | 内核包 postinst 未完成 | 按提示执行 `update-initramfs -c -k <release>`，RPM 系执行 `dracut -f` |
| 引导配置中未找到新内核 | 引导配置未更新 | Debian 会自动重试 `update-grub`；RPM 系按提示手工执行 `grub2-mkconfig` |
| 提示需要 root 权限 | 未使用 sudo | 使用 `sudo bash fix.sh` |
| `--check` 显示候选版本未知 | 本地包索引为空，`--check` 不刷新索引 | 先执行 `apt-get update` 或 `dnf makecache`，或直接运行修复流程 |

## 更新修复基线

1. 打开对应官方公告（Debian Security Tracker、ALAS、Ubuntu、Red Hat 等）。
2. 确认内核包名、EVR、软件源渠道与架构。
3. 修改 `data/cve-2026-98432.yml` 中对应记录的 `fixed_version`、`advisory`、`advisory_url`、`verified` 与 `notes`。
4. 完成适配与测试后，才将 `autofix` 改为 `yes`。
5. 运行全部测试，并更新 `CHANGELOG.md`。

## 项目结构

```
install.sh                  引导安装器：下载指定 Tag 的整包、校验 fix.sh 的 SHA256、转调 fix.sh
fix.sh                      入口：参数解析、流程编排、状态机出口
lib/
  common.sh                 退出码、颜色、日志、路径与容器识别
  detect.sh                 发行版、版本、架构与内核识别
  version.sh                dpkg、rpm、apk、pacman 版本比较
  advisory.sh               基线加载与查询
  kernel.sh                 运行内核与软件包的映射
  package_manager.sh        apt、dnf、yum 抽象
  install.sh                计划输出、安装、安装后校验、重启提示
  status.sh                 六态状态机
  report.sh                 --list-distros 与 --report
adapters/                   11 个发行版适配文件，声明身份、版本范围与能力
data/cve-2026-98432.yml     核验后的官方修复基线
tests/                      5 个测试套件、模拟实现与容器冒烟脚本
```

## 许可证

MIT，见 [LICENSE](LICENSE)。
