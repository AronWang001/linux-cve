# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.1.1] - 2026-11-01

仓库更名为 `linux-cve-2026-98432-fix`（原 `debian-cve-2026-98432-fix`）。v1.1.0 起工具已覆盖 Debian 之外的多套发行版，原名中的 `debian-` 前缀与实际定位不符。**无功能、无判定逻辑、无基线数据变更**，属于纯改名补丁。

### 变更

- 仓库地址：`AronWang001/debian-cve-2026-98432-fix` → `AronWang001/linux-cve-2026-98432-fix`（GitHub 侧旧地址会 301 跳转，但不再作为推荐入口）。
- `fix.sh`：`PROJECT_URL` 指向新地址；`SCRIPT_VERSION` 更新为 `1.1.1`。
- `install.sh`：`REPO` 指向新地址；归档目录名改为由 `REPO` 推导（`SRC_NAME="${REPO##*/}"`），以后改名不再需要改两处。
- `README.md`：徽章、引导安装器链接、`git clone` 地址、`SHA256SUMS` 链接全部切换到新仓库的 `v1.1.1` Tag。
- `tests/test.sh`：`--version` 断言同步为 `1.1.1`。

### 升级说明

- 已安装 v1.1.0 的用户无需做任何操作：脚本行为未变，检测与修复结果完全一致。
- v1.1.0 的 Tag / Release / 资产保持原样可下载（历史可追溯），但其中的 `install.sh` **在改名后不可用**：它写死了旧归档目录名（`debian-cve-2026-98432-fix-1.1.0`），而 GitHub 归档目录名随仓库名变化，执行时会停在「工具包结构异常（缺少 fix.sh）」。该失败发生在下载解包阶段，不会执行任何系统操作，但无法完成安装——请使用 v1.1.1 的安装链接。
- 本版本已把归档目录名改为由 `REPO` 推导，同类改名不会再破坏引导安装器。

## [1.1.0] - 2026-11-01

从「仅 Debian」升级为**多发行版检测 + 有限自动修复**。核心原则：**能识别一个系统，不等于支持自动修复**。

### 新增

#### 1. 发行版覆盖（官方公告逐条核验，核验日期 2026-11-01）

| 类别 | 发行版 | 行为 |
| --- | --- | --- |
| 自动检测 + 自动修复 | Debian 12 / 13、Amazon Linux 2、Amazon Linux 2023 | 官方公告状态 `Fixed`，按已核验 EVR/版本安装内核 |
| 仅检测（官方尚未修复） | Ubuntu 20.04 / 22.04 / 24.04、RHEL 8 / 9 / 10 | 输出官方 CVE 页面与状态，`PATCH_NOT_RELEASED`，不安装 |
| 仅识别（未完成核验） | Rocky、AlmaLinux、Oracle Linux（UEK/RHCK 分开）、Fedora、openSUSE Leap、SUSE、Arch、Alpine | 只做识别与状态展示，`UNKNOWN`，不安装 |

- Amazon Linux 2 支持 4.14 / 5.4 / 5.10 / 5.15 四条独立基线；AL2023 支持 `kernel` / `kernel6.12` / `kernel6.18` 三个独立包，互不混用。
- Oracle Linux 区分 `kernel-uek` 与 `kernel`（RHCK）；Alpine 区分 `linux-lts` / `linux-virt` / `linux-edge`；Arch 不做版本号假设（滚动发行版）。
- 识别同时支持 `x86_64/amd64` 与 `aarch64/arm64`；未在白名单内的架构直接拒绝修改。

#### 2. 架构重构（`fix.sh` 仍是唯一入口）

- `lib/`：`common`、`detect`、`version`、`advisory`、`kernel`、`package_manager`、`install`、`status`、`report`。
- `adapters/`：11 个发行版适配文件，每个显式声明 `detect_supported`、`autofix_default`、支持版本、架构、内核 flavor、官方公告 URL、升级步骤与说明。
- `data/cve-2026-98432.yml`：人工核验后的基线（状态、修复版本、公告链接、仓库、升级步骤、核验日期、是否允许自动修复），Bash 解析，无在线抓取。
- `install.sh`：引导安装器（多文件布局无法用单文件 `curl` 完成），下载固定 Tag 整包 → 校验 `fix.sh` SHA256 → 转调 `fix.sh`。

#### 3. 统一状态机与退出码

`FIXED` / `PENDING_REBOOT` / `VULNERABLE_PATCH_AVAILABLE` / `PATCH_NOT_RELEASED` / `UNKNOWN` / `UNSUPPORTED`，对应退出码 0 / 3 / 2 / 6 / 4 / 1，用户取消为 5。

#### 4. 版本比较

- dpkg 语义（`epoch:`、`~` 回滚、`+deb12u1` 等），沿用 `dpkg --compare-versions`。
- RPM EVR（epoch、release、`~`、`^`），纯 Bash 实现 `rpmvercmp`。
- Alpine（`-rN` 与 `_alpha/_beta/_pre/_rc/_p` 权重）。
- Arch（`pkgver-pkgrel`）。

#### 5. 安装后校验与引导检查

- 以包数据库（dpkg/rpm/apk/pacman）实际结果为准，安装命令返回 0 不算成功。
- 校验内核镜像、initramfs/initrd；识别**实际使用的引导程序**（GRUB / grub2 / systemd-boot），不假设一定是 GRUB。
- RPM 系不擅自重建引导配置（避免破坏云厂商启动项），缺失启动项时停止并给出人工命令。
- 只提示重启，绝不自动重启；重启后重跑脚本才判定 `FIXED`。

#### 6. 命令行

- 新增 `--list-distros`（支持矩阵）与 `--report [文件]`（本地报告，仅白名单字段，不含凭据）。
- 保留 `--check`、`--yes`、`--help`、`--version`、`--no-color`；`--yes` 不能绕过发行版白名单、公告核验与版本校验。

### 安全设计

- 自动修复必须同时满足：adapter 允许自动修复 + 基线 `autofix: yes` + 基线完整（修复版本非空）+ 候选版本同分支且达标。
- 容器环境、`uname` 与包管理器架构冲突、第三方/自编译内核一律判定 `UNKNOWN`，不猜测、不安装。
- 只使用发行版官方源或用户已配置的仓库；不新增第三方源、不编译内核、不删除旧内核、不做全系统升级、不自动重启。
- 不修改 SSH、防火墙、网络、HAProxy、V2bX、Xray 或业务配置。

### 测试

- 5 个测试套件共 66 个用例：Debian 回归 26 例、发行版识别 16 例、Amazon Linux 适配 11 例、版本比较 5 例、安全边界 8 例。
- 新增模拟器 `tests/lib/mocks_pm.py`（rpm/dnf/yum/apk/pacman）与公共骨架 `tests/lib/harness.sh`，全部在假根目录中运行，不触碰真实系统。
- 新增容器冒烟 `tests/container_smoke.sh`：Debian 12/13、Ubuntu 22.04/24.04、Rocky 9、Alma 9、Fedora、openSUSE Leap、Alpine、Arch、Amazon Linux 2/2023 的识别校验。
- GitHub Actions 三个 job：`shellcheck`、`unit`（5 个套件）、`distro-smoke`（容器矩阵）。

### 已知限制

- 未在真实虚拟机 / 云主机上执行内核安装与重启验证；容器冒烟只覆盖「识别」环节，不能替代真实内核启动验证。
- Ubuntu、RHEL、Rocky、AlmaLinux、Oracle Linux、Fedora、openSUSE/SUSE、Arch、Alpine 目前均为**仅检测/仅识别**，不提供自动修复。
- 基线是人工核验的静态文件，不实时同步官方公告；更新方式见 README「基线更新」。

### 兼容性

- 保留 v1.0.0 的全部 Debian 行为与退出码 0/1/2/3/4/5，新增 6（官方尚未发布修复包）。
- Debian 修复版本基线未变：`6.1.190-1`、`6.12.113-1~deb12u1`、`6.12.113-1`。

### 开发过程中发现并修复的问题

1. 运行内核与包的映射在多内核发行版上会误配 → 统一为 `<包名>\t<版本>\t<标识>` 三元组，先按分支再按版本筛选。
2. ShellCheck 无法跨文件追踪全局状态，产生大量 SC2034 → 对「只做初始化 / 只产出状态」的模块显式声明 `# shellcheck disable=SC2034`，并修正其中真正无用的变量。
3. Arch 的 `*-lts` 模式会抢先匹配 `*-rt-lts`，导致 rt-lts 内核被识别为 lts → 调整 case 顺序并加注释。
4. AL2023 的 6.12/6.18 内核对在判定输出中只显示笼统的 `kernel` → 改为显示真实运行内核包名（`kernel6.12` 等）。
5. 测试用包管理器模拟器把新内核写到了错误的根目录，导致安装后校验误判 → 统一读取 `FIX_SYSROOT`。
6. 测试模拟器未按 `--latest-limit 1` 的取值解析位置参数，`repoquery` 目标包名被误认为 `1` → 统一参数解析。
7. `detect_pm_sources` 用了 `[[ 条件 ]] && 赋值` 作为分支最后一条语句：条件为假时函数返回 1，在 `set -e` 下直接中断脚本。Debian/Ubuntu 容器内 `/var/lib/apt/lists` 为空时必现（由容器冒烟测试发现）→ 全部改为 `if` 块并显式 `return 0`，同时补充「空 APT 索引」回归用例。

## [1.0.0] - 2026-11-01

首个正式版本。

### 新增

- **环境检测**：root 权限、Debian 12/13 识别（版本号 + 代号交叉校验）、amd64 架构校验、运行内核版本、运行内核对应的 `linux-image` 软件包版本、APT 源数量与 security 源、待重启标记。
- **漏洞判定**：按「发行版 + 内核分支」选择修复基线，使用 `dpkg --compare-versions` 比较，输出四种状态——已修复 / 待重启 / 存在漏洞 / 无法确认。
- **修复流程**：交互式确认 → `apt-get update` → 复核候选版本 → 安装官方内核元包 → 校验 dpkg 实际结果 → 校验 initramfs → 校验 GRUB → 输出重启提示。
- **元包选择**：Debian 12 / 6.1 与 Debian 13 / 6.12 使用 `linux-image-amd64`，Debian 12 / 6.12 使用 `linux-image-6.12-amd64`；`-cloud-amd64`、`-rt-amd64` 变体自动匹配；元包不可用时回退到同分支具体镜像包。
- **重启提醒**：输出原内核、新内核、安装状态、是否需要重启，并给出可复制的 `reboot` 命令；不自动重启。
- **二次验证**：重启后重跑脚本即可确认运行内核是否达到修复版本。
- `--check` 只读模式、`--help`、`--version`、`--no-color`、`--yes`。
- 分级退出码：0 已修复 / 1 错误 / 2 存在漏洞 / 3 待重启 / 4 无法确认 / 5 用户取消。
- 测试套件 `tests/test.sh`（26 个用例）+ dpkg/apt 模拟器 `tests/lib/mocks.py`。

### 安全设计

- 只使用 Debian 官方软件源，不编译内核、不引入第三方源、不删除旧内核。
- 不执行 `apt-get upgrade` / `dist-upgrade`，不改动 SSH、防火墙、网络与业务配置。
- 安装使用 `--force-confdef --force-confold`，不覆盖已有配置文件。
- 候选版本必须同时满足「内核分支一致」与「版本 ≥ 修复版本」，否则中止。
- apt 返回 0 不作为修复依据，必须由 dpkg 数据库确认修复版本内核已安装。
- 全部错误路径显式退出，不静默忽略失败。

### 修复版本基线

| 发行版 | 源码包 | 分支 | 修复版本 | 公告 |
| --- | --- | --- | --- | --- |
| Debian 12 bookworm | `linux` | 6.1 | `6.1.190-1` | DLA-4841-1 |
| Debian 12 bookworm | `linux-6.12` | 6.12 | `6.12.113-1~deb12u1` | DLA-4850-1 |
| Debian 13 trixie | `linux` | 6.12 | `6.12.113-1` | DSA-6568-1 |

核对日期：2026-11-01，来源：Debian Security Tracker / DSA-6568-1 / DLA-4841-1 / DLA-4850-1。

### 测试

- 26 个用例全部通过，覆盖任务要求的 16 个场景及额外边界场景。
- `shellcheck -S style fix.sh tests/test.sh` 无告警（ShellCheck 0.11.0）。

### 开发过程中发现并修复的问题

1. 脚本早期版本在被 `source` 时直接执行 `main`，无法做进程内单元测试 → 增加 `BASH_SOURCE` 守卫。
2. `apt-cache policy` 解析未固定 locale，中文环境下字段名被翻译会导致候选版本解析失败 → 解析调用固定 `LC_ALL=C`。
3. 测试模拟器未跳过 `apt-get` 的全局 `-o` 选项，把 `-o` 当成子命令，导致「APT 更新失败」「安装失败」用例被误判为通过 → 修正参数解析，并补充断言校验 APT 原始报错，确认失败确实来自预期环节。
4. ShellCheck 对测试脚本报 SC2034 / SC2329 / SC2016 → 清理未使用变量、标注 trap 调用与单引号片段用途。
5. 用 `eval` 恢复 `nullglob` 的写法改为显式状态判断，避免拼接执行。
