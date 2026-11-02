# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.3.0] - 2026-11-02

新增 CloudLinux 7/7h/8/8 LTS/9/9 LTS/10 的检测基线，并新增 `NOT_AFFECTED` 状态（退出码 `8`）与 `--allow-staged-rollout` 参数。同时重新核验 Oracle Linux UEK、SUSE/openSUSE 与 AlmaLinux 的官方页面，修正 v1.2.0 中关于 SLES 15 SP7 的表述错误。

**自动修复范围未扩大**：CloudLinux 的 7 条记录全部为 `autofix: no`。官方修复包已发布，但涉及 staged rollout、TuxCare ELS 订阅资格与 testing 仓库，且未在真实实例完成「安装→引导项检查→重启→复核」验证，因此只做检测。

### 新增

- CloudLinux 适配层 `adapters/cloudlinux.sh`（第 12 个适配文件），按 2026-10-30 官方公告建立 7 条基线：
  - `cloudlinux-7-standard-3.10`：CL7 标准内核 3.10，官方说明漏洞代码自 Linux 4.4 引入，状态 `not_affected`。
  - `cloudlinux-7h-4.18`、`cloudlinux-8-standard-4.18`：`kernel` `4.18.0-553.180.1.lve.1`，`advisory_status: staged_rollout`。
  - `cloudlinux-8-lts-5.14`、`cloudlinux-9-lts-5.14`：`kernel-lts` `5.14.0-284.1101.el8.tuxcare.11.els19` / `5.14.0-284.1101.el9.tuxcare.11.els19`（TuxCare ELS）。
  - `cloudlinux-9-standard-5.14`、`cloudlinux-10-standard-6.12`：`5.14.0-687.61.2.el9_8`、`6.12.0-211.69.2.el10_2`，仅 AlmaLinux testing，状态 `testing`。
- `NOT_AFFECTED` 状态与退出码 `8`：官方明确说明内核分支不含漏洞代码时使用，不安装、不重启，输出「判定结果：不受影响」。
- CloudLinux 身份三重交叉校验 `cloudlinux_verify_identity()`：`/etc/os-release`、`/etc/cloudlinux-release`、`cloudlinux-release` 软件包主版本必须一致；缺少后两者或版本冲突时判 `UNKNOWN`，不套用 RHEL/Ubuntu 结论。无 RPM 数据库时识别为 CloudLinux for Ubuntu 22.04，只输出「由 Canonical 推进」。
- CloudLinux 内核流判定 `cloudlinux_detect_stream()`：`kernel-lts` → `lts-els`；`7+3.10` → `standard-3.10`、`7+4.18` → `hybrid-4.18`、`8+4.18` → `standard-4.18`、`9+5.14` → `standard-5.14`、`10+6.12` → `standard-6.12`。CL9 的标准内核与 LTS 同为 5.14，只能靠包名区分。
- staged rollout 只读查询 `cloudlinux_check_rollout()`：用 `rpm_candidate` 查询当前仓库候选，得出 `reached` / `pending` / `unknown` 三态；未到达时提示「官方已发布，但当前实例尚未进入 staged rollout」，任何状态都不安装。
- `--allow-staged-rollout` 参数：仅在 CloudLinux 上输出 bypass 仓库的风险说明（可能缺少机型与驱动验证、只能单次启用、不写 repo 文件），非 CloudLinux 上提示「已忽略」。本版未实现实际安装路径，指定后也不会执行 `yum`。
- 测试 `tests/test_cloudlinux.sh`（17 个用例）：CL7 3.10 不受影响、CL7h/CL8 独立识别、CL8/9 LTS 的独立 EVR、CL9/10 仅 testing、CloudLinux for Ubuntu、身份缺失与版本冲突、`--allow-staged-rollout` 不启用 bypass、`--yes` 不能绕过、`--check` 只读、`--list-distros` 标注。

### 变更

- `lib/advisory.sh`：字段去引号不再为每个字段 fork 子 shell（改为写入 `UNQUOTED`）。基线从 51 条增至 58 条后，单次检测在 Git Bash 下由约 62 秒降到约 11 秒，判定结果不变。
- `lib/detect.sh`：新增 CloudLinux 身份与内核流识别；`normalize_release` 与 `adapter_file_for_id` 支持 `cloudlinux` / `cloudlinuxos`。
- `lib/kernel.sh`：内核包识别补充 `kernel-lts`。
- `lib/status.sh`：新增 CloudLinux 身份校验失败即 `UNKNOWN`、`not_affected` 状态映射、rollout 状态参与判定理由、`autofix` 增加 rollout 闸门；`CL_VARIANT` / `CL_STREAM` 改为「未赋值时补空」，避免判定开始时丢失变体信息。
- `lib/report.sh`：`--list-distros` 与 `--report` 增加 CloudLinux 与 Rollout 行，状态标签补充「不受影响」。
- `lib/install.sh`：新增 `print_staged_rollout_notice()`。
- `fix.sh`：版本改为 `1.3.0`；新增 `--allow-staged-rollout` 解析与 `NOT_AFFECTED` 出口；帮助文本与 `--version` 同步 CloudLinux 与退出码 7/8。
- `data/cve-2026-98432.yml`：51 条增至 58 条；Oracle Linux、SUSE、AlmaLinux、RHEL、Ubuntu 共 37 条记录的 `verified` 更新为 2026-11-02；`sles-15.7-unknown` 的 `notes` 改为「QA 列表有 6.4.0-150700.53.90.1，但 released 列表无 SP7 条目，状态表全部 In progress，也无 SUSE-SU 公告」，与官方页面一致。
- `README.md` / `README.en.md`：补充 CloudLinux 支持矩阵、「官方声明不受影响」小节、staged rollout 与 bypass 风险、ELS 授权要求、退出码 8 与新参数；SLES 15 SP7 的描述同步修正；测试套件表与 CI 说明更新为 9 个套件 112 个用例。

### 测试

- 用例总数 112 个：v1.2.0 的 94 个 + 新增 18 个（`test_cloudlinux` 17、`test_baseline` 1）。
- 原有 94 个用例全部保留，断言未删除、未放宽预期退出码；除下面两处说明外，`test.sh`、`test_detection.sh`、`test_amazon_linux.sh`、`test_new_distros.sh`、`test_safety.sh`、`test_installer.sh`、`test_version.sh` 未改动。
- **`tests/test_baseline.sh` 有一处放宽**：`status` 合法值列表新增 `not_affected`，这是为新增状态放行，不是收紧校验；同一文件新增的用例会反过来检查 `not_affected` 记录不得带 `fixed_version`、不得允许自动修复、必须写明官方依据。
- **`tests/test.sh` 第 14 个用例有一处断言更新**：`--version` 的期望字符串随版本号由 `1.2.0` 改为 `1.3.0`。这是每次发版都必须跟随的版本号断言，其余断言（`--help` 用法与退出码、非法参数）未改动。
- `tests/lib/harness.sh` 新增 `h_hide_cmd` / `h_show_cmd`，用于模拟没有 RPM 数据库的 CloudLinux for Ubuntu 场景；当 PATH 中还存在同名真实命令（例如 CI runner 自带的 `rpm`）时，会额外构造一个不含该命令的 PATH，避免场景失真。
- 容器冒烟不覆盖 CloudLinux：官方镜像需要订阅凭据，公开 CI 无法拉取，因此该发行版只有模拟测试与只读查询验证。

### 已知限制

- CloudLinux、Oracle Linux、SUSE/openSUSE、AlmaLinux 均未在真实虚拟机完成「安装→引导项检查→重启→复核」，`autofix` 保持 `no`。
- CloudLinux 8/9 LTS 需要 TuxCare ELS 订阅；工具不添加 TuxCare 源，也不从外部 URL 下载 RPM。
- `cloudlinux-rollout-3-bypass` 未接入安装路径，指定 `--allow-staged-rollout` 也不会启用；等实机验证完成后再评估。
- SLES 15 SP7 仍为 `UNKNOWN`，冲突未消除。

### 升级说明

- 从 v1.2.0 升级无需修改配置，Debian/Amazon Linux 的判定与安装行为不变。
- 新增退出码 `8`（`NOT_AFFECTED`），脚本化调用方需要按需处理；退出码 `7` 语义不变。
- 新增参数 `--allow-staged-rollout`，不指定时行为与 v1.2.0 一致。

## [1.2.0] - 2026-11-01

新增 Oracle Linux UEK、SUSE/openSUSE、AlmaLinux 的官方补丁基线，基线模型改为按产品/版本/内核流/flavor/架构/仓库渠道精确匹配。安装器改为整包 SHA256 校验。

**自动修复能力未扩大**：新纳入的发行版只做检测与状态展示。真实虚拟机上的安装、引导项检查与重启验证尚未完成，因此 `autofix` 全部为 `no`，避免把未验证的安装流程交付给生产环境。

### 新增

- Oracle Linux UEK：按 2026-10-16 的三个勘误建立 7 条基线。
  - `ELSA-2026-500397`：UEKR6 `5.4.17-2136.360.3.1`（`el7uek` / `el8uek`）
  - `ELSA-2026-500398`：UEKR7 `5.15.0-325.221.6.4`（`el8uek` / `el9uek`）
  - `ELSA-2026-500399`：UEKR8 `6.12.0-207.111.5.4`（`el9uek` / `el10uek`）
  - UEK 代际由运行内核分支判定（5.4 / 5.15 / 6.12），OL8 与 OL9 的不同代际分别匹配；OL7 只对应 x86_64 UEKR6 ELS 频道；RHCK 无独立勘误，保持 `UNKNOWN`。
- SUSE / openSUSE：按 2026-10-29 的官方发布包列表建立基线。
  - openSUSE Leap 16.0、SLES 16.0：`kernel-default >= 6.12.0-160000.40.1`
  - SLES 15 SP4-LTSS：`5.14.21-150400.24.246.1`
  - SLES 15 SP5-LTSS：`5.14.21-150500.55.195.1`
  - SLES 15 SP6-LTSS：`6.4.0-150600.23.143.1`
  - `kernel-default-base` 使用独立的完整 EVR（如 `6.12.0-160000.40.1.160000.2.30`），不与 `kernel-default` 共用。
  - SLES 15 SP7 的发布包列表与状态表互相矛盾（状态仍为 `In progress`），按 `UNKNOWN` 处理。
  - SLE Micro 6.2 有修复包，但使用 transactional-update，仅检测。
- 新状态 `PATCH_TESTING_ONLY` 与退出码 `7`：AlmaLinux 8/9/10 的修复内核仅在 testing 仓库（2026-10-30 公告），工具不会启用 testing 源或安装测试内核。
- `zypper` 只读能力：候选版本查询、事务 dry-run 预览、按 EVR 安装的实现，全部只在 `autofix=yes` 时可达；当前没有 SUSE 记录启用自动修复。
- 基线字段：`product`、`service_pack`、`kernel_stream`、`kernel_flavor`、`repo_channel`、`advisory_status`、`tested_install`、`tested_reboot`。
- 基线静态检查 `tests/test_baseline.sh`：ID 与组合键唯一、`fixed/testing` 必须有完整 EVR 与公告、通配记录不得声明已修复、`autofix=yes` 必须有正式补丁（新模型还要求实机安装与重启验证）。
- 安装器整包校验：`install.sh` 现在要求 Release 提供 `SHA256SUMS`，校验 `fix.sh`、`install.sh`、`lib/*.sh`、`adapters/*.sh`、`data/*.yml` 的全部哈希；清单缺失、哈希不符、路径穿越、缺少 `sha256sum/shasum` 时一律停止，不再「警告后继续」。

### 变更

- `lib/advisory.sh`：新增 `baseline_lookup_exact()`，按产品、版本、内核分支、软件包、架构、内核流严格匹配；多条记录冲突或无记录时返回 `UNKNOWN`，不再让通配记录兜底命中。
- `lib/kernel.sh`：RPM/SUSE 的运行内核映射同时接受 `EVR`、`EVR.arch`、`EVR-flavor` 三种形式；补充 `kernel-64kb`、`kernel-azure`、`kernel-uek64k` 等内核包识别。
- `fix.sh`：`SCRIPT_VERSION` 更新为 `1.2.0`；新增 `PATCH_TESTING_ONLY` 的退出码与提示；`--check` 支持 SUSE 目标包预览。只检测的发行版不再输出「可执行以下命令修复」，避免与「未启用自动修复」自相矛盾。
- `--list-distros`：自动修复列按基线中的 `autofix` 汇总；有修复包但未完成实机验证的发行版显示「仅检测」，不再因为一条 fixed 记录就宣称整个家族可自动修复。
- 状态输出与 `--report` 新增「内核流」「仓库渠道」「更新方式」「实机验证」四行，SUSE Micro 会明确显示 `transactional-update`。

### 测试

- 用例总数 94 个：v1.1.2 的 66 个 + 新增 28 个（`test_new_distros` 14、`test_baseline` 7、`test_installer` 7）。原有 66 个用例全部保留，没有删除任何用例。
- 其中 `tests/test_detection.sh` 有 4 个用例的预期结果随本版行为更新，**旧断言不再成立**：
  - D5 AlmaLinux 9.4：期望退出码 `4`（`UNKNOWN`）→ `7`（`PATCH_TESTING_ONLY`），并新增「判定结果：仅测试仓库有补丁」断言。
  - D6 Oracle Linux 9.4（UEKR7）：`4` → `2`（`VULNERABLE_PATCH_AVAILABLE`），并新增 `ELSA-2026-500398`、「未启用自动修复」、未执行 `dnf install` 三条断言。
  - D8 SLES 15 SP5：`4` → `2`，并新增 LTSS 仓库频道与「未启用自动修复」两条断言。
  - D12：原「SUSE 15.5 判 `UNKNOWN`」场景改为 SLES 15 SP7 官方状态自相矛盾，断言仍为「判定结果：无法确认」「未启用（仅检测）」，且不得出现「判定结果：已修复」。
- 这 4 处合计净增 6 条断言（`test_detection.sh` 从 91 条到 97 条），没有删除或放宽检查。但 **CI 全绿只证明当前断言集合通过，不能用来证明 v1.1.2 的旧预期（上述四例均为 `UNKNOWN`）在 v1.2.0 下仍然成立**。

### 已知限制

- Oracle Linux、SUSE/openSUSE、AlmaLinux 均未在真实虚拟机或云主机上完成「安装→引导项检查→重启→`FIXED`」验证，因此不启用自动修复。
- SLES 的 LTSS 基线需要对应订阅与仓库资格；工具无法判断订阅状态，只展示官方 EVR。
- AlmaLinux 的 testing 补丁未经社区验证，不得用于生产。

### 升级说明

- 从 v1.1.2 升级无需修改配置，判定流程与已有 Debian/Amazon Linux 行为不变。
- 新增退出码 `7`，脚本化调用方需要按需处理。

## [1.1.2] - 2026-11-01

安装方式改为一键执行，并按项目文档规范重写 README。判定逻辑、支持矩阵与基线数据均未变更。

### 变更

- 一键执行：`curl -fsSL https://raw.githubusercontent.com/AronWang001/linux-cve-2026-98432-fix/v1.1.2/install.sh | sudo bash`。命令直接进入检测与修复流程，确认提示从 `/dev/tty` 读取，不再要求先把 `install.sh` 落盘。
- 只读与免交互用法：`| sudo bash -s -- --check`、`| sudo bash -s -- --yes`。`--yes` 仍不能绕过发行版白名单、公告核验与版本校验。
- `install.sh`：用法注释同步为新的一键执行方式；`REPO` / `VERSION` 保持动态推导与集中定义。
- `README.md`：按「真实、结构清晰、可操作」的要求重写。删除装饰性提示与宣传性表述，补齐系统要求、执行方式、参数、退出码、支持状态、判定流程、测试与已知限制；核对全部官方版本号与公告链接，未在真实 AWS 实例执行的验证在「已知限制」中明确标注。
- `fix.sh`：`SCRIPT_VERSION` 更新为 `1.1.2`。
- `tests/test.sh`：`--version` 断言同步为 `1.1.2`。

### 升级说明

- 已使用 v1.1.1 的用户可不更新：本次不涉及判定与安装逻辑。
- 手工下载后执行的方式仍然可用，`install.sh` 与仓库整包均未改变目录结构。

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
