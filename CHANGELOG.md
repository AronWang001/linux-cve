# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

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
