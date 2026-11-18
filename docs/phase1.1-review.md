# 阶段 1.1 收尾审查与修订报告

- 阶段：1.1/9（阶段 1 收尾审查，不启动阶段 2）
- 日期：2026-11-18
- 分支：`feat/v2.0.0`（HEAD `c24239f`，基于 `ec1415b`，未推送）
- 版本号：`2.0.0-dev`

---

## 0. Skills 实际加载情况

| Skill | 加载 | 用途 |
|-------|------|------|
| investigate-first | 是 | 只读核实先行，禁止未分析直接修改 |
| migration | 是 | 审查 0001_init.sql 与迁移策略 |
| lean-build | 是 | 控制修订范围，不做无关扩展 |
| safe-refactor | 是 | 小步安全重构（字段改名、校验抽取） |
| review-agent | 是 | 对 `ddad10d..HEAD` 独立审查，产出 1 项发现并修复 |
| verify-and-stop | 是 | 最终验证与硬停止 |

## 1. Git 状态核实（只读，未推送）

```
$ git rev-parse HEAD            c24239f（审查修复后）
$ git branch --show-current     feat/v2.0.0
$ git status --porcelain=v1     （干净）
$ git diff --name-only ec1415b..HEAD -- fix.sh lib adapters install.sh data tests .github
                                0 个文件（v1.3.2 旧代码零改动）
```

阶段 1 四提交（`ae0198e`、`e285ecb`、`a494838`、`ddad10d`）完整保留，无重置、无删除。
远端 `main` 仍指向 `ec1415b`，`feat/v2.0.0` 未推送，无 Tag/Release 操作。

本轮新增提交（`ddad10d..HEAD`，共 5 个）：

| 提交 | 内容 |
|------|------|
| `a257e76` | fix(domain): P1-1/2/3 架构匹配、版本原始值、来源渠道 + P1-4/5 领域层部分 |
| `7dc270c` | fix(database): P1-4/5/6 Schema 完整性与迁移一致性守卫 |
| `f8ff8fb` | fix(buildinfo): P1-7 构建信息注入回退 unknown |
| `c130cda` | docs: 文档统一 + 阶段 1 报告勘误 |
| `c24239f` | fix(domain): 独立审查发现的 UID 校验绕过修复 |

## 2. 专项技术审查与修订（P1-1 ~ P1-7）

### P1-1 架构匹配 `archMatch` —— 已修订

原缺陷：`noarch` 安装包被当通配符接受任意公告架构；公告空声明自动匹配一切。

修订后规则（`domain.ArchMatches`，已入 `docs/data-model.md` §2.1 规则表）：

| 公告声明 | 匹配行为 |
|----------|----------|
| `any` | 唯一通配标识 |
| `all`/`noarch` | 仅互配架构无关包 |
| 已登记原生架构 | 同规范架构互配（`amd64≡x86_64`、`arm64≡aarch64`，其余自映射：armhf/armel/i386/i686/x86/ppc64le/s390x/riscv64/src） |
| 空串/未登记标识 | 一律不匹配（即使两侧同名），禁止自动放行 |

`PackageRef.Arch` 逐字保留原生标识，归一化仅存在于匹配路径（`CanonicalArch`）。
测试：`TestArchMatches` 26 组正反向用例 + `TestCanonicalArch`。

### P1-2 版本原始值 —— 模型合格，边界测试补齐

`Version{Raw, Epoch, Upstream, Release}` 可无损表达原始串，`String()` 恒优先返回 `Raw`。
新增 `version_test.go`：epoch、dpkg tilde 回移（`6.12.113-1~deb12u1`）、rpm EVR、
apk `-r0`、pacman pkgrel、预发布（`2.0~rc1-1`）逐条断言无损。
**明确声明**：dpkg/rpm/apk/pacman 原生比较语义属阶段 2 `internal/version`，
本阶段只固化存储，不做比较；`StructurallyEqual` 仅判重、不排序（有测试固化）。

### P1-3 软件包来源渠道 —— 已修订

原缺陷：`InstalledPackage.Channel` 语义含混，采集输出可被误读为来源结论。

修订：来源渠道四分法（已入 `data-model.md` §2.2 对照表）——
①已安装包信息 ②当前启用的软件源 ③软件源候选修复版本 ④可证明的安装来源。
仅 ④ 允许写渠道结论，字段改名 `OriginChannel` + `OriginEvidence`，
哨兵值 `ChannelUnknown`；声明具体渠道必须携带来源证明，`Validate()` 强制执行。
`Finding` 同步改名。阶段 2 资产采集按只读约定实现。

### P1-4 SQLite 关系完整性 —— 已修订（0001 未发布，直接修订初始迁移）

- `advisory_fixes` 不再冗余 `advisory_uid`：只存 `(source_id, advisory_id, cve_id)`
  三元组，组合外键锚定 `advisories`（ON DELETE CASCADE），结构性消除 UID↔三元组
  不一致可能；九列 UNIQUE 不变，跨发行版/release/渠道不冲突。
- `advisory_fixes` / `advisory_not_affected` 均增加 `(distro_id, release)` 组合外键
  锚定 `distro_releases`，合法发行版配非法 release 也被拒绝。
- 领域层 `AdvisoryFix.Validate` 强制 UID 与三元组一致（审查后加固：`SourceID` 必填）。
- 测试：`TestCompositeReleaseFK`、`TestAdvisoryTripleFK`（含级联删除）、
  `TestAdvisoryFixUniqueScopedByCoordinate`（四组坐标）、`TestForeignKeyEnforced`。

### P1-5 签名与完整性状态 —— 已统一

五字段定案：`trust_level`（应然）/ `signature_kind` / `signature_status`
（verified|failed|missing|not-applicable|unverified）/ `integrity_status`
（verified|failed|unchecked）/ `content_hash`。
`validation_level` 与文档中的 `signature_verified` 均已删除，签名验证与内容哈希
校验在 Schema、领域模型（`Evidence.Signature` × `Evidence.Integrity`）和
`architecture.md`/`data-model.md` 三处一致，禁止互相冒充。
测试：`TestFeedSourceSignatureIntegrity`（默认值、合法组合、CHECK 拒绝非法枚举）。

### P1-6 Schema 版本一致性 —— 已解决（唯一权威方案）

- **权威来源 = `schema_migrations`**；`app_meta.schema_version` 种子行删除，双记录不复存在。
- 迁移 SQL 与迁移记录同一事务提交，失败整体回滚（`TestApplyOneRollbackOnError`）。
- `validateApplied`（独立可测函数）拒绝：校验和篡改、库版本高于二进制、
  迁移序列缺档（`TestValidateAppliedConsistency` 合成用例覆盖四类）。
- `guardSchemaAge` 接入 `Open`：库 Schema 高于二进制**拒绝打开**（含只读命令，
  `TestOpenRejectsNewerSchema`）。
- 重复执行幂等保留（`TestMigrateIdempotent`）。

### P1-7 构建信息 —— 已修复

原问题：CLI 实测输出 `commit ec1415b`（main 基线）冒充当前构建。
修复：`buildinfo.Commit`/`BuildDate` 未注入时显示 `unknown`，不回退任何提交号；
Makefile 注入构建时 `git rev-parse --short HEAD` 与真实构建时间。
实测证据（本机重新构建）：

```
# 注入构建（当时 HEAD = ddad10d）：
$ go build -ldflags "...Commit=$(git rev-parse --short HEAD)..." && ./dist/linux-cve.exe version
linux-cve 2.0.0-dev (commit ddad10d, built 2026-11-18T05:16:50Z, go1.27.4, windows/amd64)

# 无 ldflags 构建：
$ go build ./cmd/linux-cve && ./linux-cve version
linux-cve 2.0.0-dev (commit unknown, built unknown, go1.27.4, windows/amd64)
```

commit 与注入时 HEAD 一致，不再是基线 `ec1415b`；未注入时显示 `unknown`。

新增 `buildinfo_test.go` 固化默认值与注入值。

## 3. 最终 Schema / 架构 / 数据模型

| 交付 | 文件 | 状态 |
|------|------|------|
| 最终架构文档 | `docs/architecture.md` | 已同步五字段与证据结构 |
| 最终数据模型 | `docs/data-model.md` | 包模型/渠道四分法/Schema/匹配规则/迁移规则全部对齐代码 |
| 最终 Schema | `internal/database/migrations/0001_init.sql` | 组合外键、五字段、单一权威（未发布迁移，已安全修订） |
| CLI 用法 | `docs/cli.md` | 与实现一致，无需改动 |
| 支持矩阵 | `docs/support-matrix.md` | 无受影响字段引用，无需改动 |

## 4. 测试结果（全部真实执行）

| 项 | 命令 | 结果 |
|----|------|------|
| Go 单测 | `go test ./... -v` | **79 PASS / 0 FAIL / 0 SKIP**（`grep -c "^=== RUN"` = 79；`grep -E "^\s*--- (FAIL|SKIP)"` 无输出） |
| 分布 | 逐包计数 | app 10、apperr 3、buildinfo 2、config 10、database 18、domain 30、exitcode 2、logging 4 |
| Race | `go test -race ./...` | 8 包全部 ok |
| 静态检查 | `go vet ./...` | 退出码 0 |
| 格式 | `gofmt -l ./cmd ./internal` | 空输出 |
| 构建 | `go build ./...` | 退出码 0 |
| 交叉编译 | CGO_ENABLED=0 linux/amd64 | 7,827,616 字节（`-s -w`） |
| 交叉编译 | CGO_ENABLED=0 linux/arm64 | 7,536,800 字节 |
| v1.3.2 主套件 | `bash tests/test.sh` | **28/28 PASS，EXIT=0**（本轮重跑） |
| v1.3.2 版本套件 | `bash tests/test_version.sh` | **5/5 PASS，EXIT=0** |
| 旧代码零改动 | `git diff ec1415b..HEAD -- fix.sh lib adapters install.sh data tests .github` | 0 文件 |

**勘误声明**：阶段 1 报告曾用 `grep -c "FAIL|SKIP"`（未加 `-E`）证明零失败，
该命令按字面匹配恒为 0，证据无效。本轮全部计数改用扩展正则并在 §4 给出原始命令，
`docs/phase1-report.md` 已同步勘误。

**未执行 / BLOCKED（不计为通过）**：其余 6 套 v1.3.2 Bash 套件（test_detection/
test_safety/test_amazon_linux/test_baseline/test_new_distros/test_cloudlinux/
test_installer）、容器冒烟、ShellCheck——本机无 Docker/WSL/shellcheck；
Linux 实机验证（交叉编译≠实机运行）——无测试 VM。

## 5. 未解决问题清单

1. **无 Linux 实机**（阻塞阶段 4/5 验收）：需要可销毁 VM——Debian 12/13、Ubuntu
   22.04/24.04、Amazon Linux 2023。未经批准不产生费用。
2. Go CI 未接入（`.github/workflows/test.yml` 仍为 v1.3.2 Bash 测试），计划阶段 2 补。
3. 依赖经 `goproxy.cn` 拉取，CI 需固定 `GOPROXY`/`GOSUMDB` 或 vendor。
4. `go.sum` 间接依赖（modernc.org/libc 等）待阶段 7 依赖安全审计。
5. 交叉编译产物未在 Linux 运行过；文件权限、非 root 错误路径未实机验证。
6. 本机 v1.3.2 套件在 Windows Git Bash 全程约 6 分钟，历史上曾被 540s 超时截断
   （环境性能问题，非断言失败）。

## 6. 阶段 2 前置条件

- **测试环境清单确认**：Debian 12、Debian 13、Ubuntu 22.04、Ubuntu 24.04、
  Amazon Linux 2023（可销毁 VM/SSH 主机）。无 VM 时阶段 2 先以纯代码 + 模拟数据
  推进采集器与版本比较器，实机验证后置——需你确认该降级路径。
- 资产采集只读边界确认：只调用 `dpkg-query`/`rpm -q`/`apk info`/`pacman -Q`
  等只读查询，不刷新软件源、不装依赖。
- 版本比较交叉验证路径：与 `dpkg --compare-versions`、`rpmdev-vercmp` 真实输出逐条比对。
- 0002_inventory 迁移的前置（P1-6）已完成，可安全开工。

## 7. 验收对照（本轮 8 项要求）

| 要求 | 状态 |
|------|------|
| 1 source/binary 包区分 | ✅ 阶段 1 已落实，本轮复核无回归 |
| 2 advisories 唯一索引修订 | ✅ 三元组组合外键 + 九列 UNIQUE |
| 3 状态三维拆分 | ✅ 保持 |
| 4 PENDING_RESTART 证据链 | ✅ 保持（采集属阶段 5） |
| 5 pacman 预演 → Arch 不开放自动修复 | ✅ 保持 |
| 6 AL2 legacy/2026-06-30 | ✅ 保持 |
| 7 AL2 updateinfo 验证状态 | ✅ `signature_status`/`integrity_status` 实然记录 |
| 8 签名 vs TLS/哈希分层 + 资产输入 | ✅ 架构图与五字段统一 |
