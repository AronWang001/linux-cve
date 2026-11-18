# 阶段 3.0.1 设计修订审查记录

- 版本：3.0.1-frozen
- 状态：设计修订与冻结（未实现 Feed 业务代码、未启动 CVE 匹配）
- 关联：`docs/phase3.0-design.md`（冻结主文档）、`docs/feed-source-research.md`（数据源核验）

---

## 1. 审查范围与方法

本轮对阶段 3.0 初版设计进行修订与冻结，重点复核 8 项任务。调查方式：

- **真实网络核验**：Red Hat / SUSE / Debian 端点逐一致实际请求核验（非假设历史接口），签名文件、公钥指纹、许可文本均取得原文证据。
- **文档交叉核对**：阶段 0 调查报告（`audit/phase0-data-sources.md`）、阶段 1 `data-model.md` / `architecture.md`、阶段 3.0 初版设计三方对照，修正矛盾。
- **Skills**：investigate-first（证据优先）、migration（0003 迁移设计）、review-agent（架构/安全边界审查）、verify-and-stop（最终核验）。

---

## 2. 审查结论：发现并修正的矛盾

### 2.1 [P1] Red Hat 信任分级错误（已修正）

- **初版错误**：phase3.0-design.md §4 写「仅 Red Hat 提供 PGP 签名（需进一步确认）、SUSE 无签名」，并把 Red Hat 列 B 级、SUSE 列 B 级。
- **实际证据**（已核验）：
  - Red Hat CSAF advisories 目录每个 `.json` 配 `.json.asc`（GPG）+ `.json.sha256`；`provider-metadata.json` 声明 PGP 指纹 `77E79ABE93673533ED09EBE2DCE3823597F5EAC4` + `role=csaf_trusted_provider`。
  - SUSE 每个 `.json` 配 `.asc` + `.sha256` + `.sha512`；公钥 `security-automation.asc`。
- **修正**：Red Hat 升 A 级；SUSE 保持 A 级；A 级签名源 = 2 个（Red Hat + SUSE）。

### 2.2 [P1] Red Hat 主数据源未随官方弃用调整（已修正）

- **初版**：以 OVAL v2 为主数据源。
- **官方证据**：OVAL v2 弃用公告 + RHEL 10 发行说明明确「OVAL/DS v2 进入维护模式，RHEL 10 起不再发布」。
- **修正**：CSAF Advisory + per-CVE VEX 为主，OSV（经 OSV.dev）交叉，OVAL v2 仅兼容。

### 2.3 [P1] Schema DDL 与阶段 1 权威定义漂移（已修正）

- **初版问题**：phase3.0-design.md §5 的 `advisories` 表用 `uid` 主键 + 单一 `fixed_version` + `raw_payload BLOB`，与阶段 1 `data-model.md` §4.4（`uid` 主键 + `fixed_version_raw`/`fixed_epoch`/`fixed_version`/`fixed_release` 三元组 + 无 raw_payload）不一致；且初版 `advisories` 多加了 `distro_id`/`release` 维度（阶段 1 契约里发行版维度在 advisory_fixes）。
- **修正**：`data-model.md` §4.4 为权威口径；0003 只新增表 + 加溯源列，不重建既有表；`advisories` 本体保持「源+公告号+CVE」三元组，发行版维度归 advisory_fixes。

### 2.4 [P2] Feed 存储每 CVE 重复存全量文件（已修正）

- **初版问题**：`advisories.raw_payload BLOB` 每行存完整原始数据，Debian 90MB JSON 会被 4k+ 包各存一份，爆炸式膨胀。
- **修正**：改为「不可变 Artifact（内容哈希寻址，跨公告共享）+ 归一化记录携带 `artifact_sha256`/`raw_locator`/`raw_record_hash` 追溯」。

### 2.5 [P2] 原子更新未处理文件系统+SQLite 非原子提交（已修正）

- **初版**：只提「staging 表 + 单事务 swap」，未解决 Artifact 文件落盘与 SQLite 提交之间崩溃的半更新。
- **修正**：两段式提交（先落不可变 Artifact，后单事务写归一化 + 翻转 active 指针），补并发锁、崩溃恢复、磁盘不足、重复更新。

---

## 3. 各项任务完成情况

| # | 任务 | 状态 | 关键产出 |
|---|------|------|----------|
| 1 | 修订 Red Hat 数据源策略 | ✅ | CSAF/VEX 为主，OVAL 兼容；信任分级升 A；`feed-source-research.md` §2 |
| 2 | 补充 SUSE 数据源 | ✅ | CSAF Advisory + 独立 CSAF VEX；changes/deletions 增量；CC-BY-4.0；`feed-source-research.md` §3 |
| 3 | Debian DSA/DLA 关联 | ✅ | 三层关联；再分发授权未确认、禁止默认打包；`feed-source-research.md` §4 |
| 4 | 覆盖范围 COVERED/PARTIAL/UNKNOWN | ✅ | 官方仓库/第三方/手动/自编译/容器/应用依赖六类；`phase3.0-design.md` §8.1 |
| 5 | 修订 Feed 存储架构 | ✅ | Artifact 内容寻址 + Snapshot；`data-model.md` §4.3.1 |
| 6 | 修订原子更新机制 | ✅ | 两段式提交 + 崩溃恢复；`phase3.0-design.md` §3.2 |
| 7 | Feed 解析安全 | ✅ | 统一护栏 + XXE 禁用 + zip-bomb；`phase3.0-design.md` §3.5 |
| 8 | CLI JSON 契约收尾 | ✅ | schema_version 升 2；架构规范化落地代码 + 测试 |

---

## 4. 任务 8 专项：CLI JSON 契约

### 4.1 schema_version 升至 2

- `internal/app/inventory_dto.go` 的 `inventorySchemaVersion` 从 1 → 2。
- 依据：`saved_inventory_id` 是新增字段，按 cli.md 契约「新增字段递增版本」。虽可选字段（`omitempty`）属向后兼容，但 v1 从未正式发布，直接以 2 作为首个对外稳定版本，消除「从未发布的 v1」歧义。
- 契约细化（写入 cli.md §3.1.1）：新增可选字段可不递增；新增必填/改名/删除/类型变更必须递增。

### 4.2 架构规范化（真实代码改动）

发现 DTO 直接输出 `inv.Arch` / `p.Ref.Arch` 原始值（rpm 系为 `x86_64`），与「统一架构规范」要求不符。落地：

- `internal/app/inventory_dto.go` 新增 `canonicalArchOrKeep`，对 `distro.arch` / `packages[].arch` 用 `domain.CanonicalArch` 归一（`x86_64`→`amd64`、`aarch64`→`arm64`、`all`/`noarch`→`all`），无法识别时保留原值不丢信息。
- 明确「原始架构 vs 规范化架构」：领域模型 `Inventory.Arch`/`PackageRef.Arch` 保留 `uname -m` 原值（审计/内核映射），CLI JSON 输出规范化名（下游匹配）。
- 新增测试 `TestInventoryJSONArchCanonical`（rpm 系 `x86_64` → 输出 `amd64`）。

### 4.3 空值语义与 saved_inventory_id 存在条件

- `saved_inventory_id` 用 `*int64` + `omitempty`，仅 `--save` 成功时有值，否则字段缺省不出现。
- 空数组 `[]`、空串 `""`、时间 UTC RFC3339（零值空串）语义已在 cli.md 固化。

---

## 5. 数据许可与归属

| 源 | 许可 | 归属 | 再分发确认 |
|----|------|------|-----------|
| Red Hat | CC-BY-4.0 | 归属 + 原始链接 | ✅ |
| SUSE | CC-BY-4.0 | 归属 SUSE | ✅ |
| Debian | 无正式许可 | 归属 Security Team | ⚠️ 未确认（2026-11 邮件列表仍在询问） |
| Ubuntu / Alpine / Arch | 未确认 | 待调查 | ⚠️ 未确认 |

**结论**：未确认再分发授权的源，运行期按需拉取 + 本机缓存 + 报告保留来源与归属，**不打包进公开发布资产**。阶段 3.1 补齐 Ubuntu/Alpine/Arch 许可调查。

---

## 6. 遗留问题与风险

| # | 事项 | 等级 | 说明 |
|---|------|------|------|
| 1 | Ubuntu/Alpine/Arch 许可与再分发授权未确认 | 中 | 阶段 3.1 补齐调查 |
| 2 | SUSE 无 `provider-metadata.json`，信任锚为目录内公钥文件 | 中 | 实现时固化 `security-automation.asc` 指纹，检测轮换 |
| 3 | Red Hat per-CVE VEX 按需拉取，需维护 CVE→VEX 索引 | 中 | RSS（近 3 天）+ 年份目录扫描 |
| 4 | 原生版本比较 C 级差分测试仍 BLOCKED（阶段 2 遗留） | 中 | 需 Linux 环境，不属本轮范围 |
| 5 | Linux 实机采集 D 级验证未做（阶段 2 遗留） | 中 | 阶段 4/5 补 |

---

## 7. 阶段 3.1 实施路线

1. 落地 `internal/feed` 下载/缓存层：不可变 Artifact + ETag 条件请求 + A 级源签名验证 + 解析安全护栏。
2. 落地 0003 迁移（feed_artifacts/feed_snapshots/溯源列）与两段式原子提交。
3. 按 Alpine → Arch → Debian → Ubuntu → Red Hat CSAF/VEX → SUSE CSAF/VEX 顺序实现解析器。
4. 每源真实小样本解析 + 匹配差分；A 级源补签名验证测试。
5. 阶段 3 只交付 `VulnState` 判定，不实现修复可行性。
6. 补齐 Ubuntu/Alpine/Arch 许可调查。

---

## 8. 停止状态

本轮以文档与设计修订为主，未开发六大 Feed 解析器、未开发 CVE 匹配业务。已完成冻结，等待阶段 3.1 授权。
