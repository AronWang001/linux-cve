# 阶段 2 交付报告：资产采集与版本比较

> 阶段：2 / 9
> 分支：`feat/v2.0.0`
> 基线 HEAD：`f516e0c`

---

## 1. 任务完成情况

| # | 任务 | 状态 | 说明 |
|---|------|------|------|
| 1 | `internal/version` 四类版本比较引擎 | ✅ PASS | dpkg / rpm / apk / pacman 忠实移植 |
| 2 | `internal/inventory` 资产采集 | ✅ PASS | 发行版 / 内核 / 包清单只读采集 |
| 3 | `0002_inventory.sql` 迁移 + SaveInventory | ✅ PASS | 三表 + 事务 + 外键 + 回滚 |
| 4 | CLI `inventory` 命令 | ✅ PASS | `--json` / `--save`，退出码规范 |
| 5 | 全量验证 | ✅ PASS（含 BLOCKED 项） | 见 §4 |
| 6 | 独立审查 | ✅ PASS（P1/P2 已评估） | 见 §6 |

## 2. 新增功能清单

### 2.1 版本比较引擎（`internal/version`）

| 文件 | 内容 |
|------|------|
| `version.go` | 包文档 + `Compare`/`Parse` 分发 + 公共辅助 |
| `debian.go` | dpkg `verrevcmp` + Policy 5.6.12 切分 |
| `rpm.go` | `rpmvercmp.cc` 现代语义 + EVR 拆分 |
| `pacman.go` | `alpm_pkg_vercmp`（旧 rpm 语义怪癖） |
| `apk.go` | `version.c` tokenizer + 后缀等级 |

### 2.2 资产采集（`internal/inventory`）

| 文件 | 内容 |
|------|------|
| `runner.go` | `Runner` 接口 + `ExecRunner`（超时/输出上限） |
| `system.go` | `ParseOSRelease` + `DetectSystem` |
| `packages.go` | dpkg / rpm / apk / pacman 四路采集 |
| `kernel.go` | 内核包精确证据映射 |
| `inventory.go` | `Collector` 编排 + `Collect` |

### 2.3 数据库与 CLI

- `internal/domain/inventory.go`：`Inventory` 快照模型 + `ComputeHash`（顺序无关 SHA256）
- `internal/domain/package.go`：`ComputeEntryHash`（包记录哈希）
- `internal/database/migrations/0002_inventory.sql`：三张表
- `internal/database/inventory.go`：`SaveInventory`（单事务）+ `InventoryOverview`
- `internal/app/inventory.go`：`linux-cve inventory [--json] [--save]`

## 3. 四种版本比较算法

| 管理器 | 上游来源 | 关键规则 | 特殊边界 |
|--------|----------|----------|----------|
| dpkg | `dpkg/lib/dpkg/version.c` | `order()`：digit→0、alpha→字符、`~`→-1、其他→c+256；最后连字符切 revision | 缺失 revision ≡ "0"；`~` 早于空串；数字段去前导零按位数 |
| rpm | `rpm/rpmio/rpmvercmp.cc` | `~` 早于一切、`^` 晚于串尾早于字母数字；数字段>字母段 | 尾部剩余者胜；数字段去前导零按位数 |
| apk | `apk-tools/src/version.c` | tokenizer 语法 `digit{.digit}{letter}{_suf}{~hash}{-rN}` | `_alpha/_beta/_pre/_rc` 预发布、`_cvs/_svn/_git/_hg/_p` 后发布；前导零→串比较；无 epoch |
| pacman | `pacman/lib/libalpm/version.c` | 旧 rpm 语义：无 `~/^`、分隔符长度参与、尾部 alpha 更旧 | release 仅两侧都存在才比较（`1.0-1 == 1.0`） |

**实证差异固化**：`1.0a` vs `1.0` → dpkg/rpm = 1（更新），alpm = -1（更旧），由 `TestCrossManagerSemanticsDiffer` 固化，证明未共用字符串比较。

## 4. 全量验证结果

### 4.1 Go 工具链

| 检查 | 结果 |
|------|------|
| `gofmt -d` | ✅ PASS（无差异） |
| `go test ./... -count=1` | ✅ PASS（134 测试，0 失败） |
| `go vet ./...` | ✅ PASS |
| `go test -race ./...` | ✅ PASS |
| `go build ./...` | ✅ PASS |
| Linux AMD64 交叉编译 | ✅ PASS |
| Linux ARM64 交叉编译 | ✅ PASS |
| Windows AMD64 编译 | ✅ PASS |

### 4.2 测试统计

- 阶段 1 基线：79 测试
- 阶段 2 全量：**134 测试，全部通过**（新增约 55 个）
- 版本比较 16 个测试函数；采集 25 用例；数据库 25 测试；CLI 新增 8 测试

### 4.3 版本比较验证程度

| 级别 | 状态 |
|------|------|
| A. 上游源码语义核对 | ✅ 完成（四份源码下载留存于 `audit/refsrc/`） |
| B. 本地 Go 单元测试 | ✅ 完成（覆盖 epoch/release/前导零/分隔符/字母数字/预发布/特殊字符/边界/非法输入） |
| C. 原生工具差分测试 | ❌ **BLOCKED**（本机无 dpkg/rpm/apk/pacman/vercmp，任务书禁止装系统软件） |
| D. Linux 实机验证 | ❌ **未做**（留待后续阶段） |

### 4.4 数据库验证

| 检查 | 结果 |
|------|------|
| 0001→0002 连续迁移 | ✅ `TestMigrate0002Upgrade` |
| 重复迁移幂等 | ✅ `TestMigrateIdempotent` |
| 事务回滚 | ✅ `TestSaveInventoryRollback`（触发器制造中途失败）+ `TestApplyOneRollbackOnError` |
| 外键约束 | ✅ `TestInventoryPackagesFK` / `TestInventoryCascadeDelete` / `TestForeignKeyEnforced` |
| 重复资产保存（UNIQUE） | ✅ `TestInventoryPackageUnique` |
| EntryHash 稳定性 | ✅ 固定字段哈希 |
| 数据库重启后读取 | ✅ roundtrip |
| schema_version 一致性 | ✅ `schema_migrations` 唯一权威 |

### 4.5 旧版回归保护

- v1.3.2 的 35 个 Bash/Shell 文件（`fix.sh`、`install.sh`、`lib/*.sh`、`adapters/*.sh`、`tests/*.sh`）**全部未被修改**。
- 阶段 1 的 79 测试基线未退化（134 = 79 + 55 新增）。

## 5. 资产采集数据来源

| 管理器 | 采集命令 | SourceName 来源 | OriginChannel |
|--------|----------|-----------------|---------------|
| dpkg | `dpkg-query -W -f="${binary:Package}\t${Version}\t${Architecture}\t${Source}\t${source:Version}\t${Vendor}\t${Status}"` | `${Source}` 字段（空=桥接失败） | 一律 `unknown` |
| rpm | `rpm -qa --qf "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\t%{VENDOR}\t%{INSTALLTIME}"` | `SOURCERPM` 尾部两刀切分（`(none)`=桥接失败） | 一律 `unknown` |
| apk | `apk list --manifest` + `apk list --installed -v` | `{origin}`（工具自身输出） | 一律 `unknown` |
| pacman | `pacman -Qi` | 无 pkgbase，留空（桥接失败） | 一律 `unknown` |

内核映射仅精确证据：dpkg 系 `linux-image-<uname -r>` 精确存在；rpm 系 `<version>-<release>.<arch> == uname -r`；apk/pacman 留空。

## 6. 独立审查结果

审查方法：逐文件研读四个版本算法实现、采集逻辑、内核映射、SaveInventory 事务、CLI 分发，比对上游源码语义与任务书证据规则。

### 结论

**P0 问题：无。P1 问题：无。**

核心实现质量高：四个算法忠实移植（枚举序号、终局规则、怪癖均保留），证据规则严格（SourceName 不猜测、OriginChannel 全 unknown、内核映射仅精确证据），事务可靠（`defer Rollback` + 显式 `Commit`）。

### P2（已知，不影响正确性）

- **`--json` 输出字段名**：`inventory --json` 使用 Go 结构体默认 PascalCase 字段名（`internal/domain` 与 `internal/inventory` 无 JSON tag）。作为机器可读接口缺乏规范。已在 `docs/cli.md` 标注，建议阶段 3（`scan` 输出）统一 JSON 协议时一并对齐。

### 测试缺口与残余风险

- 原生工具差分测试（C 级）BLOCKED，需 Linux 环境补做。
- Linux 实机验证（D 级）未做，采集器真实输出格式需实机确认。
- apk 缺 `-v` 关联时丢包（架构是必填项），行为正确但实机 apk 输出格式待验证。

## 7. 尚未解决的问题

1. 原生版本比较差分测试（C 级）：BLOCKED，需 Linux 环境。
2. Linux 实机采集验证（D 级）：未做。
3. `--json` 字段命名规范：P2，留待阶段 3 统一。
4. 本阶段不开放任何自动修复（符合任务书）。

## 8. 阶段 3 开工建议

1. **情报源客户端（`internal/feed`）**：按架构文档 §3 信任分级（A/B/C），实现 Debian Tracker / Ubuntu OVAL / AL2023 updateinfo 等源的下载、签名验证（minisign/cosign keyless）、内容哈希校验。
2. **匹配引擎（`internal/matcher`）**：用 `internal/version` 的 `Compare` + `internal/inventory` 的 `Inventory`，实现 `VulnState` 三态计算（VULNERABLE / FIXED / UNKNOWN / NOT_AFFECTED）。
3. **CLI `scan`/`list`/`show`**：完成采集→匹配→输出的端到端闭环。
4. **前置补做**：在 Linux 实机补做 C 级差分测试与 D 级实机验证，消除阶段 2 的 BLOCKED 项。
5. **JSON 协议规范化**：统一对外 JSON 字段命名（snake_case），同步对齐 `inventory --json`。
