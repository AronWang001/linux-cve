# 阶段 3.0 设计：漏洞情报采集、归一化、存储与匹配

- 版本：3.0.1-frozen
- 状态：设计修订与冻结（未进行大规模业务编码）
- 依赖：阶段 1 数据模型与状态契约（`docs/data-model.md`）、阶段 2 资产采集与版本比较
- 关联：`docs/feed-source-research.md`（六大数据源最终核验）、`docs/phase3.0.1-review.md`（本轮审查记录）

> 本阶段为**只读调查与设计**，端点与格式均重新核验（2026-11-18/19），
> 不假定历史接口未变。数据源端点/格式/签名/许可详见 `docs/feed-source-research.md`。

> **本轮冻结的重大修订**（相对 3.0-draft.1）：
> 1. Red Hat 主数据源从 OVAL v2 转为 CSAF Advisory + per-CVE VEX；信任分级从 B 级**升为 A 级**（实测有 GPG `.asc` + SHA256 + CSAF 信任锚）。
> 2. SUSE 补充独立 CSAF VEX（`csaf-vex/` 目录）。
> 3. Debian 补充 DSA/DLA 三层关联，再分发授权未确认、禁止默认打包。
> 4. Feed 存储改为「不可变 Artifact（按内容哈希）与归一化数据分离」。
> 5. 原子更新改为「文件系统 + SQLite 分离提交」，明确崩溃恢复。
> 6. 明确 COVERED / PARTIAL / UNKNOWN 覆盖范围。

---

## 1. 官方数据源最终核验（摘要）

> 完整端点、签名指纹、许可、增量机制见 `docs/feed-source-research.md`。下表为策略摘要。

| # | 数据源 | 主判定依据 | 更新机制 | 签名 | 信任级别 |
|---|--------|-----------|----------|------|----------|
| 1 | Debian | Security Tracker JSON + DSA/DLA 公告 | SHA256 比对（无 ETag） | 无 | B |
| 2 | Ubuntu | OVAL（cve/usn 类） | ETag / Last-Modified | 无 | B |
| 3 | Red Hat | **CSAF Advisory + per-CVE VEX**（OVAL v2 已弃用） | 年目录 + RSS（近 3 天） | **GPG `.asc`** | **A** |
| 4 | SUSE | **CSAF Advisory + CSAF VEX** | `index.txt` + `changes.csv` + `deletions.csv` | **GPG `.asc`** | **A** |
| 5 | Alpine | secdb（main/community） | `last-update` 时间戳 | 无 | B |
| 6 | Arch | Security Tracker `all.json` | SHA256 比对 | 无 | B |

### 1.1 相对阶段 3.0 初版的关键修订

1. **Red Hat 信任分级修正（B→A）**：初版误标「Red Hat 无签名」。实测 CSAF/VEX 每文件配 `.asc` + `.sha256`，`provider-metadata.json` 声明 PGP 公钥指纹 `77E79ABE93673533ED09EBE2DCE3823597F5EAC4`，`role=csaf_trusted_provider`。
2. **Red Hat 主数据源迁移**：OVAL v2 已官方弃用（维护模式，RHEL 10 起不再发布），改用 CSAF + VEX 为主，OSV（经 OSV.dev）交叉，OVAL 仅兼容。
3. **SUSE 补充 CSAF VEX**：独立 `csaf-vex/` 目录（2023–2026），配 `changes.csv`/`deletions.csv`/`index.txt`。
4. **Debian DSA/DLA 三层关联**：Tracker JSON 提供判定，DSA/DLA 提供公告链接；再分发授权未确认，禁止默认打包。
5. **签名源由 1 个增至 2 个**：SUSE + Red Hat 均为 A 级（GPG 分离签名）。

---

## 2. Feed 数据模型（统一 Advisory + 存储分层）

> 设计原则：不同数据源字段差异大，统一模型**不得丢失原始证据**。
> 统一字段用于匹配与展示；无法归一的字段落到归一化之外的**不可变 Artifact** 保留。

### 2.0 存储分层（修订）

原始情报文件**按内容哈希保存为不可变 Artifact**，不按 CVE 重复保存完整文件。
归一化记录只存「指向 Artifact 的引用 + 原始记录定位」，不内嵌全文。

```
Feed Source（静态配置：端点/信任级别/签名公钥）
   └─ Feed Snapshot（一次成功同步的归一化结果集，含 active 指针）
         └─ Feed Artifact（不可变原始文件，按 sha256 内容寻址，跨公告共享）
                └─ Advisory（归一化公告，引用 Artifact + 原始记录定位）
                     ├─ Advisory Package（受影响/修复的包与版本）
                     ├─ Advisory CVE（关联的 CVE）
                     └─ Advisory Evidence（判定依据与原始定位）
```

```go
// FeedSource 是静态数据源配置（阶段 1 已在 feed_sources 表建模，此处确认契约）。
type FeedSource struct {
    ID            string // debian-tracker / ubuntu-oval / redhat-csaf / suse-csaf / alpine-secdb / arch-tracker / ...
    TrustLevel    string // A | B | C
    SignatureKind string // none | gpg | csaf | ...
    PublicKeyFP   string // A 级源的 PGP 公钥指纹（Red Hat / SUSE）
    URL           string
}

// FeedArtifact 是内容寻址的不可变原始文件。
// 一个 Artifact 可能被多条 Advisory 引用（如 Debian 90MB JSON 被 4k+ 包共享）。
type FeedArtifact struct {
    SHA256        string // 内容哈希 = 主键（内容寻址，天然去重）
    SourceID      string
    SizeBytes     int64
    DownloadURL   string
    FetchedAt     time.Time
    SignatureStatus string // verified | failed | not-applicable
    IntegrityStatus  string // verified | failed
    StoredPath    string // 本地不可变文件路径（文件名 = sha256）
}

// FeedSnapshot 是一次成功同步的归一化结果集。
type FeedSnapshot struct {
    ID          string // 内容派生
    SourceID    string
    Artifacts   []string // 引用的 artifact sha256 列表
    StartedAt   time.Time
    CompletedAt time.Time
    IsActive    bool      // active 指针：只有完整成功提交后翻转
}

// Advisory 是跨源统一的漏洞公告（归一化，不内嵌原始全文）。
type Advisory struct {
    UID          string    // sha256(source_id|advisory_id|cve_id)[:16]，内容派生、顺序无关
    SourceID     string
    AdvisoryID   string    // DSA-5810-1 / USN-9018-1 / RHSA-2026:93414 / SUSE-SU-... / AVG-2843
    CVEID        string    // 主 CVE；一个公告可关联多个 CVE（issues[] 展开为多行）
    DistroID     string
    Release      string
    Title        string
    Severity     string    // 展示用，不参与判定
    Description  string
    PublishedAt  *time.Time
    UpdatedAt    *time.Time
    ReferenceURL string
    // 可追溯性（修订）：不存全文，存指向 Artifact 的引用 + 定位
    ArtifactSHA256  string // 指向 FeedArtifact
    RawLocator      string // 原始记录定位：JSON 路径 / OVAL definition id / CSAF 文档 id
    RawRecordHash   string // 原始记录自身哈希（sha256(原始记录字节)）
    ParserVersion   string // 解析器版本
}

// AdvisoryFix 是公告中「某包某渠道的修复版本」声明（对应阶段 1 advisory_fixes 表）。
type AdvisoryFix struct {
    AdvisoryUID  string
    SourceID     string
    AdvisoryID   string
    CVEID        string
    DistroID     string
    Release      string
    Channel      string          // bookworm-security / amzn2023-core / ...
    Kind         domain.PackageKind  // source | binary
    PackageName  string
    Arch         string          // any | all | 原生架构（缺省 any）
    FixedVersion string          // 原始字符串，逐字保留
    FixedAt      *time.Time
    EvidenceURL  string
}

// AdvisoryNotAffected 是「官方明确声明不受影响」的证据（显式 NOT_AFFECTED）。
type AdvisoryNotAffected struct {
    SourceID    string
    AdvisoryID  string
    CVEID       string
    DistroID    string
    Release     string
    PackageKind domain.PackageKind
    PackageName string
    Arch        string
    Reason      string   // not-affected / not-in-release / vulnerable-code-absent / end-of-life
    EvidenceURL string
}
```

**不可变与归一化的关系**：

- Artifact 是**不可变原始字节**，按 sha256 内容寻址，一旦落盘永不改写；被撤回/删除的公告不删除 Artifact，只在归一化层标记状态。
- Advisory/Fix/NotAffected 是**归一化记录**，可随解析器版本演进重建；每条都携带 `ArtifactSHA256` + `RawLocator` + `RawRecordHash` 追溯原始证据。
- 归一化失败或需要重解析时，从 Artifact 重新解析即可，不依赖已丢失的中间态。

### 2.1 各源字段映射（保留原始证据）

| 统一字段 | Debian | Ubuntu OVAL | Red Hat CSAF/VEX | SUSE CSAF | Alpine secdb | Arch |
|----------|--------|-------------|------------------|-----------|--------------|------|
| AdvisoryID | DSA/DLA 编号（RSS 反查） | USN-xxxx-x | RHSA-... | SUSE-SU-... | （无公告号） | AVG-xxxx |
| CVEID | 包下 CVE 键 | OVAL CVE | VEX 文档 id（cve-...） | CSAF | secdb 条目 | issues[] |
| 受影响/修复版本 | releases[代号].fixed_version | OVAL test | VEX product_status + remediations | affected/fixed | secdb fixed | affected/fixed |
| NOT_AFFECTED 证据 | status=resolved + nodsa | OVAL state | VEX `known_not_affected`/`fixed` | `known_not_affected` | 无该包条目≠不涉及 | status="Not affected" |
| 严重程度 | urgency | OVAL severity | VEX threats + CVE CVSS | CSAF | secdb severity | severity |
| 源码包↔二进制映射 | 按源码包组织 | 按二进制包（有 src 元数据） | VEX product_tree 二进制 + SRPM | 源码包+二进制包 | origin | packages[]（无 pkgbase） |

**核心证据规则**（延续阶段 2 的严谨性）：

- Debian `status=resolved` + `fixed_version` 才是 FIXED 证据；`status=open` 是 VULNERABLE；`nodsa=true` 表示「不修复」，仍需作为 VULNERABLE 但记 no-fix。
- Red Hat VEX 的 `product_status.fixed` 才判 FIXED；`known_affected` 判 VULNERABLE；`known_not_affected` 判 NOT_AFFECTED；`under_investigation` 判 UNKNOWN；`will-not-fix`（Red Hat「不修复」）记 VULNERABLE + NO_FIX。
- 「该源没有某 CVE 的记录」**不等于 NOT_AFFECTED**；只有显式 `not-affected` / `known_not_affected` 才算。
- 无法证明时必须落 `UNKNOWN`，记 `source_gap` 证据。

---

## 3. Feed 更新机制

### 3.1 分层缓存与增量

```
远端（各源） ──ETag/Last-Modified──▶ 下载临时文件 ──校验──▶ 不可变 Artifact（sha256 寻址）──解析──▶ 情报库（SQLite）
```

- **首次全量**：逐源下载完整文件（Debian ~90MB 一次性）。
- **增量**：
  - 有 ETag/Last-Modified 的源（Ubuntu/RedHat/SUSE/Alpine）用条件请求（`If-None-Match` / `If-Modified-Since`），304 则跳过。
  - SUSE 用 `changes.csv` + `deletions.csv`（**累计历史，按时间戳过滤**出新增/变更/撤回）。
  - Red Hat 用年份目录 + RHSA RSS（近 3 天，需每日轮询）；per-CVE VEX 按 CVE 按需拉取。
  - Debian/Arch 无 ETag，用「下载→SHA256 与上次比对」判定；相同则跳过写库。
- **本地缓存**：原始文件落为不可变 Artifact（文件名=sha256），解析产物才进 SQLite。

### 3.2 原子更新与恢复（文件系统 + SQLite 分离提交）

文件系统与 SQLite **不能共同原子提交**，因此采用「先落不可变 Artifact，后单事务提交归一化数据」的两段式流程，任一步失败都不破坏上一份有效情报：

1. 下载到临时文件（`.tmp` 后缀，独立于正式数据目录）。
2. 验证传输状态（HTTP 状态、完整读入）。
3. 验证文件大小与哈希（`content_bytes` + SHA256）。
4. 若源提供数字签名（Red Hat/SUSE 的 `.asc`），用固化公钥指纹验证签名。
5. 解析并完成数据质量检查（记录数、必填字段、异常隔离）。
6. 将原始文件**按内容哈希**保存为不可变 Artifact（同内容天然去重，跳过已存在的）。
7. 使用 SQLite **单事务**写入新 FeedSnapshot 与归一化数据（Advisory/Fix/NotAffected）。
8. 事务内更新 active snapshot 指针（`IsActive` 翻转）。
9. 事务提交成功后再清理旧快照与无引用 Artifact（延迟 GC）。

**失败语义**：

| 步骤失败 | 行为 |
|----------|------|
| 下载/传输失败 | 返回错误，不触碰已有库与 Artifact |
| 哈希/签名验证失败 | 丢弃临时文件，`signature_status`/`integrity_status` 记 failed，不写库 |
| 解析/质量检查失败 | 丢弃归一化结果，Artifact 保留供排查，不写库 |
| 事务中途失败 | SQLite 整体回滚，active 指针不变，上一份情报完好 |

**并发与崩溃恢复**：

- 并发更新：SQLite `BEGIN IMMEDIATE` 或文件锁（`.lock`）串行化同一源的更新，避免双写。
- 进程崩溃：临时文件 `.tmp` 与未提交事务在下次启动时清理；active 指针只在事务提交时原子翻转，崩溃不会留下「半更新」的可读快照。
- 磁盘空间不足：写入前预估所需空间，不足则拒绝并保留旧库；Artifact 写盘用「写临时→rename」避免半写文件。
- 重复更新：同一内容 Artifact 因 sha256 寻址天然去重；重复快照通过快照内容哈希判等跳过。

### 3.3 元数据

`app_meta` 固定键（阶段 1 已定）：`feed_last_update`（上次成功同步时间）、`feed_snapshot_hash`（内容哈希）、`db_created_at`、`db_engine_version`。数据新鲜度由 `feed_last_update` 与各源 `last-update`/`changes.csv` 时间戳共同判定。

### 3.4 断网降级

`--offline` 或网络失败时，使用**最近一次成功同步**的情报库 + 本地缓存，明确标记数据新鲜度（报告里显示「情报库截至 X，已过期 N 天」），不阻塞本地扫描。

### 3.5 解析安全（统一限制）

所有数据源共用一套解析护栏，损坏/恶意/格式变化文件不能导致情报库半更新：

| 限制项 | 默认值（可配置） |
|--------|------------------|
| HTTP 超时 | 60s |
| 最大下载体积 | 源相关（Debian 120MB，其余 64MB 上限） |
| 最大解压体积 | 下载体积 × 8，且 ≤ 512MB |
| 最大解压比例 | 8:1（超出判定 zip-bomb 拒绝） |
| JSON 嵌套深度 | ≤ 64 |
| XML 外部实体（XXE） | **禁用**（`encoding/xml` 不解析外部实体；流式解析） |
| 单条记录最大长度 | 1MB |
| 异常记录隔离 | 单条解析失败跳过并计数，不中断整批；异常率超阈值则整批拒绝 |

- ETag / Last-Modified **仅作为缓存验证机制**，不能替代完整性校验。
- 损坏文件、恶意文件、格式变化 → 该源本次更新整体失败，保留上一份有效情报，`status='error'` 记 `last_error`。

---

## 4. 数据真实性与信任机制（严格分层）

| 层级 | 机制 | 回答的问题 | 哪些源实际提供 |
|------|------|-----------|----------------|
| 1. 传输安全 | HTTPS | 传输中不被窃听/篡改（中间人） | 全部 |
| 2. 内容完整性 | SHA256 | 下载文件与发布方一致（防传输损坏/缓存污染） | RedHat/SUSE 提供 `.sha256`；其余自算+比对 |
| 3. 数字签名 | GPG `.asc` | 内容确由发布方签发（防上游被入侵） | **Red Hat CSAF/VEX、SUSE CSAF/VEX** |
| 4. 构建来源证明 | cosign OIDC | 二进制/工件可追溯到构建者 | 本项目自身发布时用（阶段 8），**情报源不适用** |

**硬规则**：

- 只有数据源**真正提供签名**时才执行签名验证；不得把 HTTPS 或 SHA256 描述成「数字签名」。
- A 级源签名验证用 `provider-metadata.json`（Red Hat）或官方目录公钥（SUSE）声明的**固化指纹**，检测密钥轮换与吊销：指纹不符 → 拒绝并告警，不静默换钥。
- 各源信任分级（供报告展示，不改变判定逻辑）：

| 源 | 传输 | 完整性 | 签名 | 综合信任 |
|----|------|--------|------|----------|
| Debian | HTTPS | 自算 SHA256 | 无 | B（HTTPS+内容哈希，无签名） |
| Ubuntu | HTTPS | 自算 SHA256 | 无 | B |
| Red Hat | HTTPS | `.sha256` | **GPG `.asc`** | **A** |
| SUSE | HTTPS | `.sha256`/`.sha512` | **GPG `.asc`** | **A** |
| Alpine | HTTPS | last-update 时间戳 | 无 | B |
| Arch | HTTPS | 自算 SHA256 | 无 | B |

- 未签名的源，完整性靠「SHA256 + 与上次比对」防损坏，但**不能**防上游被入侵。这在报告中如实标注，不夸大。

---

## 5. SQLite Schema 迁移设计（0003_feed.sql）

> **权威定义**：`advisories` / `advisory_fixes` / `advisory_not_affected` / `cves` / `cve_references`
> 已在阶段 1 `docs/data-model.md` §4.3–4.6 定义，0001 已建表。0003 **不重复建这些表**，
> 只新增 Feed 存储分层所需的表，并确认这些既有表的字段为权威口径（以 data-model.md 为准）。

### 5.1 0003 新增表（Feed 存储分层）

```sql
-- 不可变原始文件（内容寻址，跨公告共享）
CREATE TABLE feed_artifacts (
    sha256           TEXT PRIMARY KEY,          -- 内容哈希 = 主键
    source_id        TEXT NOT NULL REFERENCES feed_sources(id),
    size_bytes       INTEGER NOT NULL,
    download_url     TEXT NOT NULL,
    fetched_at       TEXT NOT NULL,
    signature_status TEXT NOT NULL DEFAULT 'not-applicable'
                     CHECK (signature_status IN ('verified','failed','missing','not-applicable','unverified')),
    integrity_status TEXT NOT NULL DEFAULT 'unchecked'
                     CHECK (integrity_status IN ('verified','failed','unchecked')),
    stored_path      TEXT NOT NULL              -- 本地文件路径（文件名=sha256）
);

-- 一次成功同步的归一化结果集（active 指针）
CREATE TABLE feed_snapshots (
    id             TEXT PRIMARY KEY,            -- 内容派生
    source_id      TEXT NOT NULL REFERENCES feed_sources(id),
    started_at     TEXT NOT NULL,
    completed_at   TEXT,
    is_active      INTEGER NOT NULL DEFAULT 0,  -- 1=当前有效；仅事务提交时翻转
    content_hash   TEXT NOT NULL,               -- 快照内容哈希，用于重复更新判等
    parser_version TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX idx_snapshot_active ON feed_snapshots (source_id) WHERE is_active = 1;

-- 快照 ↔ artifact 多对多
CREATE TABLE feed_snapshot_artifacts (
    snapshot_id  TEXT NOT NULL REFERENCES feed_snapshots(id) ON DELETE CASCADE,
    artifact_sha TEXT NOT NULL REFERENCES feed_artifacts(sha256),
    PRIMARY KEY (snapshot_id, artifact_sha)
);
```

### 5.2 既有表字段对齐（0003 迁移时的改动）

- `advisories` **移除** `raw_payload BLOB` 与 `raw_hash`（初版草案），改为
  `artifact_sha256 TEXT` + `raw_locator TEXT` + `raw_record_hash TEXT` + `parser_version TEXT`，
  指向 `feed_artifacts`，避免每条 CVE 重复存完整原始文件。
  （阶段 1 的 `advisories` 表以 `uid` 为主键，字段见 data-model.md §4.4，此处不重复建表，仅记录需在 0003 迁移中新增的溯源列。）
- `advisory_fixes` 以阶段 1 §4.4 定义为准：`fixed_version_raw` + `fixed_epoch` + `fixed_version` + `fixed_release`
  三元组拆分（初版草案的单一 `fixed_version` 已被修订 P1 取代）。
- `advisory_not_affected` 以阶段 1 §4.5 定义为准，含 `package_kind` + `arch` 维度。

### 5.3 findings（阶段 3 匹配产物，与 0003 同批落地）

```sql
CREATE TABLE findings (
    id                INTEGER PRIMARY KEY,
    scan_id           TEXT NOT NULL,            -- 一次扫描 = 一个 inventory + 一组 findings
    inventory_id      INTEGER NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL,
    package_name      TEXT NOT NULL,
    package_arch      TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version     TEXT NOT NULL DEFAULT '',
    vuln_state        TEXT NOT NULL CHECK (vuln_state IN ('VULNERABLE','FIXED','NOT_AFFECTED','UNKNOWN','UNSUPPORTED')),
    remediation_state TEXT NOT NULL CHECK (remediation_state IN ('FIX_AVAILABLE','NO_FIX','FIX_PENDING_MIRROR','MANUAL_REQUIRED','BLOCKED','NOT_APPLICABLE','UNKNOWN')),
    reboot_state      TEXT NOT NULL CHECK (reboot_state IN ('NOT_REQUIRED','REQUIRED','UNKNOWN')),
    confidence        TEXT NOT NULL CHECK (confidence IN ('CONFIRMED','LIKELY','UNKNOWN')),
    evidence          TEXT NOT NULL DEFAULT '', -- JSON：命中依据、候选 fix、compare_error、source_gap 等
    UNIQUE (scan_id, cve_id, package_name, package_arch)
);
```

迁移要求（延续阶段 1/2 的硬约束）：

- 外键、`schema_migrations` 唯一权威、同事务、校验和、0002 可升级、幂等、失败整体回滚。
- `findings.vuln_state` / `remediation_state` / `reboot_state` 三列**独立存在**，禁止合并为单一枚举（阶段 1 修订 3 的契约）。
- 0003 只新增表 + 给既有表加溯源列，**不重建** `advisories` 等既有表；迁移前用 `PRAGMA table_info` 确认既有列，避免与 data-model.md 权威定义漂移。

---

## 6. CVE 匹配规则

### 6.1 源码包↔二进制包映射（逐源解决）

| 场景 | 映射证据 | 匹配键 |
|------|----------|--------|
| Debian 源码包 | Tracker 按源码包组织 | 安装包 `SourceName`（dpkg `${Source}`）→ 源码包名 |
| RPM SourceRPM | OVAL/CSAF 含 SRPM 名 | 安装包 `SourceName`（rpm `SOURCERPM` 解析）→ SRPM 名 |
| APK origin | secdb 按包名，origin 指向源包 | 安装包 `SourceName`（apk `{origin}`）→ 源包名 |
| Pacman 无 pkgbase | **无可靠源码包名证据** | `SourceName` 留空 → 只能做 binary↔binary 匹配，源码包级公告落 `UNKNOWN` |

### 6.2 匹配算法（阶段 1 §5 已定契约，此处确认）

对每个 CVE：
1. 取该 `(distro, release)` 下所有 `advisory_fixes`，按 `(channel, package_name)` 分组。
2. `kind=source` → 命中 `{p | p.SourceName == fix.package_name && archMatch}`；`kind=binary` → 命中 `{p | p.Name == fix.package_name && archMatch}`。
3. 用包管理器原生规则（`internal/version.Compare`）比较 `p.Version` 与 `fix.FixedVersion`：`<` → VULNERABLE，`>=` → FIXED（回移补丁自然成立），不可比 → UNKNOWN。
4. 多渠道取「已启用渠道」中最低固定版本，全部候选写入 Evidence。
5. 显式 `advisory_not_affected` → NOT_AFFECTED。
6. 无数据 → UNKNOWN（记 `source_gap`）。

### 6.3 关键边界（必须正确处理）

- **同名不同架构**：`archMatch` 按 `domain.ArchMatches`（`any` 通配、`all/noarch` 互配、原生架构按规范名互配、未登记一律不匹配）。
- **同名不同发行版**：匹配前先锁 `(distro_id, release)`，跨发行版不串扰。
- **不同 release**：Debian 的 bookworm/trixie、Ubuntu 的 jammy/noble 严格隔离；release 未登记的安装包（事实采集允许）在匹配阶段落 `UNSUPPORTED`（planner 准入查 `distro_releases`）。
- **回移补丁**：`p.Version >= fix.FixedVersion` 即 FIXED，无需识别 `~deb12u1` 等回移后缀（版本比较引擎已正确处理）。
- **一 CVE 多公告**：合并同 `(cve, package)` 的多条 fix，取最低固定版本。
- **一包多 CVE**：逐 CVE 独立产出 finding，不合并。
- **官方无记录的 CVE**：不是 NOT_AFFECTED，落 `UNKNOWN` + `source_gap`。

---

## 7. 漏洞状态判定规则（三维独立）

沿用阶段 1 §3（`VulnState` × `RemediationState` × `RebootState`），**不重新合并**：

- `VulnState`（检测结论）：`VULNERABLE` / `FIXED` / `NOT_AFFECTED` / `UNKNOWN` / `UNSUPPORTED`。
- `RemediationState`（修复可行性）：`FIX_AVAILABLE` / `NO_FIX` / `FIX_PENDING_MIRROR` / `MANUAL_REQUIRED` / `BLOCKED` / `NOT_APPLICABLE` / `UNKNOWN`。
- `RebootState`（运行时生效）：`NOT_REQUIRED` / `REQUIRED` / `UNKNOWN`。

阶段 3 落地 `VulnState` 的**判定**（匹配引擎输出）；`RemediationState`/`RebootState` 由阶段 4/5 的 planner/remediation 填充。阶段 3 只保证三者独立建模，不提前实现修复可行性。

**硬约束**：

- 查不到 CVE 记录 ≠ NOT_AFFECTED；无充分证据 = UNKNOWN。
- `VulnState=VULNERABLE` 才可能触发修复；其余状态 `RemediationState=NOT_APPLICABLE`。

---

## 8. 数据源支持矩阵（阶段 3 目标）

| 源 | 检测 | 源码包映射 | 二进制包映射 | 增量更新 | 签名 |
|----|------|-----------|-------------|----------|------|
| Debian | ✅ | ✅（源码包组织） | ✅（Source 桥接） | SHA256 比对 | 无 |
| Ubuntu | ✅ | ✅（OVAL src） | ✅（OVAL 二进制） | ETag/304 | 无 |
| Red Hat | ✅ | ✅（VEX product_tree） | ✅ | 年目录 + RSS | **GPG `.asc`** |
| SUSE | ✅ | ✅（CSAF 产品树） | ✅ | changes.csv/deletions.csv | **GPG `.asc`** |
| Alpine | ✅ | ✅（origin） | ✅ | last-update | 无 |
| Arch | ✅ | ❌（无 pkgbase） | ✅（all.json packages） | SHA256 比对 | 无 |

### 8.1 覆盖范围（COVERED / PARTIAL / UNKNOWN）

| 软件来源 | 覆盖状态 |
|----------|----------|
| 官方发行版仓库（含 backports/security 通道） | COVERED |
| 官方已发布但本机仓库未同步的修复包 | COVERED（检测）/ PARTIAL（修复） |
| 第三方软件仓库（EPEL 等） | PARTIAL（仅官方数据显式覆盖时判定） |
| 用户手动安装的 .deb/.rpm | PARTIAL（可采集，无公告对应 → UNKNOWN） |
| 自行编译软件（/usr/local） | UNKNOWN（不在包管理器清单，不判定） |
| 容器内软件 | UNKNOWN（v2.0 首期排除） |
| pip/npm/maven/go modules 应用依赖 | UNKNOWN（v2.0 首期排除） |

**硬规则**：无官方公告记录 ≠ 安全；NOT_AFFECTED 仅来自显式官方声明；NVD/CVE.org 仅作元数据补充，不替代发行版回移证据。

---

## 9. 测试策略

1. **解析器单测**：每源构造真实样本（从各源下载的**真实小样本**，标注 REAL）+ 人工构造边界样本（SYNTHETIC），验证字段映射与证据保留。
2. **归一化测试**：跨源异构数据归一为统一 Advisory，验证原始证据（`artifact_sha256` + `raw_locator` + `raw_record_hash`）无损。
3. **匹配引擎测试**：覆盖 §6.3 全部边界（架构、发行版隔离、release、回移、多公告、多 CVE、source_gap、UNKNOWN vs NOT_AFFECTED）。
4. **增量更新测试**：模拟 ETag 304、changes.csv/deletions.csv 增量（含撤回保留历史）、下载失败不删库、解析失败不写半成品。
5. **原子更新与恢复测试**：并发更新锁、进程崩溃恢复（临时文件清理、active 指针原子性）、磁盘空间不足、重复更新去重。
6. **迁移测试**：0003 连续迁移、幂等、回滚、外键。
7. **签名验证测试**：Red Hat/SUSE 有效签名通过、指纹不符拒绝、密钥轮换告警、无签名源 `not-applicable`。
8. **解析安全测试**：zip-bomb（解压比超限）、XXE（外部实体拒绝）、超深嵌套、超长记录、异常记录隔离与整批拒绝阈值。
9. **差分测试**：匹配结果与官方已知结论对照（如已知 CVE 在 Debian 12 的状态）。
10. **夹具区分**：REAL（真实下载样本）与 SYNTHETIC（人工构造）严格标注，不混用、不冒称实机。

---

## 10. 风险清单

| # | 风险 | 等级 | 缓解 |
|---|------|------|------|
| 1 | Debian ~90MB 全量无增量端点，每次比对成本高 | 中 | 本地缓存 + SHA256 比对；仅在变化时写库；至多每日一次 |
| 2 | Red Hat OVAL v2 已弃用，历史依赖需迁移 | 高 | 改用 CSAF+VEX 为主；OVAL 仅兼容，不做新功能 |
| 3 | 签名源只有 2 个（Red Hat/SUSE），其余仅 HTTPS+SHA256 | 高 | 如实标注信任分级；不夸大完整性保障 |
| 4 | 签名密钥轮换/吊销处理不当 | 中 | 固化指纹 + 指纹不符拒绝并告警；不静默换钥 |
| 5 | Pacman 无 pkgbase，源码包级公告无法匹配 | 高 | binary↔binary 兜底；源码包级落 UNKNOWN，明确报告 |
| 6 | CSAF/OVAL XML 解析复杂度高、体积大 | 中 | 流式解析 + XXE 禁用 + 解压比/体积上限 |
| 7 | 各源字段语义漂移（未登记的 release、新字段） | 中 | 解析器容错 + 未知字段落 Artifact；定期复核端点 |
| 8 | 「无记录」被误判为 NOT_AFFECTED | 高 | 硬规则：仅显式 not-affected/known_not_affected 才算 |
| 9 | Debian/Ubuntu/Alpine/Arch 再分发授权未确认 | 中 | 运行期按需拉取 + 本机缓存，不打包进发布资产；补齐许可调查 |
| 10 | 文件系统与 SQLite 非原子提交，崩溃可能半更新 | 高 | 两段式提交 + active 指针事务翻转 + 临时文件清理 |

---

## 11. 阶段 3.1 实施路线

1. 先落地 `internal/feed` 的下载/缓存层：不可变 Artifact（sha256 寻址）+ ETag 条件请求 + 签名验证（A 级源）+ 解析安全护栏。
2. 落地 FeedSnapshot/Artifact 的 SQLite 0003 迁移与两段式原子提交（含崩溃恢复、并发锁）。
3. 按「Alpine（最小）→ Arch（最小）→ Debian → Ubuntu → RedHat CSAF/VEX → SUSE CSAF/VEX」顺序实现解析器，先易后难。
4. 每源完成即做真实小样本解析验证 + 匹配差分；A 级源补签名验证测试。
5. 阶段 3 只交付 `VulnState` 判定；`RemediationState`/`RebootState` 建模但不实现修复可行性。
6. 补齐 Ubuntu/Alpine/Arch 的许可与再分发授权调查（本阶段遗留项）。
