# v2.0 数据模型与数据库 Schema

- 版本：2.0.0-draft.2
- 对应迁移：`0001_init.sql`（阶段 1）、`0002_inventory.sql`（阶段 2）、`0003_findings.sql`（阶段 3）

---

## 1. 实体关系

```
distros 1──n distro_releases
                │
feed_sources 1──n advisories 1──n advisory_fixes
                       │              │  (distro_id, release, channel, package_kind, name, arch)
                       │              ▼
                       └──────▶ cves ──────▶ findings ◀──── inventory_packages
                                                │              ▲
                                                │              │
                                          remediation_runs   inventories 1──n inventory_packages
```

`findings` 不持久化到情报库之外的事业表，而是「一次扫描 = 一个 inventory + 一组 findings」写入 `scan_runs` / `findings`，便于报告与复检对比（阶段 3 落地）。

---

## 2. 包身份模型 `[修订 1]`

### 2.1 两个 Kind

```go
type PackageKind string

const (
    PackageKindSource PackageKind = "source"
    PackageKindBinary PackageKind = "binary"
)

// PackageRef 是包身份与版本的组合键，作为匹配与计划的唯一坐标。
type PackageRef struct {
    Kind    PackageKind
    Name    string
    Arch    string   // "amd64"/"arm64"/"noarch"/"all"；"any" 表示公告未限定架构
    Epoch   int      // dpkg/rpm 的 epoch；apk/pacman 为 0
    Version string   // 上游版本
    Release string   // 发行版修订号（dpkg 的 -1~deb12u1 的 1~deb12u1 部分；rpm 的 .el9 部分）
}
```

### 2.2 本机安装包

```go
type InstalledPackage struct {
    Ref           PackageRef       // Kind = binary
    SourceName    string           // 源码包名（dpkg Source / rpm SOURCERPM / apk origin / pacman pkgbase）
    SourceVersion string           // 源码包版本（可得时）
    Manager       PackageManager   // dpkg|rpm|apk|pacman
    Channel       string           // 来源渠道：bookworm-security / noble-updates / amzn2023-core / main / core
    Vendor        string           // 发行版或打包者
    InstallTime   time.Time        // 零值表示未知
    EntryHash     string           // 该包记录的内容哈希，用于资产快照比对
}
```

`SourceName` 是源码包公告与二进制包之间的**唯一桥接字段**。它有三个合法状态：

| 状态 | 含义 | 匹配行为 |
|------|------|----------|
| 有值且与包名相同 | 源码包与二进制包同名（多数 RPM/Alpine） | 正常桥接 |
| 有值且与包名不同 | 拆分包（`linux` → `linux-image-*`） | 正常桥接 |
| 空 / 无法解析 | dpkg 缺 `Source` 字段、rpm 缺 `SOURCERPM` | **桥接失败 → UNKNOWN** |

禁止用字符串前缀猜测替代此字段（例如把 `linux-image-6.8.0-31-generic` 猜成 `linux`）。

### 2.3 公告条目

```go
type AdvisoryFix struct {
    AdvisoryUID  string       // 见 2.4
    SourceID     string
    AdvisoryID   string       // DSA-5810-1 / USN-9018-1 / RHSA-2026:93414 / SUSE-SU-2026:1234-1
    CVEID        string
    DistroID     string
    Release      string
    Channel      string       // 该修复所在的仓库渠道
    Ref          PackageRef   // Kind 可为 source 或 binary
    FixedVersion string       // 原始字符串，逐字保留
    FixedAt      *time.Time
    EvidenceURL  string
}
```

### 2.4 稳定性要求：Advisory UID

`AdvisoryUID = sha256(source_id | advisory_id | cve_id)[:16]`，由内容派生、与插入顺序无关。同一公告重复导入幂等，不产生重复行。**不得**使用自增 ID 作为跨表引用，否则增量更新时无法对齐。

---

## 3. 状态模型 `[修订 3]`

三个维度独立存在于 `Finding` 中，禁止合并成单一枚举：

```go
// 维度一：检测结论
type VulnState string
const (
    VulnStateVulnerable  VulnState = "VULNERABLE"
    VulnStateFixed       VulnState = "FIXED"
    VulnStateNotAffected VulnState = "NOT_AFFECTED"
    VulnStateUnknown     VulnState = "UNKNOWN"
    VulnStateUnsupported VulnState = "UNSUPPORTED"
)

// 维度二：修复可行性
type RemediationState string
const (
    RemediationFixAvailable      RemediationState = "FIX_AVAILABLE"
    RemediationNoFix             RemediationState = "NO_FIX"
    RemediationPendingMirror     RemediationState = "FIX_PENDING_MIRROR"
    RemediationManualRequired    RemediationState = "MANUAL_REQUIRED"
    RemediationBlocked           RemediationState = "BLOCKED"
    RemediationNotApplicable     RemediationState = "NOT_APPLICABLE"
    RemediationUnknown           RemediationState = "UNKNOWN"
)

// 维度三：运行时状态（补丁装好后的生效情况）
type RebootState string
const (
    RebootNotRequired RebootState = "NOT_REQUIRED"
    RebootRequired    RebootState = "REQUIRED"
    RebootUnknown     RebootState = "UNKNOWN"
)

type Confidence string
const (
    ConfidenceConfirmed Confidence = "CONFIRMED"
    ConfidenceLikely    Confidence = "LIKELY"
    ConfidenceUnknown   Confidence = "UNKNOWN"
)

type ServiceRestart struct {
    Service    string
    Confidence Confidence
    Evidence   []string   // 每条为可读的证据描述，报告中原样输出
}

type RuntimeState struct {
    Reboot    RebootState
    Restarts  []ServiceRestart
    Notes     []string
}
```

约束（在 `domain` 包中以方法与测试固化）：

- `VulnState` 只有 `VULNERABLE` 才可能触发修复；`FIXED` / `NOT_AFFECTED` / `UNSUPPORTED` 一律 `RemediationNotApplicable`。
- `UNKNOWN` 的 `RemediationState` 不得为 `FIX_AVAILABLE`。
- `Confidence == LIKELY` 的 `ServiceRestart` 不进「已确认待重启」计数。

---

## 4. SQLite Schema

### 4.1 迁移与元数据

```sql
CREATE TABLE schema_migrations (
    version    INTEGER PRIMARY KEY,     -- 迁移序号，严格递增
    name       TEXT    NOT NULL,
    checksum   TEXT    NOT NULL,        -- SQL 文件 SHA256，启动时校验，防止手改库
    applied_at TEXT    NOT NULL         -- RFC3339 UTC
);

CREATE TABLE app_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

`app_meta` 固定键：`schema_version`、`feed_last_update`、`feed_snapshot_hash`、`db_created_at`、`db_engine_version`。

### 4.2 发行版与生命周期 `[修订 6]`

```sql
CREATE TABLE distros (
    id     TEXT PRIMARY KEY,                        -- debian|ubuntu|rhel|rocky|almalinux|ol|amzn|sles|opensuse-leap|alpine|arch|fedora|cloudlinux
    name   TEXT NOT NULL,
    family TEXT NOT NULL CHECK (family IN ('debian','rpm','suse','alpine','arch','unknown'))
);

CREATE TABLE distro_releases (
    id              TEXT PRIMARY KEY,               -- debian:12 / ubuntu:24.04 / amzn:2023
    distro_id       TEXT NOT NULL REFERENCES distros(id),
    release         TEXT NOT NULL,                  -- 12 / 24.04 / 2023
    codename        TEXT NOT NULL DEFAULT '',       -- bookworm / noble / (空)
    lifecycle_state TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (lifecycle_state IN ('active','legacy','eol','unknown')),
    eol_date        TEXT,                           -- YYYY-MM-DD
    UNIQUE (distro_id, release)
);
```

`amzn:2` 必须落 `lifecycle_state='legacy'`、`eol_date='2026-06-30'`。planner 见 `legacy` 直接拒绝出计划。

### 4.3 情报源与信任等级 `[修订 8]`

```sql
CREATE TABLE feed_sources (
    id               TEXT PRIMARY KEY,              -- debian-tracker / ubuntu-oval / rhel-api / suse-csaf / alpine-secdb / arch-tracker / al2023-updateinfo / nvd
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,                 -- tracker|oval|csaf|csaf-vex|api|secdb|updateinfo|nvd
    url              TEXT NOT NULL,
    trust_level      TEXT NOT NULL CHECK (trust_level IN ('A','B','C')),
    signature_kind   TEXT NOT NULL DEFAULT 'none'
                     CHECK (signature_kind IN ('none','minisign','gpg','csaf','x509')),
    scope            TEXT NOT NULL DEFAULT 'advisory'
                     CHECK (scope IN ('advisory','metadata')),   -- C 级元数据源不得参与判定
    validation_level TEXT NOT NULL DEFAULT 'unverified'
                     CHECK (validation_level IN ('verified','structure-only','unverified')),
    status           TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (status IN ('ok','stale','error','unknown')),
    last_checked_at  TEXT,
    last_success_at  TEXT,
    content_hash     TEXT,                          -- SHA256(下载字节)
    content_bytes    INTEGER,
    last_error       TEXT
);
```

三个字段刻意分开，不允许合并成一个 `verified`：

- `signature_kind='none'` + `validation_level='structure-only'` = B 级源正常运行状态（仅 TLS + 哈希）。
- `trust_level='A'` 且验签失败 → `status='error'`，数据不得入库。
- `scope='metadata'` 的源（NVD/CVE.org）只能写 `cves`，不得写 `advisory_fixes`。此约束由写入口 API 强制，不只靠约定。

### 4.4 公告与修复版本 `[修订 2]`

```sql
CREATE TABLE advisories (
    uid            TEXT PRIMARY KEY,                -- sha256(source|advisory|cve)[:16]
    source_id      TEXT NOT NULL REFERENCES feed_sources(id),
    advisory_id    TEXT NOT NULL,
    cve_id         TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    severity       TEXT NOT NULL DEFAULT 'unknown'
                   CHECK (severity IN ('critical','high','medium','low','none','unknown')),
    severity_source TEXT NOT NULL DEFAULT '',
    issued_at      TEXT,
    updated_at     TEXT,
    url            TEXT NOT NULL DEFAULT '',
    fetched_at     TEXT NOT NULL,
    UNIQUE (source_id, advisory_id, cve_id)
);

CREATE TABLE advisory_fixes (
    id                INTEGER PRIMARY KEY,
    advisory_uid      TEXT NOT NULL REFERENCES advisories(uid) ON DELETE CASCADE,
    source_id         TEXT NOT NULL,
    advisory_id       TEXT NOT NULL,
    cve_id            TEXT NOT NULL,
    distro_id         TEXT NOT NULL REFERENCES distros(id),
    release           TEXT NOT NULL,                -- 必须与 distro_releases.release 一致
    channel           TEXT NOT NULL,                -- bookworm-security / noble-updates / amzn2023-core / main / core / extra
    package_kind      TEXT NOT NULL CHECK (package_kind IN ('source','binary')),
    package_name      TEXT NOT NULL,
    arch              TEXT NOT NULL DEFAULT 'any',  -- any = 未限定架构；否则 amd64/arm64/noarch/all/i686
    fixed_version_raw TEXT NOT NULL,                -- 逐字保留原始版本串
    fixed_epoch       INTEGER NOT NULL DEFAULT 0,
    fixed_version     TEXT NOT NULL,                -- 上游部分
    fixed_release     TEXT NOT NULL DEFAULT '',     -- 发行修订部分
    fixed_at          TEXT,
    evidence_url      TEXT NOT NULL DEFAULT '',

    -- [修订 2] 唯一性必须锚定「哪个发行版的哪个 release 的哪个渠道的哪个包身份」
    UNIQUE (source_id, advisory_id, cve_id, distro_id, release, channel,
            package_kind, package_name, arch)
);

CREATE INDEX idx_fixes_lookup
    ON advisory_fixes (distro_id, release, package_kind, package_name);
CREATE INDEX idx_fixes_cve ON advisory_fixes (cve_id);
```

为什么必须包含这六个维度（对比旧草案 `UNIQUE(advisory_id, package_name)` 的缺陷）：

| 维度 | 缺失时的真实错误 |
|------|------------------|
| `distro_id` | Debian `openssl 3.0.11-1~deb12u2` 与 Ubuntu `3.0.13-0ubuntu3.5` 同包名互相覆盖 |
| `release` | Debian 12 与 13 的固定版本不同，后者覆盖前者导致 bookworm 误判为已修复 |
| `channel` | `bookworm` 与 `bookworm-security` 的修复版本不同；backports 版本更高，混用会把未升级机器判成 FIXED |
| `package_kind` | `linux`（源码）与 `linux-image-*`（二进制）同名冲突 |
| `package_name` | 一个公告修多个包（`openssl`+`openssl-dev`），仅按公告去重会丢行 |
| `arch` | `noarch` 与 `amd64` 的同名包版本可不同；`any` 与具体架构也必须区分 |

`fixed_version_raw` 与拆分后的三元组同时保存：比较用结构化字段，报告与审计用原始串，避免解析器升级后无法回溯。

### 4.5 显式「不受影响」声明

```sql
CREATE TABLE advisory_not_affected (
    id           INTEGER PRIMARY KEY,
    source_id    TEXT NOT NULL REFERENCES feed_sources(id),
    advisory_id  TEXT NOT NULL DEFAULT '',
    cve_id       TEXT NOT NULL,
    distro_id    TEXT NOT NULL,
    release      TEXT NOT NULL,
    package_kind TEXT NOT NULL CHECK (package_kind IN ('source','binary')),
    package_name TEXT NOT NULL,
    arch         TEXT NOT NULL DEFAULT 'any',
    reason       TEXT NOT NULL,                    -- not-affected | not-in-release | vulnerable-code-absent | end-of-life
    evidence_url TEXT NOT NULL DEFAULT '',
    UNIQUE (source_id, cve_id, distro_id, release, package_kind, package_name, arch)
);
```

只有此表能推出 `NOT_AFFECTED`。**数据源未收录 CVE ≠ 不受影响**（Alpine secdb 与 Arch 追踪器都未收录 CVE-2026-98432，正确结论是 `UNKNOWN`）。

### 4.6 CVE 元数据（C 级）

```sql
CREATE TABLE cves (
    id                 TEXT PRIMARY KEY,           -- CVE-YYYY-NNNN
    title              TEXT NOT NULL DEFAULT '',
    description        TEXT NOT NULL DEFAULT '',
    cvss_version       TEXT NOT NULL DEFAULT '',
    cvss_score         REAL,
    cvss_vector        TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT 'unknown'
                       CHECK (severity IN ('critical','high','medium','low','none','unknown')),
    severity_source    TEXT NOT NULL DEFAULT '',   -- nvd | vendor
    published_at       TEXT,
    updated_at         TEXT,
    metadata_source_id TEXT,                       -- 固定为 C 级源
    fetched_at         TEXT
);

CREATE TABLE cve_references (
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    url    TEXT NOT NULL,
    tags   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, url)
);
```

`cves.severity` 仅用于展示与排序，**不参与** `VulnState` 计算。

---

## 5. 匹配算法（阶段 3 实现，此处定契约）

```
输入：inventory(distro, release, arch, []InstalledPackage) + 情报库
输出：[]Finding

对每个 CVE：
  1. 取该 (distro, release) 下所有 advisory_fixes，按 (channel, package_name) 分组
  2. 对每条 fix：
     a. kind=source → 命中集合 = {p | p.SourceName == fix.package_name && archMatch(p, fix.arch)}
     b. kind=binary → 命中集合 = {p | p.Name == fix.package_name && archMatch(p, fix.arch)}
     c. 命中集为空 → 该 fix 不产出 finding（不是 NOT_AFFECTED）
  3. 对每个命中包：用该包管理器的原生比较规则比较 p.Version 与 fix.FixedVersion
     <  → VULNERABLE
     >= → FIXED（回移补丁由此自然成立）
     不可比 → UNKNOWN（记录 compare_error 证据）
  4. 同一 (cve, package) 有多条 fix（多渠道）时取「已启用渠道」中最低的固定版本，
     并把全部候选写入 Evidence，报告中可追溯
  5. 无任何 fix 覆盖且 advisory_not_affected 显式声明 → NOT_AFFECTED
  6. 无任何数据 → UNKNOWN，Evidence 记 source_gap
```

`archMatch(p, fix.arch)`：`fix.arch ∈ {"any", p.Arch, "noarch"}` 为真；`p.Arch == "noarch"` 时接受任意 `fix.arch`。

---

## 6. 迁移策略

| 迁移 | 内容 | 阶段 |
|------|------|------|
| 0001_init | schema_migrations、app_meta、distros、distro_releases、feed_sources、advisories、advisory_fixes、advisory_not_affected、cves、cve_references + 种子数据（发行版与生命周期） | 1 |
| 0002_inventory | inventories、inventory_packages、kernel_state | 2 |
| 0003_findings | scan_runs、findings、finding_evidence | 3 |
| 0004_remediation | plans、plan_changes、remediation_runs、audit_log | 5 |

规则：

- 每个迁移是单文件、单事务、幂等（`IF NOT EXISTS` 之外不与已有数据冲突）。
- 迁移不可回滚；出错时整个事务回滚，库保持上一版本。
- 已应用迁移的 `checksum` 与文件不符 → 拒绝启动（`ExitIntegrity`）。
- 库 `schema_version` 高于二进制内嵌最大值 → 拒绝启动，提示升级二进制。
