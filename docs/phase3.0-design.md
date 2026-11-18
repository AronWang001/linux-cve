# 阶段 3.0 设计：漏洞情报采集、归一化、存储与匹配

- 版本：3.0-draft.1
- 状态：只读调查与技术设计（未进行大规模业务编码）
- 依赖：阶段 1 数据模型与状态契约（`docs/data-model.md`）、阶段 2 资产采集与版本比较

> 本阶段为**只读调查与设计**，端点与格式均重新核验（2026-11-18），
> 不假定历史接口未变。所有数据源端点、格式、大小、更新频率见 §1。

---

## 1. 官方数据源最新核验报告

| # | 数据源 | 端点（已核验） | 格式 | 体量 | 更新频率 | 校验/签名 |
|---|--------|----------------|------|------|----------|-----------|
| 1 | Debian Security Tracker | `https://security-tracker.debian.org/tracker/data/json` | 按包分组 JSON：`{包名: {CVE: {description, scope, releases: {代号: {status, fixed_version, urgency, repositories}}}}}` | ~90MB 级全量 | 近实时 | 仅 HTTPS，无官方 SHA256/签名 |
| 2 | Ubuntu OVAL/USN | `https://security-metadata.canonical.com/oval/` | `com.ubuntu.<release>.{cve,usn,pkg}.oval.xml.bz2` | 每文件 1–13MB | 每日 | 仅 HTTPS |
| 3 | Red Hat OVAL/CSAF | `https://security.access.redhat.com/data/oval/v2/`（**已从 redhat.com 迁移**） | `PULP_MANIFEST` + `feed.json`/`feed.xml` + `RHEL5..9/` 目录 | manifest 45KB | 每日 | PULP_MANIFEST 提供内容校验 |
| 4 | SUSE CSAF | `https://ftp.suse.com/pub/projects/security/csaf/` | 按年份目录 + `index.txt`/`changes.csv`/`deletions.csv` | index 1MB | 每日 | `changes.csv` 提供增量清单 |
| 5 | Alpine secdb | `https://secdb.alpinelinux.org/v3.20/` | `main.json` + `community.json`（每仓库） | 每文件 ~100–160KB | 每日 | `last-update` 时间戳文件 |
| 6 | Arch Security Tracker | `https://security.archlinux.org/all.json` | 顶层数组，元素含 `name/status/severity/type/affected/fixed/issues[]/advisories[]/packages[]` | 全量单文件 | 近实时 | 仅 HTTPS |

### 1.1 关键发现（相对阶段 0 的变更）

1. **Red Hat 端点域名已迁移**：`www.redhat.com/security/data` → `security.access.redhat.com/data`。旧 URL 必须视为废弃。
2. **SUSE 提供增量清单**：`changes.csv`（新增/变更）与 `deletions.csv`（删除），可支撑增量更新，无需每次全量拉取。
3. **Alpine 有精确时间戳**：`/last-update` 文件（分钟级）可作为增量判定依据。
4. **Arch 无官方 JSON 文档页**，但 `all.json` 可下载且结构稳定（顶层数组）；数据权威源在其 GitLab 仓库 `gitlab.archlinux.org/archlinux/security-tracker`。
5. **Debian 无签名/校验文件**，仅 HTTPS 传输安全；这是唯一超过 50MB 的全量源。

---

## 2. Feed 数据模型（统一 Advisory）

> 设计原则：不同数据源字段差异大，统一模型**不得丢失原始证据**。
> 统一字段用于匹配与展示；无法归一的字段落入 `raw_payload`（摘要+哈希）保留。

```go
// Advisory 是跨源统一的漏洞公告。
type Advisory struct {
    UID          string    // sha256(source_id|advisory_id|cve_id)[:16]，内容派生、顺序无关
    SourceID     string    // debian|ubuntu|redhat|suse|alpine|arch
    AdvisoryID   string    // DSA-5810-1 / USN-9018-1 / RHSA-2026:93414 / SUSE-SU-... / AVG-2843
    CVEID        string    // 主 CVE；一个公告可关联多个 CVE（issues[] 展开为多行）
    DistroID     string
    Release      string    // 发行版代号/版本：bookworm / jammy / 9 / 3.20 / rolling
    Title        string
    Severity     string    // critical|high|medium|low|none|unknown（展示用，不参与判定）
    Description  string
    PublishedAt  *time.Time
    UpdatedAt    *time.Time
    ReferenceURL string    // 官方公告链接
    RawHash      string    // 原始数据的 SHA256，用于去重与审计
    RawPayload   []byte    // 原始数据原文（保留证据，丢失则不可追溯）
}

// AdvisoryFix 是公告中「某包某渠道的修复版本」声明。
type AdvisoryFix struct {
    AdvisoryUID  string
    SourceID     string
    AdvisoryID   string
    CVEID        string
    DistroID     string
    Release      string
    Channel      string          // bookworm-security / amzn2023-core / ...
    Kind         domain.PackageKind  // source | binary
    PackageName  string          // 源码包名或二进制包名
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
    PackageName string
    Reason      string   // nodsa_reason / not-affected 说明
    EvidenceURL string
}
```

### 2.1 各源字段映射（保留原始证据）

| 统一字段 | Debian | Ubuntu OVAL | Red Hat OVAL/CSAF | SUSE CSAF | Alpine secdb | Arch |
|----------|--------|-------------|-------------------|-----------|--------------|------|
| AdvisoryID | （无公告号，用 CVE+包名合成 UID） | USN-xxxx-x | RHSA/RHBA-... | SUSE-SU/OU-... | （无公告号） | AVG-xxxx |
| CVEID | 包下 CVE 键 | OVAL CVE | CSAF/CVE | CSAF | secdb 条目 | issues[] |
| 受影响/修复版本 | releases[代号].fixed_version | OVAL test | 受影响+修复 | affected/fixed | secdb fixed | affected/fixed |
| NOT_AFFECTED 证据 | status=resolved + nodsa | OVAL state | unaffected | 无 affected | 无该包条目≠不涉及 | status="Not affected" |
| 严重程度 | urgency | OVAL severity | CVE CVSS | CSAF | secdb severity | severity |
| 源码包↔二进制映射 | Debian 原生按源码包组织 | 按二进制包（有 src 元数据） | SRPM | 源码包+二进制包 | origin | packages[]（无 pkgbase） |

**核心证据规则**（延续阶段 2 的严谨性）：

- Debian `status=resolved` + `fixed_version` 才是 FIXED 证据；`status=open` 是 VULNERABLE；`nodsa=true` 表示「不修复」，仍需作为 VULNERABLE 但记 no-fix。
- 「该源没有某 CVE 的记录」**不等于 NOT_AFFECTED**；只有显式 `not-affected` / `status=not-affected` 才算。
- 无法证明时必须落 `UNKNOWN`，记 `source_gap` 证据。

---

## 3. Feed 更新机制

### 3.1 分层缓存与增量

```
远端（各源） ──ETag/Last-Modified──▶ 本地缓存（原始文件，按源+版本存）──解析──▶ 情报库（SQLite）
```

- **首次全量**：逐源下载完整文件（Debian ~90MB 一次性）。
- **增量**：
  - 有 ETag/Last-Modified 的源（Ubuntu/RedHat/SUSE/Alpine）用条件请求（`If-None-Match` / `If-Modified-Since`），304 则跳过。
  - SUSE 用 `changes.csv` + `deletions.csv` 精确增量。
  - Debian/Arch 无 ETag，用「下载→SHA256 与上次比对」判定；相同则跳过写库。
- **本地缓存**：原始文件落 `cache/feeds/<source>/`，解析产物才进 SQLite。

### 3.2 原子更新与回滚

- 解析 → 写入**临时 staging 表** → 校验通过 → **单事务** swap 到正式表 → 更新 `app_meta.feed_last_update` / `feed_snapshot_hash`。
- 任一步失败 → 整体回滚，**上一次有效数据库保持不变**。
- **下载失败**：直接返回，不触碰已有库。
- **解析失败**：半成品数据绝不写入正式情报库；解析器报错并保留原始文件供排查。

### 3.3 元数据

`app_meta` 固定键（阶段 1 已定）：`feed_last_update`（上次成功同步时间）、`feed_snapshot_hash`（内容哈希）、`db_created_at`、`db_engine_version`。数据新鲜度由 `feed_last_update` 与各源 `last-update`/`changes.csv` 时间戳共同判定。

### 3.4 断网降级

`--offline` 或网络失败时，使用**最近一次成功同步**的情报库 + 本地缓存，明确标记数据新鲜度（报告里显示「情报库截至 X，已过期 N 天」），不阻塞本地扫描。

---

## 4. 数据真实性与信任机制（严格分层）

| 层级 | 机制 | 回答的问题 | 哪些源实际提供 |
|------|------|-----------|----------------|
| 1. 传输安全 | HTTPS | 传输中不被窃听/篡改（中间人） | 全部 |
| 2. 内容完整性 | SHA256 | 下载文件与发布方一致（防传输损坏/缓存污染） | RedHat PULP_MANIFEST；其余需自算+比对 |
| 3. 数字签名 | PGP / minisign | 内容确由发布方签发（防上游被入侵） | **仅 Red Hat 提供 PGP 签名**（需进一步确认） |
| 4. 构建来源证明 | cosign OIDC | 二进制/工件可追溯到构建者 | 本项目自身发布时用（阶段 8），**情报源不适用** |

**硬规则**：

- 只有数据源**真正提供签名**时才执行签名验证；不得把 HTTPS 或 SHA256 描述成「数字签名」。
- 各源信任分级（供报告展示，不改变判定逻辑）：

| 源 | 传输 | 完整性 | 签名 | 综合信任 |
|----|------|--------|------|----------|
| Debian | HTTPS | 自算 SHA256 | 无 | B（HTTPS+内容哈希，无签名） |
| Ubuntu | HTTPS | 自算 SHA256 | 无 | B |
| Red Hat | HTTPS | PULP_MANIFEST | 有 PGP | A |
| SUSE | HTTPS | 自算 SHA256 | 无 | B |
| Alpine | HTTPS | last-update 时间戳 | 无 | B |
| Arch | HTTPS | 自算 SHA256 | 无 | B |

- 未签名的源，完整性靠「SHA256 + 与上次比对」防损坏，但**不能**防上游被入侵。这在报告中如实标注，不夸大。

---

## 5. SQLite Schema 迁移设计（0003_findings.sql）

沿用阶段 1 §4 已定义的表结构（`advisories` / `advisory_fixes` / `cves` / `cve_references`），新增/确认以下要点：

```sql
-- 公告（统一 Advisory）
CREATE TABLE advisories (
    uid           TEXT PRIMARY KEY,
    source_id     TEXT NOT NULL,
    advisory_id   TEXT NOT NULL,
    cve_id        TEXT NOT NULL,
    distro_id     TEXT NOT NULL REFERENCES distros(id),
    release       TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    severity      TEXT NOT NULL DEFAULT 'unknown',
    description   TEXT NOT NULL DEFAULT '',
    published_at  TEXT,
    updated_at    TEXT,
    reference_url TEXT NOT NULL DEFAULT '',
    raw_hash      TEXT NOT NULL,
    raw_payload   BLOB,                 -- 原始数据证据
    UNIQUE (source_id, advisory_id, cve_id)
);

-- 修复声明（阶段 1 §4.6 已定 AdvisoryFix）
CREATE TABLE advisory_fixes (
    uid           TEXT PRIMARY KEY,
    source_id     TEXT NOT NULL,
    advisory_id   TEXT NOT NULL,
    cve_id        TEXT NOT NULL,
    distro_id     TEXT NOT NULL,
    release       TEXT NOT NULL,
    channel       TEXT NOT NULL DEFAULT '',
    package_kind  TEXT NOT NULL CHECK (package_kind IN ('source','binary')),
    package_name  TEXT NOT NULL,
    arch          TEXT NOT NULL DEFAULT 'any',
    fixed_version TEXT NOT NULL,
    fixed_at      TEXT,
    evidence_url  TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (source_id, advisory_id, cve_id)
        REFERENCES advisories(source_id, advisory_id, cve_id) ON DELETE CASCADE
);

-- 显式不受影响声明
CREATE TABLE advisory_not_affected (
    source_id     TEXT NOT NULL,
    advisory_id   TEXT NOT NULL,
    cve_id        TEXT NOT NULL,
    distro_id     TEXT NOT NULL,
    release       TEXT NOT NULL,
    package_name  TEXT NOT NULL,
    reason        TEXT NOT NULL DEFAULT '',
    evidence_url  TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (source_id, advisory_id, cve_id, distro_id, release, package_name)
);

-- 发现（一次扫描的结论，阶段 3 落地）
CREATE TABLE findings (
    id             INTEGER PRIMARY KEY,
    scan_id        TEXT NOT NULL,       -- 一次扫描 = 一个 inventory + 一组 findings
    inventory_id   INTEGER NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    cve_id         TEXT NOT NULL,
    package_name   TEXT NOT NULL,
    package_arch   TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version  TEXT NOT NULL DEFAULT '',
    vuln_state     TEXT NOT NULL CHECK (vuln_state IN ('VULNERABLE','FIXED','NOT_AFFECTED','UNKNOWN','UNSUPPORTED')),
    remediation_state TEXT NOT NULL CHECK (remediation_state IN ('FIX_AVAILABLE','NO_FIX','FIX_PENDING_MIRROR','MANUAL_REQUIRED','BLOCKED','NOT_APPLICABLE','UNKNOWN')),
    reboot_state   TEXT NOT NULL CHECK (reboot_state IN ('NOT_REQUIRED','REQUIRED','UNKNOWN')),
    confidence     TEXT NOT NULL CHECK (confidence IN ('CONFIRMED','LIKELY','UNKNOWN')),
    evidence       TEXT NOT NULL DEFAULT '',  -- JSON：命中依据、候选 fix、compare_error、source_gap 等
    UNIQUE (scan_id, cve_id, package_name, package_arch)
);
```

迁移要求（延续阶段 1/2 的硬约束）：

- 外键、`schema_migrations` 唯一权威、同事务、校验和、0002 可升级、幂等、失败整体回滚。
- `findings.vuln_state` / `remediation_state` / `reboot_state` 三列**独立存在**，禁止合并为单一枚举（阶段 1 修订 3 的契约）。

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
| Red Hat | ✅ | ✅（SRPM） | ✅ | PULP_MANIFEST | PGP |
| SUSE | ✅ | ✅ | ✅ | changes.csv | 无 |
| Alpine | ✅ | ✅（origin） | ✅ | last-update | 无 |
| Arch | ✅ | ❌（无 pkgbase） | ✅（all.json packages） | SHA256 比对 | 无 |

---

## 9. 测试策略

1. **解析器单测**：每源构造真实样本（从各源下载的**真实小样本**，标注 REAL）+ 人工构造边界样本（SYNTHETIC），验证字段映射与证据保留。
2. **归一化测试**：跨源异构数据归一为统一 Advisory，验证原始证据（raw_payload + raw_hash）无损。
3. **匹配引擎测试**：覆盖 §6.3 全部边界（架构、发行版隔离、release、回移、多公告、多 CVE、source_gap、UNKNOWN vs NOT_AFFECTED）。
4. **增量更新测试**：模拟 ETag 304、changes.csv 增量、下载失败不删库、解析失败不写半成品。
5. **迁移测试**：0003 连续迁移、幂等、回滚、外键。
6. **差分测试**：匹配结果与官方已知结论对照（如已知 CVE 在 Debian 12 的状态）。
7. **夹具区分**：REAL（真实下载样本）与 SYNTHETIC（人工构造）严格标注，不混用、不冒称实机。

---

## 10. 风险清单

| # | 风险 | 等级 | 缓解 |
|---|------|------|------|
| 1 | Debian ~90MB 全量无增量端点，每次比对成本高 | 中 | 本地缓存 + SHA256 比对；仅在变化时写库 |
| 2 | Red Hat 端点已迁移，历史配置易失效 | 中 | 已核验新端点 `security.access.redhat.com`；配置化 URL |
| 3 | 多数源无数字签名，仅 HTTPS+SHA256 | 高 | 如实标注信任分级 B 级；不夸大完整性保障 |
| 4 | Pacman 无 pkgbase，源码包级公告无法匹配 | 高 | binary↔binary 兜底；源码包级落 UNKNOWN，明确报告 |
| 5 | OVAL/CSAF XML 解析复杂度高、体积大 | 中 | 流式解析（非 DOM 全载），分版本分文件拉取 |
| 6 | 各源字段语义漂移（未登记的 release、新字段） | 中 | 解析器容错 + 未知字段落 raw_payload；定期复核端点 |
| 7 | 「无记录」被误判为 NOT_AFFECTED | 高 | 硬规则：仅显式 not-affected 才算，否则 UNKNOWN |

---

## 11. 阶段 3 开工建议（后续）

1. 先落地 `internal/feed` 的下载/缓存层（ETag + SHA256 比对 + 原子 swap）。
2. 按「Alpine（最小）→ Arch（最小）→ Debian → Ubuntu → RedHat/SUSE（XML 流式）」顺序实现解析器，先易后难。
3. 每源完成即做真实小样本解析验证 + 匹配差分。
4. 情报库写入走 staging + 单事务 swap，先通过「下载失败/解析失败不破坏已有库」的测试。
5. 阶段 3 只交付 `VulnState` 判定；`RemediationState`/`RebootState` 建模但不实现修复可行性。
