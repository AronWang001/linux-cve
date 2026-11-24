-- 0003_feed.sql — 阶段 3.1：情报存储分层与扫描结果
--
-- 遵循 docs/phase3.0-design.md §5：
--   * 不重建 advisories / advisory_fixes / advisory_not_affected（0001 已建，字段为准）；
--   * 只新增 Feed 存储分层（artifact / snapshot）与 findings；
--   * 给 advisories 补溯源列，使每条归一化记录都能指回不可变原始字节。
--
-- 分层关系：
--   feed_sources → feed_snapshots → feed_snapshot_artifacts → feed_artifacts
--   advisories 通过 artifact_sha256 + raw_locator + raw_record_hash 指回原始证据。

-- 不可变原始文件（内容寻址，跨公告共享）-----------------------------------
-- sha256 既是主键也是磁盘文件名；同内容天然去重。
-- signature_status 与 integrity_status 分列：哈希通过不等于签名通过。

CREATE TABLE feed_artifacts (
    sha256           TEXT PRIMARY KEY,
    source_id        TEXT NOT NULL REFERENCES feed_sources(id),
    size_bytes       INTEGER NOT NULL,
    download_url     TEXT NOT NULL,
    fetched_at       TEXT NOT NULL,
    signature_status TEXT NOT NULL DEFAULT 'not-applicable'
                     CHECK (signature_status IN ('verified','failed','missing','not-applicable','unverified')),
    integrity_status TEXT NOT NULL DEFAULT 'unchecked'
                     CHECK (integrity_status IN ('verified','failed','unchecked')),
    stored_path      TEXT NOT NULL,
    etag             TEXT NOT NULL DEFAULT '',
    last_modified    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_artifacts_source ON feed_artifacts (source_id, fetched_at);

-- 一次成功同步的归一化结果集 ----------------------------------------------
-- is_active 是「当前有效」指针，只在事务提交时翻转；崩溃不会留下半更新快照。

CREATE TABLE feed_snapshots (
    id             TEXT PRIMARY KEY,
    source_id      TEXT NOT NULL REFERENCES feed_sources(id),
    started_at     TEXT NOT NULL,
    completed_at   TEXT,
    is_active      INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0,1)),
    content_hash   TEXT NOT NULL DEFAULT '',
    parser_version TEXT NOT NULL DEFAULT '',
    advisories     INTEGER NOT NULL DEFAULT 0,
    fixes          INTEGER NOT NULL DEFAULT 0,
    not_affected   INTEGER NOT NULL DEFAULT 0,
    skipped        INTEGER NOT NULL DEFAULT 0
);

-- 每个源最多一个 active 快照，从结构上排除「两个快照同时有效」。
CREATE UNIQUE INDEX idx_snapshot_active ON feed_snapshots (source_id) WHERE is_active = 1;

-- 快照 ↔ artifact 多对多 ---------------------------------------------------

CREATE TABLE feed_snapshot_artifacts (
    snapshot_id  TEXT NOT NULL REFERENCES feed_snapshots(id) ON DELETE CASCADE,
    artifact_sha TEXT NOT NULL REFERENCES feed_artifacts(sha256),
    PRIMARY KEY (snapshot_id, artifact_sha)
);

-- advisories 溯源列 -------------------------------------------------------
-- 原文不内嵌进库，只存引用与定位；raw_record_hash 用于判断单条记录是否变化。
ALTER TABLE advisories ADD COLUMN artifact_sha256  TEXT NOT NULL DEFAULT '';
ALTER TABLE advisories ADD COLUMN raw_locator      TEXT NOT NULL DEFAULT '';
ALTER TABLE advisories ADD COLUMN raw_record_hash  TEXT NOT NULL DEFAULT '';
ALTER TABLE advisories ADD COLUMN parser_version   TEXT NOT NULL DEFAULT '';

-- 发布方对这条记录的原始状态串（Debian 的 resolved/open/undetermined、
-- Red Hat VEX 的状态桶等）。
-- 为什么不只用 advisory_fixes 表达：实测 Debian Tracker 的 fixed_version
-- 大量是占位 "0"，真正修复版本在 repositories 里；同时 open 状态意味着
-- 「已确认受影响但无修复版本」，这类记录没有 fixed_version 可写，
-- 必须靠本列 + 空修复记录共同表达。设计稿假定 fixed_version 恒有值，
-- 实测不成立，故补此列。
ALTER TABLE advisories ADD COLUMN vendor_status    TEXT NOT NULL DEFAULT '';

-- 被撤回的公告不物理删除：保留记录与撤回时间，匹配时以有值为准排除。
-- 这是 SUSE deletions.csv 语义的落点（设计 §3.4）。
ALTER TABLE advisories ADD COLUMN retracted_at     TEXT;

CREATE INDEX idx_fixes_lookup_channel ON advisory_fixes (distro_id, release, channel);

-- 修复版本来源 -----------------------------------------------------------
-- official            = 发布方直接声明的修复版本，可严格比较（< 即受影响）
-- repository-observed = 发布方未给修复版本，只有仓库当前版本；
--                       只能弱判（>= 判已修复，< 判 UNKNOWN），不得当作受影响证据
--
-- 必要性来自实测：Debian Tracker 有 25,449 条 resolved 记录的 fixed_version 是
-- 占位 "0"，真实版本只存在于 repositories 里；另有 233,805 条是官方版本。
-- 两者混为一谈会把「只是仓库更新过」误判成「确认受影响」。
ALTER TABLE advisory_fixes ADD COLUMN fixed_version_source TEXT NOT NULL DEFAULT 'official'
    CHECK (fixed_version_source IN ('official','repository-observed'));

-- 扫描元数据 --------------------------------------------------------------
-- findings 只存结果行，list/show 还需要「这是哪次扫描、用的哪份情报」，
-- 因此单独建 scans。scans 与 findings 同批写入，二者不跨事务。

CREATE TABLE scans (
    id              TEXT PRIMARY KEY,
    inventory_id    INTEGER NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    distro_id       TEXT NOT NULL,
    release         TEXT NOT NULL,
    arch            TEXT NOT NULL DEFAULT '',
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    coverage        TEXT NOT NULL DEFAULT 'UNKNOWN'
                    CHECK (coverage IN ('COVERED','PARTIAL','UNKNOWN')),
    coverage_detail TEXT NOT NULL DEFAULT '',
    feed_snapshot   TEXT NOT NULL DEFAULT '',
    findings_total  INTEGER NOT NULL DEFAULT 0,
    vulnerable      INTEGER NOT NULL DEFAULT 0,
    unknown         INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_scans_started ON scans (started_at);

-- 匹配结果（阶段 3 产物）----------------------------------------------------
-- 三个状态维度独立成列，禁止合并为单一枚举（阶段 1 修订 3 的契约）。

CREATE TABLE findings (
    id                INTEGER PRIMARY KEY,
    scan_id           TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    inventory_id      INTEGER NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    cve_id            TEXT NOT NULL,
    package_name      TEXT NOT NULL,
    package_arch      TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version     TEXT NOT NULL DEFAULT '',
    vuln_state        TEXT NOT NULL
                      CHECK (vuln_state IN ('VULNERABLE','FIXED','NOT_AFFECTED','UNKNOWN','UNSUPPORTED')),
    remediation_state TEXT NOT NULL
                      CHECK (remediation_state IN ('FIX_AVAILABLE','NO_FIX','FIX_PENDING_MIRROR','MANUAL_REQUIRED','BLOCKED','NOT_APPLICABLE','UNKNOWN')),
    reboot_state      TEXT NOT NULL
                      CHECK (reboot_state IN ('NOT_REQUIRED','REQUIRED','UNKNOWN')),
    confidence        TEXT NOT NULL
                      CHECK (confidence IN ('CONFIRMED','LIKELY','UNKNOWN')),
    severity          TEXT NOT NULL DEFAULT 'unknown'
                      CHECK (severity IN ('critical','high','medium','low','none','unknown')),
    advisory_id       TEXT NOT NULL DEFAULT '',
    source_id         TEXT NOT NULL DEFAULT '',
    evidence          TEXT NOT NULL DEFAULT '',
    UNIQUE (scan_id, cve_id, package_name, package_arch)
);

CREATE INDEX idx_findings_scan  ON findings (scan_id);
CREATE INDEX idx_findings_cve   ON findings (cve_id);
CREATE INDEX idx_findings_state ON findings (scan_id, vuln_state);
CREATE INDEX idx_findings_pkg   ON findings (package_name);

-- 注：feed_sources 的源配置不在迁移里写死。
-- 端点与信任等级的唯一来源是 internal/feed/registry.go，Go 侧在更新前 upsert，
-- 避免 SQL 与代码两处各存一份 URL 而逐渐漂移。
