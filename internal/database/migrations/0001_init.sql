-- 0001_init.sql — v2.0 初始 Schema
-- 内容：元数据、发行版坐标、情报源、公告、修复版本、不受影响声明、CVE 元数据。
-- 约定：时间字段统一 RFC3339 UTC 文本；布尔用 INTEGER 0/1；枚举用 CHECK 约束。

-- 迁移与元数据 ---------------------------------------------------------------

CREATE TABLE app_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- 发行版坐标 ----------------------------------------------------------------
-- 发行版与 release 是漏洞判定的第一坐标，任何跨 release 比较都是错误。

CREATE TABLE distros (
    id     TEXT PRIMARY KEY,
    name   TEXT NOT NULL,
    family TEXT NOT NULL CHECK (family IN ('debian','rpm','suse','alpine','arch','unknown'))
);

CREATE TABLE distro_releases (
    id              TEXT PRIMARY KEY,
    distro_id       TEXT NOT NULL REFERENCES distros(id),
    release         TEXT NOT NULL,
    codename        TEXT NOT NULL DEFAULT '',
    lifecycle_state TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (lifecycle_state IN ('active','legacy','eol','unknown')),
    eol_date        TEXT,
    UNIQUE (distro_id, release)
);

-- 情报源与信任等级 -----------------------------------------------------------
-- trust_level 是「应然」等级，validation_level 是「实然」验证程度，两者不得合并。
-- signature_kind 与 content_hash 分开记录，禁止把哈希通过表述为签名通过。

CREATE TABLE feed_sources (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL
                     CHECK (kind IN ('tracker','oval','csaf','csaf-vex','api','secdb','updateinfo','nvd')),
    url              TEXT NOT NULL,
    trust_level      TEXT NOT NULL CHECK (trust_level IN ('A','B','C')),
    signature_kind   TEXT NOT NULL DEFAULT 'none'
                     CHECK (signature_kind IN ('none','minisign','gpg','csaf','x509')),
    scope            TEXT NOT NULL DEFAULT 'advisory'
                     CHECK (scope IN ('advisory','metadata')),
    validation_level TEXT NOT NULL DEFAULT 'unverified'
                     CHECK (validation_level IN ('verified','structure-only','unverified')),
    status           TEXT NOT NULL DEFAULT 'unknown'
                     CHECK (status IN ('ok','stale','error','unknown')),
    last_checked_at  TEXT,
    last_success_at  TEXT,
    content_hash     TEXT,
    content_bytes    INTEGER,
    last_error       TEXT
);

-- 公告 ----------------------------------------------------------------------

CREATE TABLE advisories (
    uid             TEXT PRIMARY KEY,
    source_id       TEXT NOT NULL REFERENCES feed_sources(id),
    advisory_id     TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    severity        TEXT NOT NULL DEFAULT 'unknown'
                    CHECK (severity IN ('critical','high','medium','low','none','unknown')),
    severity_source TEXT NOT NULL DEFAULT '',
    issued_at       TEXT,
    updated_at      TEXT,
    url             TEXT NOT NULL DEFAULT '',
    fetched_at      TEXT NOT NULL,
    UNIQUE (source_id, advisory_id, cve_id)
);

-- 修复版本：唯一键必须锚定 发行版 + release + 渠道 + 包身份 + 架构。
-- 少任何一个维度都会导致跨发行版覆盖或误判（见 docs/data-model.md §4.4）。

CREATE TABLE advisory_fixes (
    id                INTEGER PRIMARY KEY,
    advisory_uid      TEXT NOT NULL REFERENCES advisories(uid) ON DELETE CASCADE,
    source_id         TEXT NOT NULL,
    advisory_id       TEXT NOT NULL,
    cve_id            TEXT NOT NULL,
    distro_id         TEXT NOT NULL REFERENCES distros(id),
    release           TEXT NOT NULL,
    channel           TEXT NOT NULL,
    package_kind      TEXT NOT NULL CHECK (package_kind IN ('source','binary')),
    package_name      TEXT NOT NULL,
    arch              TEXT NOT NULL DEFAULT 'any',
    fixed_version_raw TEXT NOT NULL,
    fixed_epoch       INTEGER NOT NULL DEFAULT 0,
    fixed_version     TEXT NOT NULL,
    fixed_release     TEXT NOT NULL DEFAULT '',
    fixed_at          TEXT,
    evidence_url      TEXT NOT NULL DEFAULT '',
    UNIQUE (source_id, advisory_id, cve_id, distro_id, release, channel,
            package_kind, package_name, arch)
);

CREATE INDEX idx_fixes_lookup ON advisory_fixes (distro_id, release, package_kind, package_name);
CREATE INDEX idx_fixes_cve    ON advisory_fixes (cve_id);

-- 显式「不受影响」声明：只有本表能推出 NOT_AFFECTED。
-- 情报源未收录某个 CVE 不等于不受影响。

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
    reason       TEXT NOT NULL
                 CHECK (reason IN ('not-affected','not-in-release','vulnerable-code-absent','end-of-life')),
    evidence_url TEXT NOT NULL DEFAULT '',
    UNIQUE (source_id, cve_id, distro_id, release, package_kind, package_name, arch)
);

-- CVE 元数据（C 级情报源，仅用于展示与排序，不参与受影响判定）---------------

CREATE TABLE cves (
    id                 TEXT PRIMARY KEY,
    title              TEXT NOT NULL DEFAULT '',
    description        TEXT NOT NULL DEFAULT '',
    cvss_version       TEXT NOT NULL DEFAULT '',
    cvss_score         REAL,
    cvss_vector        TEXT NOT NULL DEFAULT '',
    severity           TEXT NOT NULL DEFAULT 'unknown'
                       CHECK (severity IN ('critical','high','medium','low','none','unknown')),
    severity_source    TEXT NOT NULL DEFAULT '',
    published_at       TEXT,
    updated_at         TEXT,
    metadata_source_id TEXT,
    fetched_at         TEXT
);

CREATE TABLE cve_references (
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    url    TEXT NOT NULL,
    tags   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, url)
);

-- 种子数据：发行版族 --------------------------------------------------------

INSERT INTO distros (id, name, family) VALUES
    ('debian',        'Debian',                        'debian'),
    ('ubuntu',        'Ubuntu',                        'debian'),
    ('rhel',          'Red Hat Enterprise Linux',      'rpm'),
    ('rocky',         'Rocky Linux',                   'rpm'),
    ('almalinux',     'AlmaLinux',                     'rpm'),
    ('ol',            'Oracle Linux',                  'rpm'),
    ('amzn',          'Amazon Linux',                  'rpm'),
    ('fedora',        'Fedora Linux',                  'rpm'),
    ('cloudlinux',    'CloudLinux',                    'rpm'),
    ('sles',          'SUSE Linux Enterprise Server',  'suse'),
    ('opensuse-leap', 'openSUSE Leap',                 'suse'),
    ('alpine',        'Alpine Linux',                  'alpine'),
    ('arch',          'Arch Linux',                    'arch');

-- 种子数据：release 与生命周期 ----------------------------------------------
-- 只填结构性确定的信息；eol_date 拿不到可靠来源时留 NULL，不猜日期。
-- 生命周期直接决定自动修复准入：只有 active 可能通过后续闸门。

INSERT INTO distro_releases (id, distro_id, release, codename, lifecycle_state, eol_date) VALUES
    ('debian:11',        'debian',        '11',    'bullseye', 'eol',    '2026-08-31'),
    ('debian:12',        'debian',        '12',    'bookworm', 'active', NULL),
    ('debian:13',        'debian',        '13',    'trixie',   'active', NULL),
    ('ubuntu:20.04',     'ubuntu',        '20.04', 'focal',    'legacy', '2025-05-31'),
    ('ubuntu:22.04',     'ubuntu',        '22.04', 'jammy',    'active', NULL),
    ('ubuntu:24.04',     'ubuntu',        '24.04', 'noble',    'active', NULL),
    ('amzn:2',           'amzn',          '2',     '',         'legacy', '2026-06-30'),
    ('amzn:2023',        'amzn',          '2023',  '2023',     'active', NULL),
    ('rhel:8',           'rhel',          '8',     '',         'active', NULL),
    ('rhel:9',           'rhel',          '9',     '',         'active', NULL),
    ('rocky:8',          'rocky',         '8',     '',         'active', NULL),
    ('rocky:9',          'rocky',         '9',     '',         'active', NULL),
    ('almalinux:8',      'almalinux',     '8',     '',         'active', NULL),
    ('almalinux:9',      'almalinux',     '9',     '',         'active', NULL),
    ('ol:8',             'ol',            '8',     '',         'active', NULL),
    ('ol:9',             'ol',            '9',     '',         'active', NULL),
    ('sles:15',          'sles',          '15',    '',         'active', NULL),
    ('opensuse-leap:15.6','opensuse-leap','15.6',  '',         'active', NULL),
    ('alpine:3.19',      'alpine',        '3.19',  '',         'active', NULL),
    ('alpine:3.20',      'alpine',        '3.20',  '',         'active', NULL),
    ('alpine:3.21',      'alpine',        '3.21',  '',         'active', NULL),
    ('arch:rolling',     'arch',          'rolling', '',       'active', NULL);

-- 种子数据：元信息 ----------------------------------------------------------

INSERT INTO app_meta (key, value) VALUES
    ('schema_version', '1'),
    ('db_created_at',  strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
