-- 0002_inventory: 本机资产快照（阶段 2）
--
-- 一次采集 = 一行 inventories + N 行 inventory_packages + 一行 kernel_state。
-- 只存事实，不存任何漏洞判定或修复结论（那些在 0003/0004）。
--
-- 设计约束（docs/data-model.md §4.7）：
--   * inventory_packages 的 UNIQUE 锚定「哪个快照里的哪个包身份」；
--   * kernel_state 与 inventories 1:1，mapping_evidence 为空表示未认定映射；
--   * inventories.release 不设外键：资产采集是事实记录，允许未登记 release
--     落库（生命周期未知），修复准入在 planner 阶段另行查 distro_releases。

CREATE TABLE inventories (
    id                INTEGER PRIMARY KEY,
    distro_id         TEXT NOT NULL REFERENCES distros(id),
    release           TEXT NOT NULL,                  -- VERSION_ID，自由文本
    codename          TEXT NOT NULL DEFAULT '',
    arch              TEXT NOT NULL,                  -- uname -m 原值
    kernel_running    TEXT NOT NULL DEFAULT '',       -- uname -r 原值
    package_manager   TEXT NOT NULL DEFAULT 'none'
                      CHECK (package_manager IN ('dpkg','rpm','apk','pacman','none')),
    package_count     INTEGER NOT NULL DEFAULT 0,
    collected_at      TEXT NOT NULL,
    hash              TEXT NOT NULL,                  -- 快照哈希（顺序无关）
    collector_version TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_inventories_hash ON inventories(hash);
CREATE INDEX idx_inventories_collected ON inventories(collected_at);

CREATE TABLE inventory_packages (
    id                 INTEGER PRIMARY KEY,
    inventory_id       INTEGER NOT NULL REFERENCES inventories(id) ON DELETE CASCADE,
    package_kind       TEXT NOT NULL CHECK (package_kind IN ('source','binary')),
    name               TEXT NOT NULL,
    arch               TEXT NOT NULL,                 -- 原生架构标识逐字保留
    version_raw        TEXT NOT NULL,                 -- 原始版本串，无损保留
    version_epoch      INTEGER NOT NULL DEFAULT 0,
    version_upstream   TEXT NOT NULL DEFAULT '',
    version_release    TEXT NOT NULL DEFAULT '',
    source_name        TEXT NOT NULL DEFAULT '',      -- 空 = 桥接失败
    source_version_raw TEXT NOT NULL DEFAULT '',
    manager            TEXT NOT NULL
                       CHECK (manager IN ('dpkg','rpm','apk','pacman','none')),
    origin_channel     TEXT NOT NULL DEFAULT 'unknown',
    origin_evidence    TEXT NOT NULL DEFAULT '',
    vendor             TEXT NOT NULL DEFAULT '',
    install_time       TEXT,                          -- RFC3339，未知为 NULL
    entry_hash         TEXT NOT NULL DEFAULT '',
    UNIQUE (inventory_id, package_kind, name, arch)
);

CREATE INDEX idx_inv_pkgs_name ON inventory_packages(package_kind, name);

CREATE TABLE kernel_state (
    id                 INTEGER PRIMARY KEY,
    inventory_id       INTEGER NOT NULL UNIQUE REFERENCES inventories(id) ON DELETE CASCADE,
    running_version    TEXT NOT NULL DEFAULT '',
    kernel_package     TEXT NOT NULL DEFAULT '',      -- 无精确证据为空
    package_version_raw TEXT NOT NULL DEFAULT '',
    mapping_evidence   TEXT NOT NULL DEFAULT ''       -- 空 = 未认定映射
);
