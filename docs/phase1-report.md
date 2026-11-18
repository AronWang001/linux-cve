# 阶段 1 交付与验证记录

- 阶段：1/9
- 日期：2026-11-18
- 分支：`feat/v2.0.0`（基于 `main` @ `ec1415b`）
- 版本号：`2.0.0-dev`

---

## 1. 交付清单

| 类别 | 内容 |
|------|------|
| 工程骨架 | `go.mod`、`go.sum`、`Makefile`、`cmd/linux-cve/main.go` |
| CLI | `internal/app`（分发、`version`、`help`、`db status`、`db migrate`）、`internal/exitcode` |
| 基础设施 | `internal/config`（TOML+env+flag）、`internal/logging`（slog）、`internal/apperr`（错误→退出码） |
| 数据库 | `internal/database`（打开/PRAGMA/迁移）、`migrations/0001_init.sql` |
| 领域模型 | `internal/domain`（distro、package、version、cve、advisory、finding、inventory） |
| 文档 | `docs/architecture.md`、`docs/data-model.md`、`docs/support-matrix.md`、`docs/cli.md` |

规模：源码 2,271 行，测试 1,606 行，SQL 197 行，文档 949 行。

## 2. 八项修订的落实位置

| # | 修订要求 | 文档 | 代码 / 测试 |
|---|----------|------|-------------|
| 1 | 区分 source/binary 包，处理 Debian 源码包公告与二进制包关联 | `architecture.md` §4、`data-model.md` §2 | `domain.PackageKind`、`InstalledPackage.SourceName`（桥接失败→UNKNOWN）；`TestAdvisoryFixValidate` 逐项断言必填 |
| 2 | 修正 advisories 唯一索引 | `data-model.md` §4.4（含缺维度的错误对照表） | `0001_init.sql` 九列 UNIQUE；`TestAdvisoryFixUniqueScopedByCoordinate` 用 debian/ubuntu、12/13、security/backports 四组坐标验证 |
| 3 | 漏洞状态与修复状态拆为独立维度 | `architecture.md` §5、`data-model.md` §3 | `domain.VulnState`/`RemediationState`/`RuntimeState` + `Finding.Validate` 不变量；`TestFindingDimensionInvariants` |
| 4 | 重设 PENDING_RESTART 判定 | `architecture.md` §6（四类误判 + 四级证据链） | 模型层 `ServiceRestart.Confidence`；采集实现留待阶段 5，`TestFindingValidateRejectsInvalid` 校验可信度枚举 |
| 5 | pacman 预演不可靠 → Arch 不开放自动修复 | `architecture.md` §7.1、`support-matrix.md` §3 | 能力矩阵留待 `package_manager`（阶段 5）实现 `SupportsAutoFix()`；本阶段在文档中定案 |
| 6 | AL2 EOL 2026-06-30 → Legacy，不纳入首期自动修复 | `support-matrix.md` §2、`architecture.md` §9 | 种子数据 `amzn:2` = `legacy` / `2026-06-30`；`TestSeedData` 断言；`Release.SupportsAutoFix()` 拒绝 legacy |
| 7 | AL2 updateinfo 验证状态不得夸大 | `architecture.md` §10（逐源标注） | 文档标记 `unverified`；`feed_sources.validation_level` 枚举预留 `unverified` |
| 8 | 架构图区分签名与 TLS/哈希，增加资产采集输入 | `architecture.md` §2 图 + §3 分级表 | `feed_sources` 表把 `signature_kind` / `content_hash` / `validation_level` 拆成三列，禁止合并为单一 `verified` |

## 3. 构建结果

```
$ go version
go version go1.27.4 windows/amd64

$ go build ./...          # 无输出，退出码 0
$ go vet ./...            # 无输出，退出码 0

$ CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ...
  7,823,520 字节  dist/linux-cve-linux-amd64
$ CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build ...
  7,536,800 字节  dist/linux-cve-linux-arm64
```

纯 Go 实现（`modernc.org/sqlite`）无需 cgo，两个 Linux 目标均交叉编译成功。二进制未在 Linux 上运行过，见 §6。

## 4. 测试结果

命令与真实结果：

```
$ go test ./...
ok  internal/app        0.174s
ok  internal/apperr     (cached)
ok  internal/config     (cached)
ok  internal/database   (cached)
ok  internal/domain     (cached)
ok  internal/exitcode   (cached)
ok  internal/logging    (cached)
?   cmd/linux-cve       [no test files]
?   internal/buildinfo  [no test files]

$ go test ./... -v | grep -c "^=== RUN"     → 67
$ go test ./... -v | grep -c "FAIL|SKIP"    → 0
$ CGO_ENABLED=1 go test -race ./...         → 全部 ok（8 包 1.1–1.9s）
```

分布：app 10、apperr 3、config 10、database 12、domain 26、exitcode 2、logging 4。

关键用例：

- `TestMigrateFreshDatabase` / `TestMigrateIdempotent`：首次应用 1 个迁移，重复执行为 0。
- `TestChecksumTamperDetected`：篡改 `schema_migrations.checksum` 后 `db migrate` 返回 `INTEGRITY`。
- `TestNewerSchemaRejected`：库版本高于二进制时拒绝启动，返回 `INTEGRITY`。
- `TestForeignKeyEnforced`：未登记发行版被外键拒绝，脏数据无法进入判定链。
- `TestWALAndForeignKeysEnabled`：实际读取 `PRAGMA journal_mode` = `wal`、`foreign_keys` = 1。
- `TestAutoFixEligible`：11 组组合，覆盖 Legacy/EOL/未知/无修复包/仓库未同步等拒绝对应原因码。
- `TestInventoryHashOrderIndependent`：包顺序打乱后快照哈希不变（闸门可用性的前提）。

未执行项：无 Linux 实机测试、无 GUI/交互测试（本阶段无交互功能）。

## 5. CLI 实测输出

```
$ ./linux-cve version
linux-cve 2.0.0-dev (commit ec1415b, built unknown, go1.27.4, windows/amd64)

$ ./linux-cve db migrate
applied 1 migration(s); schema version = 1

$ ./linux-cve db status
database    : C:\...\smoke.db
schema      : 1
migrations  : 0001_init (2026-11-18T02:41:20Z)
pending     : none
feed sources: 0 registered

$ ./linux-cve db migrate
no pending migration; schema version = 1

$ ./linux-cve scan ; echo $?
error: cli: scan 尚未实现（阶段 3）
8

$ ./linux-cve frobnicate ; echo $?
error: cli: 未知子命令: frobnicate（运行 linux-cve help 查看用法）
2
```

## 6. 未解决问题与限制

1. **无 Linux 实机**：全部验证在 Windows/amd64 完成。Linux 二进制仅交叉编译，未运行；`/var/lib/linux-cve` 目录权限（0750）、`/etc/linux-cve/config.toml` 归属、非 root 运行的权限错误路径均未在真实 Linux 上验证。→ 阶段 2 前需要 VM 清单（Debian 12/13、Ubuntu 22.04/24.04、AL2023）。
2. **Windows 上验证了 WAL 与并发**，未验证 Linux 文件系统挂载选项（如 NFS/overlay 上的 WAL 行为）。
3. **`app_meta.schema_version` 与 `schema_migrations` 双记录**：当前两者由迁移种子与迁移记录分别写入，尚无一致性校验代码。阶段 3 加入数据更新时需要补校验或用单一来源。
4. **依赖供应链**：模块经 `goproxy.cn` 拉取，校验使用 `sum.golang.google.cn`。CI 落地时需固定 `GOPROXY`/`GOSUMDB` 或改用 vendor，避免不同网络环境解析到不同代理。
5. **`go.sum` 依赖 9 个间接模块**（`modernc.org/libc`、`mathutil`、`memory` 等），后续需在阶段 7 做依赖安全审计。
6. **未实现的表**：`inventories`、`findings`、`plans`、`audit_log` 按阶段 2/3/5 的迁移追加，当前 Schema 只到情报层。
7. **未接入 CI**：`.github/workflows/test.yml` 仍是 v1.3.2 的 Bash 测试，尚未添加 Go 检查任务。计划在阶段 2 一并添加（避免当前提交引入需要额外凭据的配置）。

## 7. 阶段 2 的前置条件

- 测试环境清单（可销毁 VM 或 SSH 主机）：Debian 12、Debian 13、Ubuntu 22.04、Ubuntu 24.04、Amazon Linux 2023。
- 确认包清单采集方式：只读调用 `dpkg-query` / `rpm -q` / `apk info`，不刷新元数据、不安装依赖。
- 确认版本比较的交叉验证方式：与 `dpkg --compare-versions`、`rpmdev-vercmp` 或 `rpm --eval` 的真实输出逐条比对。
