# Linux CVE Tool v2.0.0 正式发布与验收报告

| 项目 | 值 |
| --- | --- |
| 版本 | **v2.0.0（Stable）** |
| 发布日期 | 2026-11-24 |
| 仓库 | `AronWang001/linux-cve`（2026-11-24 由 `linux-cve-2026-98432-fix` 更名，旧地址 301 跳转） |
| 发布地址 | https://github.com/AronWang001/linux-cve/releases/tag/v2.0.0 |
| 标签 | `v2.0.0` → `main` @ `1d4021c` |
| 合并方式 | PR #5（`feat/v2.0.0` → `main`），merge commit `4a41961` |
| 发布物 | `linux-cve_2.0.0_linux_amd64.tar.gz`（5.76MB）、`linux-cve_2.0.0_linux_arm64.tar.gz`（5.22MB）、`SHA256SUMS`、`install.sh` |
| 发布形态 | Draft: false，Prerelease: false |
| 代码规模 | 93 个 Go 文件 / 21,503 行；仓库 166 个跟踪文件 |
| 测试 | **241 PASS / 0 FAIL / 5 SKIP**（SKIP 为真实数据集测试，提供数据后全部 PASS） |
| 验收环境 | Debian 13 trixie（x86_64），`43.156.247.54` |

---

## 1. 交付对照

| 目标书要求 | 状态 | 证据 |
| --- | --- | --- |
| Go 模块与工程骨架 | ✅ | `cmd/linux-cve` + `internal/` 12 个包，`go build`/`go vet` 通过 |
| 六源数据接入 | ✅ | 六源全部真实同步入库：481,139 公告 / 2,062,599 修复 |
| matcher 判定引擎 | ✅ | 三状态维度、原生版本比较、源码包桥接、覆盖判定 |
| `scan`/`list`/`show`/`report` | ✅ | 实机运行，退出码 0/3/9 语义正确 |
| `plan`/`fix` 受控修复 | ✅ | 五道闸门 + 执行后复检 + 附带变更核对，Debian 13 实机验证 |
| `feed update`/`feed status` | ✅ | 索引驱动增量、GPG 验签、替换快照、文件锁 |
| `support` 支持矩阵 | ✅ | 三类能力分列，未登记 release 一律 UNKNOWN |
| 完整性校验 | ✅ | A 级源 13,561 + 10,409 份文档 100% `signature=verified`、`integrity=verified` |
| 中文文档 | ✅ | README + 10 份 docs，含数据源、安全模型、CLI、排障、迁移 |
| GitHub CI/CD | ✅ | `go`（构建/测试/竞态/交叉编译/三发行版端到端/发布）+ `test`（v1 回归）+ `version-diff` 全绿 |
| PR 合并 main | ✅ | PR #5 |
| Stable Release | ✅ | 非 Draft、非 Prerelease，4 个资产 |
| 发布后验收 | ✅ | 20 项全通过（见 §5） |
| `GOAL COMPLETED — v2.0.0 STABLE RELEASED` | 见 §8 |

---

## 2. 六源接入实测（2026-11-24，单库）

| 源 | 信任级 | 文档/文件 | 公告 | 修复记录 | 耗时 |
| --- | --- | --- | --- | --- | --- |
| Debian Security Tracker | B | 1 个 JSON（92.5MB） | 210,415 | 222,161 | 17.9s |
| Ubuntu OVAL noble | B | 11.4MB bz2 → 270.8MB XML | 37,611 | 48,617 | 20.0s |
| Alpine secdb 3.20 | B | main + community 2 个 JSON | 8,299 | 8,344 | 3.1s |
| Arch Security Tracker | B | 1 个 JSON（898KB） | 8,035 | 7,401（+303 不受影响） | 1.8s |
| Red Hat CSAF（2026 切片） | A | 10,409 份 JSON + `.asc` | 66,991 | 810,817（+26,327 不受影响） | 约 8 分钟 |
| SUSE CSAF（2026 切片） | A | 13,561 份 JSON + `.asc` | 149,788 | 965,304 | 11.5 分钟 |
| **合计** | | **24k 个不可变文件（6.1GB）** | **481,139** | **2,062,599** | SQLite 1.5GB |

签名与完整性：`rhel-csaf` 10,409 份、`suse-csaf` 13,561 份全部 `signature=verified`
且 `integrity=verified`；指纹硬编码（Red Hat `77E79ABE…`、SUSE `6B62473B…`），
换钥必须改代码发版。

二次同步全部复用本地 CAS 字节（RHEL：新下载 0、复用 10,409、3 分 1 秒）。

---

## 3. 判定与修复

### 3.1 Debian 13 全量扫描

```
扫描：debian  13  架构 x86_64
覆盖：COVERED（该发行版所需的全部情报源均可用且未过期）
判定 124,470 条：受影响 10,230、已修复 100,985、不受影响 0、未知 13,255
统计：参与判定包 455 个，其中 206 个在情报库中无任何记录（属覆盖缺口，不代表安全）
退出码：3（FINDINGS）
```

「无数据包」构成量化：455 个包中 60 个按二进制名直接命中、239 个仅按源码名命中
（桥接生效）、157 个完全无记录；**「源码名本应命中却未命中」为 0**。

### 3.2 自动修复（实机）

| 轮次 | 包 | 从 | 到 | 复检 | 退出码 |
| --- | --- | --- | --- | --- | --- |
| 1 | `libcap2`、`libcap2-bin` | `1:2.75-10+b1` | `1:2.75-10+deb13u1+b3` | OK | 0 |
| 2 | `libsqlite3-0` | `3.46.1-7` | `3.46.1-7+deb13u2` | OK | 0 |

修复后重扫：受影响 10,230 → **10,228**，已修复 100,985 → 100,987。数字只动了 2 条，
与「修好 2 个包的 2 条判定」严格对应——这是判定链路没有虚报的证据。

反例验证：清空 `allow_auto_fix` 后 `fix --yes` 返回 **4（UNSUPPORTED）**，
计划显示「不可执行 —— 配置未开启自动修复」。

### 3.3 CI 内三发行版端到端

每次提交在官方镜像里真实同步官方情报并真实扫描（不是 mock）：

| 发行版 | 判定条数 | 受影响 | 已修复 | 未知 | 覆盖 |
| --- | --- | --- | --- | --- | --- |
| Debian 13 | 2,029 | 174 | 1,855 | 0 | COVERED |
| Ubuntu 24.04 | 316 | 12 | 304 | 0 | COVERED |
| Alpine 3.20 | 45 | 1 | 44 | 0 | COVERED |

---

## 4. 这一轮靠 CI 才发现的缺陷

发布过程中暴露的 9 个真实缺陷，全部已修并有测试覆盖。列出来是因为它们决定了
「结论能不能信」：

| # | 缺陷 | 后果 | 修法 |
| --- | --- | --- | --- |
| 1 | Debian `status=open` / Alpine 空版本键被丢弃 | 把「有洞且无补丁」变成「情报库无记录」，结论正好说反 | 落空版本记录，`IsAffectedNoFix()` |
| 2 | Red Hat 产品树按「父子」实现 | 一份公告 0 条修复记录，公告计数却正常 | 按「兄弟」结构登记全部 product_id，认 relationship |
| 3 | 指纹归一化把数字也减了 32 | 含数字的指纹（Red Hat）永远匹配不上 | 只对 `a-f` 做偏移 |
| 4 | 覆盖判定用 `ParserFor` 判断解析器 | 已接入的 RHEL/SUSE 被报「解析器未实现」 | 改用 `ParserReady` |
| 5 | 覆盖判定没按发行版过滤 | 无关源把覆盖永久压成 PARTIAL，干净机器拿不到退出码 0 | 源声明 `Distros` |
| 6 | `allow_auto_fix` 只解析不生效 | `--yes` 可绕过「默认关闭」的安全开关 | 接入 `buildPlan` 作为硬闸门 |
| 7 | `apk list --manifest` 只有 apk-tools 3.x 有 | Alpine 3.20 上采集直接失败 | 回退 `apk list --installed -v` + 版本可解析性切分 |
| 8 | release 粒度不一致（3.20.3 vs 3.20、9.4 vs 9） | **判定 0 条且退出码 0**，看起来像「没有漏洞」 | `normalizeRelease` + 空清单/全部对不上拒绝出结论 |
| 9 | 发布包二进制无执行位、`SHA256SUMS` 带 `./` 前缀 | 用户解包后 `Permission denied`、安装脚本报「没有记录」 | `chmod 0755`、awk 兼容三种写法 |

第 8 条最危险：它不报错、不告警，只是安静地给出「一切正常」。

---

## 5. 发布后验收（20 项，全通过）

用发布页的 `install.sh` 装出的 `/usr/local/bin/linux-cve`（commit `ab80e24`）执行：

| # | 验收项 | 结果 |
| --- | --- | --- |
| 1 | `version` 输出 2.0.0 | OK |
| 2 | `db status` 可用 | OK |
| 3 | `db migrate` 幂等 | OK |
| 4 | 六个情报源状态均为 ok | OK |
| 5 | `scan` 有受影响项退出码 3 | OK |
| 6 | 覆盖判定 COVERED | OK |
| 7 | `list --state FIXED --limit 5` 返回 5 条 | OK |
| 8 | `list` 头部同时给出总数与显示条数 | OK |
| 9 | `show` 输出证据链 | OK |
| 10 | `report --out` 写入成功 | OK |
| 11 | 报告含覆盖章节 | OK |
| 12 | 报告正确反映 RHEL 源已同步 | OK |
| 13 | `plan` 退出码 0 且输出计划 | OK |
| 14 | `fix` 不带 `--yes` 只预演并提示 | OK |
| 15 | 关闭 `allow_auto_fix` 后 `fix --yes` 退出码 4 | OK |
| 16 | `support` 含 Debian 13 | OK |
| 17 | `scan --json` 带 `schema_version` | OK |
| 18 | `help` 列出退出码 9 | OK |
| 19 | 发布包 SHA256 与 `SHA256SUMS` 一致 | OK |
| 20 | `install.sh` 下载→校验→安装→可执行 | OK |

CI 侧：`go`（构建/单测/竞态/双架构交叉编译/三发行版端到端/发布）、`test`（v1 回归）、
`version-diff`（dpkg/rpm/apk/pacman 四容器原生差分）在 `v2.0.0` 标签上**全部 success**。

---

## 6. 已知限制（不 promise 的事）

1. **未收录 ≠ 不受影响**。覆盖不足用退出码 9 表达，无法消除这一不确定。
2. **自动修复只开放 Debian 12/13**。RHEL / SLES / openSUSE / Ubuntu / Alpine / Arch
   的数据与解析器就绪，但没有在这些发行版上做过实机修复验收，因此不开放。
3. **RHEL 与 SUSE 的 VEX 源未接入**。RHEL 的「不受影响」来自 RHSA 内的
   `known_not_affected`（26,327 条）；SUSE 主 feed 全为 `recommended`，
   因此 SUSE 侧没有「不受影响」与「无修复方案」两类结论。
4. **容器验收 ≠ 裸机验收**。Ubuntu 24.04 / Alpine 3.20 在官方镜像内跑通，
   共用宿主内核，测试矩阵里标「容器」而不是「实机」。
5. **能力回退，必须明说**：v1.x 支持的 **Amazon Linux 2 / 2023 与 CloudLinux**
   在 v2.0.0 中**既无情报源也无适配层**，这些主机会被判为 `UNSUPPORTED`。
   这是 v2 相对 v1 的功能减少，不是遗漏的 bug——需要它们请留在 v1.3.2。
6. **Alpine 3.19–3.21 均已 EOL**，检测可用但自动修复不开放；新 release 需在
   `internal/support/matrix.go` 登记，未登记一律 UNKNOWN。
7. **生命周期日期手工维护**，发行版延期 EOL 时必须改代码发版。
8. **CSAF 源体积大**：RHEL 全量约 11GB、SUSE 约 8GB，建议 `--since` 按年切。

---

## 7. 仓库与文档

新增/重写文档：

| 文档 | 内容 |
| --- | --- |
| `README.md` / `README.en.md` | 定位、「这个工具不做什么」、六源实测、命令、支持矩阵 |
| `docs/data-sources.md` | 六源真实结构、字段语义、每个反直觉的坑 |
| `docs/security-model.md` | A/B 信任分级、签名与完整性分列、失败语义、五道闸门 |
| `docs/cli.md` | 逐命令参数、真机输出样例、退出码、CI 用法 |
| `docs/support-matrix.md` | 三类能力分别验收，实机/容器/仅数据三档证据 |
| `docs/troubleshooting.md` | 按「看到什么→为什么→怎么办」组织 |
| `docs/migration-v1-v2.md` | 退出码对照（v1 的 3 是待重启，v2 的 3 是发现漏洞） |
| `docs/release-notes-v2.0.0.md` | 发布说明正文 |
| `packaging/install.sh` | 按架构下载、SHA256 校验、安装二进制 |

---

## 8. 结论

六源接入、判定引擎、受控修复与发布链路均已跑通，并在 Debian 13 实机与
Debian 13 / Ubuntu 24.04 / Alpine 3.20 三个发行版容器内验证；发布包本身
通过 SHA256 校验、可执行、20 项验收全通过。

需要明确的是：**v2.0.0 的自动修复只对 Debian 12/13 背书**，其余发行版只是
「能检测、能给出官方修复版本」，不是「能安全地替你修」。Amazon Linux 与
CloudLinux 相对 v1.x 是能力回退，已在上文列明。

`GOAL COMPLETED — v2.0.0 STABLE RELEASED`（附带 §6 的已知限制与能力回退声明）。
