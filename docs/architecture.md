# Linux CVE Fix v2.0 架构设计（阶段 1 修订版）

- 版本：2.0.0-draft.2
- 基线：v1.3.2（`ec1415b`）
- 修订日期：2026-11-18
- 本版依据阶段 0 审批意见修订 8 处，修订点在各章以 `[修订 N]` 标注。

---

## 1. 目标与边界

### 1.1 目标

在单台 Linux 主机上完成：识别自身资产 → 用发行版官方数据判定 CVE 影响 → 生成可审计的修复计划 → 用户确认后执行 → 复检 → 出报告。全流程本地执行，可在离线状态下复用已缓存情报。

### 1.2 边界（v2.0 明确不做）

- Docker 镜像内部、pip / npm / Maven / Go modules 等应用依赖。
- 自动重启主机、删除旧内核、编译自定义内核。
- 自动添加第三方软件源、切换发行版大版本。
- 全系统无差别升级。
- 对 `UNKNOWN` 状态执行自动修复。

### 1.3 核心原则

1. **判定依据必须来自目标发行版本身**，不接受用上游版本号或 NVD 通用 CPE 推断发行版包状态。
2. **检测支持 ≠ 修复版本查询支持 ≠ 自动修复支持**，三者分别声明、分别验收。
3. **未知一律不放行**：任何证据缺失都落到 `UNKNOWN`，不落到「不受影响」。
4. **修复是独立引擎**，扫描引擎无写权限，修复引擎不得复用扫描结论而不复核。

---

## 2. 总览数据流 `[修订 8]`

```
                  ┌──────────────────────────────┐
                  │  本机资产采集（只读）        │
                  │  /etc/os-release  uname      │
                  │  dpkg-query / rpm -qa        │
                  │  apk info -v / pacman -Q     │
                  │  内核包映射  仓库候选版本    │
                  └──────────────┬───────────────┘
                                 │ Inventory
                                 ▼
┌───────────────┐      ┌──────────────────┐      ┌─────────────────┐
│ 情报源 A 级   │      │                  │      │  匹配器 matcher │
│ 官方签名数据  │─────▶│  SQLite 情报库   │─────▶│  同一 distro+   │
│ (SUSE CSAF    │      │  advisories      │      │  release+channel│
│  .asc 分离签) │      │  advisory_fixes  │      │  + arch 内比较  │
├───────────────┤      │  cve_meta        │      └────────┬────────┘
│ 情报源 B 级   │      │                  │               │
│ 官方 HTTPS    │─────▶│                  │               ▼
│ (Debian/Ubuntu│      └──────────────────┘      ┌─────────────────┐
│  /RH/Alpine/  │                                 │ 双维状态 + 证据 │
│  Arch/ALAS)   │                                 │ VulnState       │
├───────────────┤                                 │ RemediationState│
│ 情报源 C 级   │                                 │ RuntimeState    │
│ NVD / CVE.org │──▶ 只补元数据（描述/CVSS/参考） │ + Evidence[]    │
│ 不参与受影响  │                                 └────────┬────────┘
│ 判定          │                                          │
└───────────────┘                                          ▼
                                              ┌──────────────────────────┐
                                              │ 修复计划 planner（只读） │
                                              │ 变更集预演 + 安全闸门    │
                                              └────────────┬─────────────┘
                                                           │ 用户确认
                                                           ▼
                                              ┌──────────────────────────┐
                                              │ 修复引擎 remediation     │
                                              │ 锁检测→执行→验证→复检    │
                                              └────────────┬─────────────┘
                                                           ▼
                                              ┌──────────────────────────┐
                                              │ 报告 report (TXT / JSON) │
                                              └──────────────────────────┘
```

`[修订 8]` 三点变化：

1. **本机资产采集**成为流水线的第一等输入，不再是「扫描器的内部细节」。它决定后续所有匹配的候选集。
2. 情报源按**信任等级**分层绘制：A 级 = 官方数据自带密码学签名（当前仅 SUSE CSAF 提供 `.asc` 分离签名）；B 级 = 官方 HTTPS 发布、仅 TLS + 内容哈希保护；C 级 = 仅元数据，不参与受影响判定。详见第 3 章。
3. 「签名校验」与「传输完整性校验」在图上是两条不同的通路，实现与报告中也必须分开计数，不得混称「已签名验证」。

---

## 3. 数据源信任分级 `[修订 8]`

| 级别 | 定义 | 校验手段 | 当前来源 | 报告措辞 |
|------|------|----------|----------|----------|
| A | 官方提供数据文件与分离/内嵌密码学签名 | 验签（minisign/GPG/CSAF `signatures`）+ 内容哈希 | SUSE CSAF（`.json.asc`） | `signature_status: verified` |
| B | 官方 HTTPS 发布，无独立签名 | TLS 证书链 + SHA256 记录 + 单调时间戳 | Debian Tracker JSON、Ubuntu OVAL/USN、Red Hat OVAL/CSAF/Security API、Alpine secdb、Arch 追踪器、ALAS / updateinfo | `signature_status: not-applicable; integrity_status: verified` |
| C | 社区/聚合元数据 | 同上，且仅用于补充描述与评分 | NVD 2.0 API、cve.org API | `metadata-only` |

实现约束（`[修订 P1-5]`：签名验证与内容完整性验证是两条独立通路）：

- 校验结果随每条 `advisory` 落库：`feed_sources.trust_level` + `signature_kind` + `signature_status` + `integrity_status` + `content_hash`，报告逐条可查。
- `signature_status` 只记录**密码学签名**验证结果；`integrity_status` 只记录**内容哈希**比对结果。**禁止**把「下载源同站提供的 checksum 通过」表述为「数字签名验证通过」。此约束在 `internal/feed` 中以 API 形状强制：`VerifyResult{SignatureStatus, IntegrityStatus}` 两个独立字段，不允许合并成 `Verified`。
- A 级源验签失败时整批数据丢弃（`signature_status='failed'`），并降级为 `UNKNOWN`，不得「继续使用上次缓存但不提示」——必须显式标记 `stale: true`。

---

## 4. 源码包与二进制包模型 `[修订 1]`

### 4.1 问题

发行版公告的粒度不统一：

| 来源 | 公告粒度 |
|------|----------|
| Debian Security Tracker | **源码包**（`linux`、`openssl`），按 suite 给 `fixed_version` |
| Ubuntu USN / OVAL | USN 写源码包，OVAL 定义针对**二进制包**（`linux-image-6.8.0-149-generic`） |
| RHEL Security API | `package_state` 是源码包级，`affected_release` 是二进制 NEVRA |
| RHEL OVAL | 二进制包 + 固定 EVR |
| SUSE CSAF | 产品树里的二进制包（含 `-base`/`-default` 等 flavor） |
| Alpine secdb | `origin`（源码包）级 `secfixes` |
| Arch 追踪器 | `pkgbase` 级，固定版本为 pkgrel 完整版本 |

本机安装的永远是**二进制包**。若把公告的源码包名直接与二进制包名比对，Debian 系会漏报（`linux` vs `linux-image-6.8.0-31-generic`），若把二进制包名当源码包写进情报库，跨发行版又会错配。

### 4.2 模型

```
PackageKey{ Kind: source|binary, Name, Arch }
        ▲                          ▲
        │                          │
  AdvisoryFix                 InstalledPackage
  (公告声明的受影响/修复对象)   (本机实际安装)
                                   │ DerivedFrom(source_name, source_version)
                                   ▼
                              SourceRef{Name, Version}
```

三条硬规则：

1. **公告与安装包各自保留自身的 Kind**，不在入库时强行统一。`advisory_fixes.package_kind` 明确记 `source` 或 `binary`。
2. **匹配只在同一坐标内进行**：源码包公告匹配 `installed.source_package`；二进制包公告匹配 `installed.name`。两者都用本机 `source_package` 字段做桥接，而不是字符串猜测（禁止 `strings.TrimPrefix(name, pkg+"-")` 这类前缀猜测作为唯一依据）。
3. **桥接失败即 `UNKNOWN`**：若公告为源码包级，而本机 dpkg 未提供该二进制包的 `Source` 字段（或 `Source` 与公告名不一致），该包落 `UNKNOWN`，附证据 `source_bridge_unresolved`，不落 `NOT_AFFECTED`。

本机桥接数据来源：

| 包管理器 | 二进制 → 源码 | 版本来源 |
|----------|---------------|----------|
| dpkg | `dpkg-query -W -f='${Source}\n'`（缺省等于包名，可能带 `(version)`） | `${Version}`（含 epoch） |
| rpm | `rpm -q --qf '%{SOURCERPM}'`（`name-version-release.src.rpm`） | `%{EPOCH}:%{VERSION}-%{RELEASE}` |
| apk | `apk info -v` + `apk info -a` 的 `origin` 字段 | `version-rN` |
| pacman | `pacman -Qi` 的 `%n`（pkgbase 关系由 `pkgbase` 提供，缺失时退回包名） | `pkgver-pkgrel` |

### 4.3 一对多展开

一个源码包公告可能命中同一主机的多个二进制包（如 `linux` → `linux-image-*`、`linux-headers-*`、`linux-modules-*`）。展开规则：

- 全部命中的二进制包各自生成一条 `finding`，共享同一 `advisory_uid`。
- 修复计划按**二进制包实际安装名**生成升级目标，不按源码包名。
- 若命中包中任一为运行中内核提供者，该 finding 额外携带 `runtime_kernel: true`，供 `RuntimeState` 使用。

---

## 5. 状态模型：三个独立维度 `[修订 3]`

原设计中 `VULNERABLE / FIX_AVAILABLE / FIXED / PENDING_REBOOT` 混在一个枚举里，导致「已修但需重启」既像修复完成又像未完成。改为三个正交维度：

### 5.1 维度一：漏洞状态 `VulnState`（检测结论，只回答「这台机器现在有没有这个洞」）

| 值 | 含义 | 成立条件 |
|----|------|----------|
| `VULNERABLE` | 确认受影响 | 同发行版同 release 官方数据给出固定版本，且本机版本按该包管理器规则 **<** 固定版本 |
| `FIXED` | 已修复 | 同上，但本机版本 **>=** 固定版本（含回移补丁场景，见 5.4） |
| `NOT_AFFECTED` | 官方确认不受影响 | 官方数据显式声明该 release/包不受影响，或该包根本未被该 release 收录 |
| `UNKNOWN` | 无法可靠判定 | 无官方数据覆盖、桥接失败、数据过期、版本不可比 |
| `UNSUPPORTED` | 环境不支持 | 发行版/release/包管理器不在支持矩阵内 |

### 5.2 维度二：修复可行性 `RemediationState`（只回答「能不能修、怎么修」）

| 值 | 含义 |
|----|------|
| `FIX_AVAILABLE` | 官方已发布固定版本，且本机软件源可达该版本 |

| `NO_FIX` | 官方确认受影响但尚未发布修复包 |
| `FIX_PENDING_MIRROR` | 官方已发布，但本机仓库尚未同步到该版本 |
| `MANUAL_REQUIRED` | 需要人工处理（多源冲突、需大版本升级、需重新配置等） |
| `BLOCKED` | 计划未通过安全闸门（变更集超限、依赖异常、锁占用） |
| `NOT_APPLICABLE` | 无需修复（对应 `VulnState` 为 `FIXED`/`NOT_AFFECTED`/`UNSUPPORTED`） |
| `UNKNOWN` | 无法确认修复路径 |

### 5.3 维度三：运行时状态 `RuntimeState`（只回答「补丁装上了，但进程还用着旧的没」）

拆成两个子字段，因为它们证据不同、风险不同：

```go
type RuntimeState struct {
    Reboot  RebootState  // NOT_REQUIRED | REQUIRED | UNKNOWN
    Restart []ServiceRestart // 受影响服务列表
}
```

`ServiceRestart` 携带 `Confidence`（`CONFIRMED | LIKELY | UNKNOWN`）与 `Evidence []string`，见第 6 章。

### 5.4 组合语义表（终态展示与自动修复准入）

| VulnState | RemediationState | 展示 | 自动修复 |
|-----------|------------------|------|----------|
| `VULNERABLE` | `FIX_AVAILABLE` | 可修复 | 允许（通过闸门后） |
| `VULNERABLE` | `NO_FIX` | 暂无修复 | 禁止 |
| `VULNERABLE` | `FIX_PENDING_MIRROR` | 仓库未同步 | 禁止 |
| `VULNERABLE` | `MANUAL_REQUIRED` / `BLOCKED` | 需人工 | 禁止 |
| `VULNERABLE` | `UNKNOWN` | 状态未知 | 禁止 |
| `FIXED` | `NOT_APPLICABLE` | 已修复 | 不需要 |
| `FIXED` + `Reboot=REQUIRED` | `NOT_APPLICABLE` | 已修复，待重启 | 不需要（仅提示） |
| `NOT_AFFECTED` | `NOT_APPLICABLE` | 不受影响 | 不需要 |
| `UNKNOWN` / `UNSUPPORTED` | 任意 | 未知/不支持 | **禁止** |

硬约束：`AutoFixEligible()` 只在 `VULNERABLE` + `FIX_AVAILABLE` + 固定版本已知 + 生命周期为 `active` 时返回 true；其余一律 false 并给出 `ReasonCodes`。这条函数放在 `internal/domain`，由 planner 与 fix 共用，避免两处判定漂移。

`RuntimeState` 不参与准入判断：重启状态未知不构成拒绝理由，只在报告中标注「待重启状态未确认」。把它当作阻塞项会让缺少内核包元数据的主机全部无法修复，收益与代价不成比例。

**回移补丁的处理**（5.1 中「含回移补丁场景」）：只比较**同一 distro + release + channel 内**的官方固定版本号，使用该包管理器原生比较规则。Debian 的 `6.12.113-1~deb12u1` 与上游 `6.12.113` 不做任何跨体系比较；`~deb12u1` 后缀本身即表示回移，原生 dpkg 比较会自动判定其低于 `6.12.113-1`，这正是需要的语义。

---

## 6. PENDING_RESTART 的多证据判定 `[修订 4]`

### 6.1 为什么不能只看进程启动时间

`ps -o lstart` 或 `/proc/<pid>/stat` 的启动时间只能说明「进程比某个时刻晚启动」，存在四类误判：

1. 服务在升级后**恰好因其他原因重启**（配置同步、OOM、crash loop），时间晚于升级但仍是旧逻辑——实测中时间关系无法区分。
2. 升级后**新进程从磁盘重读**已加载的旧共享库仍然存在（`/proc/<pid>/maps` 显示 `(deleted)`），时间比对漏判。
3. 容器/短生命周期进程无稳定启动时间。
4. 升级时间本身不可靠：`dpkg.log`、`dnf history`、`apk` 日志、`pacman.log` 四者格式与时区不同，跨午夜或时区偏移会反转比较结果。

### 6.2 判定证据链（按可信度降序）

| # | 证据 | 采集方式 | 可信度 |
|---|------|----------|--------|
| 1 | 进程映射了已被替换/删除的库或可执行文件 | 读 `/proc/<pid>/maps`（+ `/proc/<pid>/exe` 链接），比对包文件清单中路径是否出现 `(deleted)` 或 inode 与磁盘不一致 | 高（直接证据） |
| 2 | 官方工具给出的重启清单 | `needrestart -b`（Debian/Ubuntu，可选）、`dnf needs-restarting`（RHEL 系，可选） | 高（存在则采信） |
| 3 | 服务启动早于包升级时刻 | 进程启动时间 vs 包安装时间（来自包管理器日志的 `install` 记录） | 中（仅作辅助，见 6.3） |
| 4 | 包声明的服务单元 | `dpkg` 的 `/usr/share/doc/*/changelog` 或 `systemd` 单元文件 `After=` 关系 | 低（仅用于候选集） |

### 6.3 综合规则

```
若 证据1 命中                       → ServiceRestart{Confidence: CONFIRMED}
否则若 证据2 明确列出该服务          → ServiceRestart{Confidence: CONFIRMED}
否则若 证据3 成立 且 证据4 命中      → ServiceRestart{Confidence: LIKELY}
否则若 证据3 与 证据4 无法同时成立   → ServiceRestart{Confidence: UNKNOWN}
```

- `UNKNOWN` 的语义是**不声称安全也不声称需要重启**，报告中单独列出「未能确认」区块，不进入「待重启服务」计数。
- 证据 3 单独成立时**不得**输出 `CONFIRMED`；只能 `LIKELY`，且报告中标注「基于时间推断，建议人工确认」。
- 工具不可用（非 Debian/RHEL、无 root 读 `/proc`）时，证据 1/2 均无法采集，结果为 `UNKNOWN`，不是 `NONE`。
- 主机级 `RebootState` 使用内核包判定：运行内核版本 != 已安装最高内核包版本 → `REQUIRED`；读不到已安装内核清单 → `UNKNOWN`。此项与版本比较强相关，不依赖时间。

自动修复永远不重启服务、不重启主机。`RuntimeState` 只影响报告与提示文案。

---

## 7. 修复路径与安全闸门

### 7.1 包管理器能力矩阵 `[修订 5]`

| 管理器 | 变更集预演方式 | 可靠性 | 首期自动修复 |
|--------|----------------|--------|--------------|
| dpkg/apt | `apt-get install --dry-run --no-install-recommends <pkg>=<ver>`，解析 `Inst/Conf/Remv` 行 | 高 | 开放（Debian 12/13、Ubuntu 22.04/24.04，待实机验证） |
| rpm/dnf | `dnf --assumeno upgrade <pkg>-<evr>`，输出事务表；`--downloadonly` 预取 | 高 | 开放（Amazon Linux 2023，待实机验证） |
| rpm/yum | `yum --assumeno update`；AL2 用 | 中 | **不开放**（AL2 已 EOL，见 §9） |
| zypper | `zypper --non-interactive --dry-run update <pkg>` | 中 | 暂不开放 |
| apk | `apk add --simulate --no-cache <pkg>=<ver>` | 中 | 暂不开放（待验证） |
| pacman | `pacman -Sp` 只打印 URL，**不含依赖闭包与事务顺序**；`pacman -S --print` 亦不提供可校验的变更集 | **低** | **不开放** |

`[修订 5]` 结论：`pacman -Sp` 输出的是下载 URL 列表，无法证明「本次事务将安装/升级/删除哪些包、以何顺序、是否触发 `-Rdd` 级别的替换」。Arch 属于滚动发行版，仓库内不存在「固定版本」概念（旧版本被立即移出镜像），因此**既无法保证可复现的修复版本，也无法保证变更集边界**。v2.0 对 Arch 仅提供：资产识别、CVE 检测（Arch 追踪器数据）、人工修复建议（给出 `pacman -Syu` 提示与受影响包清单）。`linux-cve plan/fix` 在 Arch 上直接返回 `UNSUPPORTED` + 退出码 4，不生成任何可执行计划。

判定该能力矩阵的代码位置：`internal/package_manager/<mgr>/capabilities.go`，`SupportsDryRun()`、`SupportsPinnedVersion()`、`SupportsAutoFix()` 三个布尔必须逐项有测试覆盖，且 `SupportsAutoFix()` 为 false 时 planner 拒绝出计划（而不是运行时才发现）。

### 7.2 安全闸门（plan → fix 的强制检查）

按顺序执行，任一失败即 `BLOCKED` 并终止：

1. **状态复核**：重跑该 CVE 的匹配，确认仍为 `VULNERABLE + FIX_AVAILABLE`。
2. **资产快照一致性**：planner 记录的 inventory 哈希与 fix 执行前重采的哈希一致；不一致则要求重新扫描（防止扫描结果过期）。
3. **固定版本可达**：候选版本存在于当前已启用仓库（不新增源、不启用新 repo、不刷新元数据以外的操作）。
4. **变更集白名单**：解析预演结果，仅允许 `upgrade` 目标包本身及其**强依赖**；出现以下任一即拒绝：
   - 无关包升级数 > `max_collateral_packages`（默认 5，可配置）
   - 任何 `remove`（非替换）、`downgrade`
   - 任何来自未在白名单中的仓库的包
   - 包管理器建议的 transaction 中含内核包而目标不是内核 CVE
5. **锁检测**：`/var/lib/dpkg/lock-frontend`、`/var/lib/rpm/.rpm.lock`、`/var/cache/zypp`、`/lib/apk/db/lock`、`/var/lib/pacman/db.lck` 存在且被占用 → 拒绝并提示。
6. **权限**：非 root 直接 `ExitPermission`，不做部分执行。
7. **确认**：交互确认或显式 `--yes`；`--yes` 仅在全部闸门通过后生效。

执行后：重新采集资产 → 重跑匹配 → 输出 `before/after` 对比。**「包安装成功」不等于「漏洞修复」**，唯一的修复成功判据是复检后 `VulnState == FIXED`（或 `NOT_AFFECTED`）。

---

## 8. 模块划分与 Go 布局

```
cmd/linux-cve/            入口，仅做参数解析与退出码映射
internal/
  app/                    子命令装配、依赖注入、交互流程
  config/                 配置加载（TOML，flag > env > file > default）
  exitcode/               统一退出码
  apperr/                 错误类型与退出码映射
  logging/                slog 封装
  domain/                 领域模型（本阶段核心产出）
  database/               SQLite 打开、PRAGMA、迁移执行器
  database/migrations/    内嵌 SQL 迁移
  inventory/              [阶段2] 资产采集
  version/                [阶段2] dpkg/rpm/apk/pacman 版本比较
  feed/                   [阶段3] 情报源客户端与信任分级
  matcher/                [阶段3] 匹配与状态计算
  planner/                [阶段5] 计划生成与闸门
  remediation/            [阶段5] 执行器
  package_manager/        [阶段5] 逐管理器适配
  report/                 [阶段6] TXT/JSON
  integrity/              [阶段8] 签名与校验
adapters/                 发行版适配（Go 代码，不是 shell）
```

依赖方向：`app → (planner|remediation|matcher|report|inventory) → domain`；`feed → domain + database`；`domain` 不 import 任何内部包（零依赖）。此约束用 `go vet` 之外的检查保证：`internal/domain` 只允许 import 标准库（Phase 1 测试断言 import 图）。

---

## 9. 生命周期与支持范围 `[修订 6]`

| 发行版 | 状态 | 检测 | 修复版本查询 | 自动修复 |
|--------|------|------|--------------|----------|
| Debian 12 (bookworm) | 支持中 | ✅ | ✅ | 首期开放（待实机验证） |
| Debian 13 (trixie) | 支持中 | ✅ | ✅ | 首期开放（待实机验证） |
| Ubuntu 22.04 / 24.04 | 支持中 | ✅ | ✅ | 首期开放（待实机验证） |
| Amazon Linux 2023 | 支持中 | ✅ | ✅ | 首期开放（待实机验证） |
| Amazon Linux 2 | **EOL 2026-06-30** | ✅ Legacy | ⚠️ 尽力 | **关闭** |
| RHEL 8/9 | 支持中 | ✅ | ✅ | 后续 |
| Rocky / Alma / Oracle | 支持中 | ✅ | ✅ | 后续 |
| SUSE / openSUSE | 支持中 | ✅ | ✅ | 后续 |
| Alpine | 支持中 | ✅ | ⚠️ 部分 | 后续 |
| Arch | 滚动 | ✅ | ⚠️ 仅当前 | **不开放** |
| Fedora | 支持中 | ✅ | ✅ | 后续 |
| CloudLinux | 支持中 | ⚠️ | ⚠️ | 不开放 |

`[修订 6]` Amazon Linux 2：

- AL2 已于 **2026-06-30** 结束标准支持，进入维护期（仅关键安全修复，且 AWS 不再保证常规更新节奏）。
- 定位：**Legacy 兼容范围**，提供检测与报告，**不纳入首期自动修复**。
- 实现：`distro_releases.lifecycle_state = 'legacy'`；planner 与 fix 对 `legacy` 一律返回 `UNSUPPORTED`（退出码 4），报告中标注「该系统已过支持期，建议规划迁移」。
- 检测仍开放，因为存量 AL2 主机数量大，能看清漏洞比看不到更有价值；但不得暗示可通过打补丁长期维持。

---

## 10. 情报数据验证状态 `[修订 7]`

阶段 0 的探测只覆盖 **CVE-2026-98432 单点**，且部分来源只验证了「URL 可达 + 结构存在」，未验证「动态引擎可持续解析」。据实记录：

| 来源 | 阶段 0 验证内容 | 状态 | Phase 3 待补 |
|------|-----------------|------|--------------|
| Debian Tracker JSON | 全量 90MB 拉取成功，`linux` 条目含目标 CVE 与 `fixed_version` | 结构已验证 | 增量更新、pocket 语义、`not-affected` 判定 |
| Ubuntu OVAL (noble) | 12MB 拉取成功，含目标 CVE 的二进制包定义 | 结构已验证 | 22.04 OVAL、USN↔CVE 关联、EOL release 处理 |
| Red Hat Security API | 返回 55 条 `affected_release`，含 NEVRA | 结构已验证 | 分页与全量遍历、`package_state` 语义 |
| Red Hat OVAL RHEL9 | 拉取成功，含目标 CVE | 结构已验证 | 多 release、stream 区分 |
| SUSE CSAF | `provider-metadata.json` 与 2026 目录可访问，`.asc` 签名文件存在 | **签名链未验证** | 验签实现、产品树到包的映射 |
| Alpine secdb | `main.json` 解析成功，`packages[].secfixes` 结构确认；**目标 CVE 未收录** | 结构已验证 | 判定「未收录 ≠ 不受影响」 |
| Arch 追踪器 | `issues.json` 解析成功；**目标 CVE 未收录** | 结构已验证 | AVG 字段、`Fixed` 状态语义 |
| AL2023 updateinfo | 镜像 `repomd.xml` 含 `updateinfo`，`primary` 可下载 | 结构已验证 | 全量 updateinfo 解析、CVE→advisory 映射 |
| **AL2 updateinfo** | **仅验证 `mirror.list` 可访问，未解析 updateinfo** | **未验证** | 完整验证；在此之前 AL2 修复版本查询标记 `unverified` |
| ALAS CVE 页面 | 重定向行为已记录 | 未验证 | HTML 解析稳定性、替代 JSON 入口 |
| NVD 2.0 API | 单 CVE 查询成功 | 结构已验证 | 限速策略、增量窗口 |

强制规则：

- AL2 的修复版本查询在完成 updateinfo 验证前，`RemediationState` 最高只能到 `UNKNOWN`，且 AL2 本身已关闭自动修复，双重约束。
- 任何来源「未收录某 CVE」只能推出 `UNKNOWN`，**不得**推出 `NOT_AFFECTED`。`NOT_AFFECTED` 必须来自官方显式声明。
- 每条 finding 的 `Evidence[]` 携带 `SignatureStatus`（verified/failed/missing/not-applicable/unverified）与 `IntegrityStatus`（verified/failed/unchecked）两个独立字段，分别记录该来源的密码学签名验证结果与内容哈希比对结果，报告中原样呈现，禁止合并。

---

## 11. 数据库与迁移

- 引擎：SQLite（`modernc.org/sqlite` v1.62.0，纯 Go，无 cgo，便于交叉编译 amd64/arm64）。
- PRAGMA：`journal_mode=WAL`、`foreign_keys=ON`、`busy_timeout=5000`、`synchronous=NORMAL`。
- 迁移：内嵌 SQL（`embed.FS`），`schema_migrations(version, name, checksum, applied_at)`；启动时校验已应用迁移的 checksum，不一致即拒绝启动（防止手工改库）。
- 只允许向前迁移；发现库版本高于二进制版本时拒绝启动（防止旧二进制写坏新库）。
- 唯一索引设计见 `docs/data-model.md` 第 4 章。

---

## 12. 风险清单

| # | 风险 | 影响 | 缓解 |
|---|------|------|------|
| R1 | 官方数据源改结构/下线 | 检测失效 | 每源独立适配器 + 解析失败即 `UNKNOWN` + CI 每日连通性探测 |
| R2 | Debian 系源码包桥接失败 | 漏报 | 桥接失败落 `UNKNOWN` 并在报告单列；`Source` 字段缺失时不猜测 |
| R3 | 预演结果与实际事务不一致 | 变更超出预期 | 执行后再比一次实际变更集，不一致立即停止后续批次 |
| R4 | 仓库元数据陈旧 | 误判「无修复」 | 区分 `FIX_PENDING_MIRROR`；修复前检查 `apt-cache policy` 候选版本 |
| R5 | 时间证据误判待重启 | 误导运维 | 见第 6 章，时间仅作 `LIKELY` |
| R6 | 大版本升级被误纳入 | 业务中断 | 闸门 4 变更集白名单 + `max_collateral_packages` |
| R7 | 无 Linux 实机验证 | 自动修复不可信 | 首期自动修复仅对通过实机验证的发行版开放；未验证即关闭 |
| R8 | SQLite 并发写 | 数据损坏 | 单写者 + WAL + busy_timeout；feed 更新用独立事务批量提交 |

---

## 13. 阶段 1 交付边界

本阶段只交付：`go.mod`、CLI 分发、配置、日志、错误与退出码、SQLite 打开与迁移、领域模型、基础单测。

不实现：资产采集、版本比较、情报抓取、匹配、计划、执行、报告。这些包在阶段 2 起按模块逐个落地，接口在 `internal/domain` 中先定型。
