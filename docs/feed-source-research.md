# 漏洞情报数据源核验报告（阶段 3.0.1 冻结版）

- 版本：3.0.1-frozen
- 状态：只读调查，端点与格式均重新核验（2026-11-18/19）
- 依赖：阶段 0 调查报告（`audit/phase0-data-sources.md`）、阶段 3.0 初版设计

> 本报告以阶段 0 调查报告为基线，逐源复核端点与格式变化，并补齐
> Red Hat / SUSE / Debian 的签名、许可与增量机制细节。**不假定历史接口未变。**

---

## 1. 六大官方数据源最终策略

| 源 | 主数据源（判定依据） | 辅助/交叉验证 | 兼容保留 | 更新机制 | 签名 | 许可 |
|----|---------------------|--------------|----------|----------|------|------|
| Debian | Security Tracker JSON | DSA / DLA 公告（RSS 短/长版） | 无 | SHA256 比对（无 ETag） | 无 | 无正式许可，归属 Debian Security Team |
| Ubuntu | OVAL（`com.ubuntu.<release>.cve.oval.xml.bz2`） | USN 公告 | 无 | ETag / Last-Modified | 无 | 未确认，待调查 |
| Red Hat | **CSAF Advisory + per-CVE VEX** | OSV（经 OSV.dev） | OVAL v2（维护模式） | 按年份目录 + RSS（近 3 天） | **GPG（.asc）** | CC-BY-4.0 |
| SUSE | **CSAF Advisory + CSAF VEX** | 无 | OVAL（备用） | `index.txt` + `changes.csv` + `deletions.csv` | **GPG（.asc）** | CC-BY-4.0 |
| Alpine | secdb（`main.json` + `community.json`） | 无 | 无 | `last-update` 时间戳 | 无 | 未确认 |
| Arch | Security Tracker `all.json` | 无 | 无 | SHA256 比对 | 无 | 未确认 |

---

## 2. Red Hat 数据源策略修订 `[关键变更]`

### 2.1 官方弃用声明（已核实）

Red Hat OVAL v2 弃用公告（`access.redhat.com/OVAL_v2_deprecation_announcement`）与 RHEL 10 发行说明明确：

- **OVAL/DS v2 已进入维护模式**，仅保留 RHEL 8/9 现有流至维护期结束，之后归档。
- **RHEL 10 及后续不再发布 OVAL v2**（RHEL 10 发行说明：`CVE OVALv2 feed 不再提供`）。
- 官方明确要求客户与扫描厂商改用 **CSAF 与 VEX**。
- OVAL v2 不接收新特性，仅限关键 bug 修复。

### 2.2 新数据源优先级

| 优先级 | 数据源 | 端点（已核验） | 用途 |
|--------|--------|---------------|------|
| 1（主） | CSAF Advisory | `security.access.redhat.com/data/csaf/v2/advisories/<year>/rhsa-<year>_<seq>.json` | 机器可读公告摄入 |
| 2（主） | per-CVE VEX | `security.access.redhat.com/data/csaf/v2/vex/<year>/cve-<YYYY>-<NNNN>.json` | 判定「某 CVE 在某产品是否已修 / 未修 / 不予修复」 |
| 3（辅助） | OSV | 经 **OSV.dev**（Red Hat 官方要求从 OSV.dev 消费，不直接拉其自有 URL `security.access.redhat.com/data/osv/`） | 跨生态归一交叉验证 |
| 4（兼容） | OVAL v2 | `security.access.redhat.com/data/oval/v2/` | 遗留扫描器兼容，**不用于新功能** |

### 2.3 数据结构

- **CSAF Advisory** 命名：`rhsa-YYYY_NNNN.json`（另有 `rhba`/`rhea` 缺陷/增强公告）。每个 `.json` 配 `.json.asc`（GPG 签名，801 字节）与 `.json.sha256`。
- **per-CVE VEX** 命名：`cve-YYYY-NNNN.json`（编号 4/5/6 位不定）。VEX 含 `product_status`（`known_affected` / `known_not_affected` / `fixed` / `under_investigation` 等状态桶）+ `remediations` + `threats`，**同时含 fixed 与 unfixed（含 will-not-fix）产品**，比纯修复清单信息更全。
- **OSV** 按公告编号 `rhsa-YYYY:NNNN.json` 组织，无增量清单、无签名文件（Red Hat 自己的 OSV 目录无 `.asc`）。
- **repository-to-cpe.json**（`data/meta/v1/repository-to-cpe.json`）把仓库相对 URL 映射到 CPE，用于把 OVAL/CSAF 数据匹配到已安装 RPM。

### 2.4 签名与信任锚（已核实）

`https://security.access.redhat.com/data/csaf/v2/provider-metadata.json`（CSAF 2.0 标准信任锚）实测内容：

```json
{
  "canonical_url": "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json",
  "metadata_version": "2.0",
  "publisher": {
    "category": "vendor",
    "name": "Red Hat Product Security",
    "namespace": "https://www.redhat.com",
    "issuing_authority": "Red Hat Product Security is responsible for vulnerability handling across all Red Hat products and services.",
    "contact_details": "secalert@redhat.com"
  },
  "role": "csaf_trusted_provider",
  "list_on_CSAF_aggregators": true,
  "mirror_on_CSAF_aggregators": true,
  "last_updated": "2024-07-10T14:00:00.0Z",
  "public_openpgp_keys": [
    {
      "fingerprint": "77E79ABE93673533ED09EBE2DCE3823597F5EAC4",
      "url": "https://security.access.redhat.com/data/97f5eac4.txt"
    }
  ],
  "distributions": [
    { "directory_url": "https://security.access.redhat.com/data/csaf/v2/advisories/" },
    { "directory_url": "https://security.access.redhat.com/data/csaf/v2/vex/" }
  ]
}
```

**结论：Red Hat 是 A 级签名源**。信任锚 = `provider-metadata.json` 内声明的 PGP 公钥指纹
`77E79ABE93673533ED09EBE2DCE3823597F5EAC4`，公钥下载自 `security.access.redhat.com/data/97f5eac4.txt`。
每个 CSAF/VEX 文件配 `.asc` 分离签名 + `.sha256` 校验和。

> 修正：阶段 3.0 初版把 Red Hat 列为 B 级（无签名）是**错误**的。实测 Red Hat CSAF/VEX
> 提供完整 GPG 签名 + SHA256 + CSAF 信任锚，应升为 A 级。

### 2.5 产品流与 EUS/AUS/TUS

- RHEL 8/9 存在 EUS（Extended Update Support）、AUS（Advanced Update Support）、TUS（Telco Update Support）等延长支持流，与标准流是**不同产品记录**。
- VEX 的 `product_tree` 按 `product_id`（含流后缀）区分；判定时必须用 `subscription-manager release --show` 取得的本机 pinned minor release 对应到正确产品流，不能仅按大版本 `8`/`9` 匹配。
- 未订阅延长支持流的 RHEL 8/9 主机，其 EUS/AUS/TUS 修复包不可用，`RemediationState` 应落 `BLOCKED` 而非 `FIX_AVAILABLE`。

### 2.6 许可

Red Hat 安全数据页明确：所有数据资源及 Security Data API 的替代表示，均采用
**CC-BY 4.0**；分发或修改版本时必须**归属 Red Hat 并提供原始链接**。

---

## 3. SUSE 数据源补充

### 3.1 端点（已核验）

| 资源 | 端点 | 说明 |
|------|------|------|
| CSAF Advisory 目录 | `ftp.suse.com/pub/projects/security/csaf/<year>/` | 按年份，2012–2026 |
| CSAF VEX 目录 | `ftp.suse.com/pub/projects/security/csaf-vex/<year>/` | **独立 VEX 目录**（2023–2026） |
| 全量索引 | `csaf/index.txt`（1MB）、`csaf-vex/index.txt` | 相对路径清单 |
| 变更清单 | `changes.csv`（2MB，累计 4.5 万行）、`deletions.csv` | 两列：`"相对路径","ISO8601时间戳"` |
| 归档包 | `csaf.tar.bz2` / `csaf-vex.tar.bz2`（各配 `.asc` + `.sha256`） | 全量一次性下载 |
| 许可 | `csaf/LICENSE` | CC-BY-4.0 |
| 公钥 | `security/keys/security-automation.asc` | 「SUSE Security Automation Key」 |

### 3.2 公告类型（前缀）

`suse-su`（SUSE 安全更新）、`opensuse-su`（openSUSE 安全更新）、`suse-ru`/`opensuse-ru`（推荐更新）、
`suse-fu`/`opensuse-fu`（功能更新）、`essa`（SUSE Security Advisory）、`esba`/`esea`、`rhsa`/`rhba`（第三方镜像）。
判定只取安全类：`suse-su` / `opensuse-su` / `essa`。

### 3.3 签名与信任锚

- 每个 `.json` 配 `.json.asc`（GPG 分离签名）+ `.json.sha256` + `.json.sha512`。
- 公钥：`security-automation.asc`（PGP 块，描述「SUSE Security Automation Key (only for automation data) <security@suse.de>」）。
- SUSE 未提供 CSAF 2.0 的 `provider-metadata.json`（根目录探测无），信任锚为**官方目录内声明的公钥文件**，需在实现时固化指纹并检测轮换。

### 3.4 增量更新设计

- `changes.csv` / `deletions.csv` 是**累计全量变更历史**（非增量），需按上次成功同步时间戳过滤出新增/变更项。
- `deletions.csv` 记录被撤回/删除的公告：**不物理删除历史证据**，而是把对应 advisory 标记为 `retracted`，保留原始记录与撤回时间，更新当前有效状态。
- `index.txt` 用于**完整索引重建**：当本地索引与远端 index 不一致（如进程崩溃、磁盘损坏）时全量重建。

### 3.5 许可

`csaf/LICENSE` 原文：「The SUSE cVRF data is provided by SUSE under the Creative Commons license,
with Attribution use: CC-BY-4.0」（2021-05-12 从 CC-BY-NC-4.0 变更）。分发需归属 SUSE。

---

## 4. Debian 数据源补充

### 4.1 三层数据关系

Debian Security Tracker JSON **不等于完整 DSA/DLA 公告库**。实际是三层：

1. **Security Tracker JSON**（`security-tracker.debian.org/tracker/data/json`，~90MB）：CVE → 源码包 → release → `status` / `fixed_version` / `repositories`。是判定依据主体。
2. **DSA**（Debian Security Advisories，stable 安全公告）：RSS 短/长版（`debian.org/security/dsa` / `dsa-long`）。
3. **DLA**（Debian LTS Security Advisories，LTS 安全公告）：同上，LTS 通道。

### 4.2 关联关系

```
CVE → 源码包 → Debian release → status(resolved/open/undetermined) → fixed_version → DSA/DLA 编号
```

- Tracker JSON 中 `status=resolved` + `fixed_version` 提供修复版本；DSA/DLA 编号通过
  Tracker 的 `references` / `advisories` 字段（若导出含）或 DSA/DLA RSS 反查关联。
- **同一 CVE 出现在多个 DSA/DLA 公告中，不产生重复漏洞记录**：以 `(source_id, advisory_id, cve_id)` 唯一键去重，advisory_id 采用「CVE+源码包」合成的确定性 UID，DSA/DLA 编号作为 `references` 附加。

### 4.3 许可与再分发（未确认，禁止默认打包）

- Debian Security Tracker 数据**无正式许可证条款**；数据文件的实际许可声明在
  `security-tracker` Git 仓库（Salsa）内，是权威来源。
- 实用立场：复用/再分发/商用被普遍接受，但需**归属 Debian Security Team**；CVE 描述版权属 CVE Program 而非 Debian。
- 2026-11 邮件列表（`debian-security-tracker`）有厂商正式询问「商业扫描器可否再分发 Tracker 数据」，
  证明**官方尚未给出明确授权答复**。
- **结论**：在授权正式确认前，**不将 Debian 原始/派生数据打包进公开发布资产**；
  运行期按需拉取（fetch-on-demand），缓存于本机，报告逐条保留来源 URL 与归属声明。
- 拉取频率：无公开限流，但 Tracker 由志愿者维护，**至多每日一次**，优先条件请求（`If-None-Match`），避免反复下载 90MB 全量。

---

## 5. 覆盖范围：COVERED / PARTIAL / UNKNOWN

六大官方数据源**只覆盖官方发行版仓库中的系统软件包**，不代表所有 Linux 软件。

| 软件来源 | 覆盖状态 | 判定依据 |
|----------|----------|----------|
| 官方发行版仓库（含 backports / security 通道） | **COVERED** | 官方公告的源码包/二进制包 + 官方固定版本 |
| 官方发布但本机仓库未同步的修复包 | **COVERED（检测）/ PARTIAL（修复）** | 判定用官方数据；修复受本机仓库同步状态约束 |
| 第三方软件仓库（EPEL、第三方 vendor repo） | **PARTIAL** | 仅在发行版官方数据显式覆盖该仓库时判定，否则 UNKNOWN |
| 用户手动安装的 `.deb`/`.rpm` | **PARTIAL** | 包名/版本可采集，但无官方公告对应 → 落 UNKNOWN |
| 自行编译软件（`make install`、`/usr/local`） | **UNKNOWN** | 不在包管理器清单内，无法采集 → 不参与判定 |
| 容器内软件（非宿主机包管理器） | **UNKNOWN** | v2.0 首期不扫描容器镜像内部，明确排除 |
| Python pip / Node.js npm / Java Maven / Go Modules 等应用依赖 | **UNKNOWN（排除）** | v2.0 首期不纳入，见总体边界 |

**硬规则**：

- **没有官方公告记录 ≠ 安全**。官方数据源未收录的 CVE 或包，判定为 `UNKNOWN`，绝不判 `NOT_AFFECTED`。
- `NOT_AFFECTED` 仅来自显式 `not-affected` / `known_not_affected` / `product_status.fixed` 等官方声明。
- NVD / CVE.org 作为**通用 CVE 元数据补充**（描述、CVSS、参考链接），**不得**用其通用 CPE 或上游版本范围替代发行版官方回移补丁证据。

---

## 6. 数据许可与归属汇总

| 源 | 许可 | 归属要求 | 是否确认可再分发 |
|----|------|----------|------------------|
| Red Hat | CC-BY-4.0 | 归属 Red Hat + 原始链接 | ✅ 是 |
| SUSE | CC-BY-4.0 | 归属 SUSE | ✅ 是 |
| Debian | 无正式许可（见 §4.3） | 归属 Debian Security Team | ⚠️ 未确认 |
| Ubuntu | 未确认 | 待调查 | ⚠️ 未确认 |
| Alpine | 未确认 | 待调查 | ⚠️ 未确认 |
| Arch | 未确认 | 待调查 | ⚠️ 未确认 |

> 未确认再分发授权的源，运行期按需拉取 + 本机缓存 + 报告保留来源与归属；
> **不打包进公开发布资产**。阶段 3.1 需补齐 Ubuntu/Alpine/Arch 的许可调查。

---

## 7. 信任分级修正（相对阶段 3.0 初版）

阶段 3.0 初版错误地把 Red Hat 列为 B 级（无签名）。修正后的 A 级签名源为**两个**：

| 级别 | 定义 | 来源 |
|------|------|------|
| A | 官方提供密码学签名（GPG `.asc`）+ 内容哈希 + 信任锚 | **Red Hat CSAF/VEX**、**SUSE CSAF/VEX** |
| B | 官方 HTTPS 发布，无独立签名，仅 TLS + SHA256 记录 | Debian Tracker、Ubuntu OVAL、Alpine secdb、Arch 追踪器 |
| C | 元数据（描述/CVSS），不参与判定 | NVD、CVE.org |

> SHA256 与「同源校验清单」都不等于数字签名。B 级源只能做到「防传输损坏/缓存污染」，
> 不能防上游被入侵。此点在报告与 `feed status` 中如实呈现，不夸大。
