# 数据源

六个官方情报源的实测结构、字段语义与解析取舍。所有数字取自 2026-11-24 在
Debian 13 测试机上的真实抓取与解析，不是文档摘抄。

## 总览

| 源 | ID | 信任级 | 发布形式 | 更新方式 |
| --- | --- | --- | --- | --- |
| Debian Security Tracker | `debian-tracker` | B | 单个 JSON（约 90MB） | 整份替换 |
| Ubuntu OVAL | `ubuntu-oval` | B | 每 codename 一个 bzip2 | 整份替换 |
| Alpine secdb | `alpine-secdb` | B | 每 release × 仓库一个 JSON | 整份替换 |
| Arch Security Tracker | `arch-tracker` | B | 单个 JSON | 整份替换 |
| Red Hat CSAF | `rhel-csaf` | A | 每份 RHSA 一个 JSON + `.asc` | 索引 + 增量 |
| SUSE CSAF | `suse-csaf` | A | 每份公告一个 JSON + `.asc` | 索引 + 增量 |

B 级 = 依赖 HTTPS 传输与哈希自校验；A 级 = 每份发布物都有厂商分离签名，
指纹固化在代码里。详见 [security-model.md](security-model.md)。

## Debian Security Tracker

端点：`https://security-tracker.debian.org/tracker/data/json`

结构是「源码包 → CVE → release」的三层对象，顶层键是**源码包**而不是 CVE，
所以解析按包推进，内存只需容纳一个包。

三条与直觉相反的实测事实：

1. **`fixed_version` 有 25,449 条是占位 `"0"`**（resolved 总数 259,254 的 8.8%），
   真实版本只在 `repositories` 里。这类记录只能弱判：本机不低于仓库当前版本
   判「已修复」，低于则 `UNKNOWN`，绝不当成「确认受影响」的证据。
2. **`status` 有三种**：`resolved`（已修复）、`open`（确认受影响、没有补丁）、
   `undetermined`（发布方尚未判定）。`open` 必须落库成
   「受影响 + 无修复版本」的空版本记录——丢掉它，这些包就变成「情报库无记录」，
   而事实是「有洞且无补丁」，结论正好说反。实测补回后修复记录从 197,151
   升到 222,161，受影响判定从 7,065 升到 10,230。
3. **`urgency` 多数是 `not yet assigned`**，映射为 `unknown` 严重度是诚实做法，
   不要为了好看硬套一个等级。

开发版 `sid` / `forky` / `experimental` 直接跳过：生产服务器不会运行它们，
而且会让 `distro_releases` 多出一批永远匹配不到的坐标。

## Ubuntu OVAL

端点：`https://security-metadata.canonical.com/oval/com.ubuntu.<codename>.cve.oval.xml.bz2`

按 codename（不是版本号）分文件。实测 noble：11.4MB bz2 → **270.8MB XML**，
37,612 条 definition、4,005 条 dpkginfo_test、2,767 object、1,514 state、
745,143 条 criterion。

引用链是 definition → criterion → test → object/state → constant_variable，
三个坑：

1. **只有 `operation="less than"` 的 evr 才是首次修复版本**。其它比较符
   （`greater than or equal` 等）表达的是「已经不受影响」，当成修复版本会把
   判定整体反过来。
2. **criterion 引用分三类**：包级 test（可解析出包名与版本）、环境条件
   test（实测 `uname_test` 60 条、`ind-def:variable_test` 236 条、`family_test` 1 条）、
   悬空引用（实测 298 个，上游数据缺失）。把环境条件当成包级引用会产出
   一堆不存在的包，把悬空引用当成格式错误会让 19,394/57,005 条记录被整批拒绝。
3. **解析不出包时仍要产出公告**，标 `VendorStatus=unresolved`。

实测结果：270.8MB XML、37,611 公告、48,617 修复、跳过 0。
经 `feed update ubuntu-oval --release noble` 全流程（下载 + 解压 + 解析 + 落库）20.0 秒。

## Alpine secdb

端点：`https://secdb.alpinelinux.org/v<release>/<repo>.json`

实测 v3.20 main 81KB / 266 包 / 2,966 条；community 132KB / 410 包 / 5,409 条。

- **366 条不是纯 CVE 条目**，其中 341 条形如 `"CVE-2021-27219 GHSL-2021-045"`，
  取首段即为合法 CVE；剩 25 条确实没有 CVE 编号，计入跳过。
- 空版本键表示「确认受影响、没有修复包」，必须落一条空版本记录，
  理由与 Debian 的 `open` 相同。
- 同一版本里可能重复列出同一 CVE（实测存在），不去重会产出两条相同记录。
- 多文件源要按文件分别算哈希做溯源，不能用联合摘要冒充单个文件的哈希。

实测：8,299 公告 / 8,344 修复 / 跳过 27；经 `feed update` 全流程 3.1 秒（含下载）。

## Arch Security Tracker

端点：`https://security.archlinux.org/issues/all.json`（`/all.json` 会 308 重定向过去，
旧地址现在返回 279 字节的 HTML 重定向页——直接固化最终地址）。

实测 898KB、2,444 条 AVG，status 四种：Fixed 2152 / Not affected 193 /
Vulnerable 84 / Unknown 15；52 条涉及多个包。

- 只有 `Fixed` 产出修复记录。
- `Not affected` 即使带 `fixed` 字段也只产出不受影响声明——照抄会凭空造出升级建议。
- `Unknown` 即使带 `fixed` 也不得当成结论。

实测：8,035 公告 / 7,401 修复 / 303 不受影响；经 `feed update` 全流程 1.8 秒。

## Red Hat CSAF

端点：`https://security.access.redhat.com/data/csaf/v2/advisories/changes.csv`
（清单 1.79MB，32,407 份公告），文档在 `advisories/<year>/rhsa-<year>_<n>.json`，
同目录有 `.asc`。信任锚是 `provider-metadata.json` 声明的指纹
`77E79ABE93673533ED09EBE2DCE3823597F5EAC4`。

**为什么用 advisories 而不是 vex**：实测单份 VEX 文档 16.8MB（把全部产品线塞进
`product_tree`），共 78,041 份，下载与存储都不现实；而扫描需要的「修复版本」
事实恰好来自 RHSA。

两个必须按真实结构实现的地方：

1. **产品树是「兄弟」结构**：带 CPE 的 `product_name`（发行版坐标的唯一来源）
   与 `architecture → product_version`（带 purl，包坐标）并列挂在 `vendor` 下，
   包**不是**产品名的子节点。按父子关系实现会得到「公告有、修复记录为零」——
   最容易被误读成「没漏洞」的形态。
2. **`product_status.fixed` 引用的是 relationship 的完整产品 ID**
   （`BaseOS-10.1.Z:tar-2:1.35-9.el10_1.x86_64`），不是包级 `product_id`。
   只认包级 ID 同样会导致零修复记录。

其它取舍：

- CPE 的 `9.6` 只取主版本 `9`：补丁流共用同一条支持线，按次版本登记会让
  9.4 的机器在 9.5 发布后掉进「未登记 release」。
- 一份公告把同一个包在 4~5 个架构各列一遍，版本一致时合并为 `any`
  （175 万行降到 85 万行）；版本随架构不同时保留各自架构。
- purl 里的 `epoch` 必须拼回版本号：rpm 比较里 epoch 优先级最高，
  丢了会把 `1:1.0` 与 `1.0` 判成相同。

实测（2026 年切片 10,409 份）：66,991 公告 / 850,931 修复 / 44,670 不受影响 / 失败 0。
入库前按唯一键（源 + 公告 + CVE + release + 渠道 + 包类型 + 包名 + 架构）去重，
实际落库 810,817 条修复记录与 26,327 条不受影响记录——差额来自去重，不是解析失败。
二次同步全部复用本地字节：新下载 0、复用 10,409、用时 3 分 1 秒。
存储代价：10,410 个文件、3.6GB。

## SUSE CSAF

端点：`https://ftp.suse.com/pub/projects/security/csaf/changes.csv`
（2.55MB，45,765 份公告），文档在 `<year>/opensuse-su-<...>.json`，
带 `.asc` 与 `.sha256`。

- **没有 `provider-metadata.json`**：指纹只能从官方公钥文件
  `keys/security-automation.asc` 现场计算后固化
  （`6B62473BD771517D41E684DFD4439E7EC133994D`）。
- **修复状态用 `product_status.recommended`**，不是 `fixed`。
  漏掉它，SUSE 的「已修复」会全部消失。
- **发行版坐标只能从产品名字符串解析**：`openSUSE Leap 16.0`、
  `SUSE Linux Enterprise Server 15 SP6`。「15 SP6」与「15.6」是同一版本，
  必须归一，否则同一台机器会命中两个 release 坐标。HPC / Real Time / Manager
  不在覆盖范围，解析不出就跳过，不猜。
- **文档含非 UTF-8 字节**（Latin-1 的乘号 `×`），严格 UTF-8 解码会整份失败；
  按替换字符处理即可，不应因此丢文档。
- **发行版只能从产品名解析，且 SLES 16 与 Leap 16 都是「16.0」**：两者必须靠产品名
  前缀分流，按版本文本匹配会把 SLES 的修复版本当成 Leap 的。
  实测入库分布：opensuse-leap 16.0 435,318 条、sles 16.0 198,615 条，互不污染。
- **主 feed 只有 `recommended`**：2026 切片 13,561 份文档的状态全是 `recommended`，
  没有 `known_affected` / `known_not_affected`。「不受影响」与「无修复方案」
  只存在于 `csaf-vex` 子目录，本期不接入，因此 SUSE 侧没有这两类结论。

实测（2026 年切片 13,561 份）：149,788 公告 / 965,304 修复 / 失败 0 / 11.5 分钟。
单份文档平均约 170KB，切片存储 2.3GB——比 RHEL 更省，但全量仍建议按年切。

## 通用防护

- 所有 JSON 解析先做深度与体积检查，避免深层嵌套打穿栈。
- 出错率超过阈值（小样本用绝对条数、大样本用比例）整批拒绝：
  半套情报比没有情报更危险，因为覆盖状态看起来仍然是 `COVERED`。
- 每条归一化记录都带 `artifact_sha256` + `raw_locator` + `parser_version`，
  可以回到发布方的原始字节与具体位置。
