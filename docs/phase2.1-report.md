# 阶段 2.1 收尾报告

> 阶段：2.1（阶段 2 收尾 + 阶段 3.0 准备）
> 分支：`feat/v2.0.0`
> 起始 HEAD：`1ab13bf`（阶段 2 交付后）
> 结束 HEAD：见 §5 提交记录

---

## 1. 本轮完成内容

| # | 任务 | 状态 |
|---|------|------|
| 1 | CLI JSON 输出规范化（snake_case + schema_version + 独立 DTO） | ✅ PASS |
| 2 | 独立审查证据补充 | ✅ PASS（1 项 P1 修复） |
| 3 | 原生版本比较差分测试准备（CI 容器） | ✅ PASS（本地 BLOCKED，CI 待跑） |
| 4 | 阶段 2 最终验收 | ✅ PASS（140 测试全绿） |
| 5 | 阶段 3.0 只读调查与技术设计 | ✅ PASS（`docs/phase3.0-design.md`） |

---

## 2. CLI JSON 输出规范化

**问题**：`inventory --json` 原本直接序列化 domain 模型，使用 Go 默认 PascalCase 字段名（`DistroID`/`Packages`/`Ref`），非稳定协议。

**修复**：

- 新增独立 CLI DTO（`internal/app/inventory_dto.go`），**不修改 domain 模型的 JSON 语义**。
- 字段统一 snake_case（`distro_id` → `distro.id`、`source_name`、`origin_channel`、`entry_hash` 等）。
- 增加 `schema_version: 1`，支持可演进。
- 空数组输出 `[]`（非 null）；空字符串显式 `""`；时间统一 UTC RFC3339；零值时间输出空串（不伪造）。
- 输出顺序稳定（struct 声明顺序）。

**测试**（经真实 Main 入口 `mainWithEnv`，仅注入采集器工厂，不复制退出码/输出逻辑）：JSON 合法性、字段命名（snake_case 无 PascalCase）、空字段、空数组、稳定输出、时间 UTC、schema_version。

## 3. 独立审查

**审查方式**：使用独立 reviewer 子代理（`cavecrew-reviewer`）审查 `internal/database` / `internal/app`；`internal/version` / `internal/inventory` 因 reviewer 子代理上游流错误未产出，由主上下文自审补充（**如实标注**：database/CLI = 独立 reviewer，version/inventory = 自审）。

**发现并修复**：

- **[P1]** `inventory --json --save` 组合时保存状态行 `saved inventory id=N` 写入 stdout，污染 JSON，下游无法解析（`internal/app/inventory.go:65`）。
  - 修复：保存 ID 纳入 DTO `saved_inventory_id` 字段（仅 `--save` 有值），stdout 始终纯 JSON。
  - 补 `TestInventoryCommandJSONSave` 组合测试覆盖。

**version/inventory 自审结论**：`verrevcmp`（dpkg）、`rpmvercmp`（~ / ^ 语义）、apk tokenizer、pacman libalpm 怪癖均忠实移植；采集严格只读、SourceName/OriginChannel/内核映射证据规则严谨。无 P0/P1。

## 4. 原生版本比较差分测试

**现状**：本地 Windows 无 dpkg/rpm/apk/pacman/vercmp，**保持 BLOCKED**（未冒称通过）。

**交付**（可选差分测试，仅在 CI Linux 容器运行）：

- `tests/vercmp_probe.go`：Go 侧探测程序，调 `internal/version.Compare` 输出 `-1/0/1/ERR`。
- `tests/version_diff.sh`：归一化四种原生命令符号并与 Go 比较。
  - dpkg：`dpkg --compare-versions`
  - rpm：`rpm --eval "%{lua:print(rpm.vercmp(...))}"`（rpm ≥ 4.16）
  - apk：`apk version -t`
  - pacman：`vercmp`
- `tests/version_diff_cases.txt`：覆盖 epoch/前导零/字母数字/分隔符/预发布/边界值，`#DIFF` 标注跨算法语义差异用例。
- `.github/workflows/version-diff.yml`：四容器矩阵（debian:12 / fedora:latest / alpine:3.20 / archlinux:latest）。

## 5. 阶段 2 最终验收

| 验证项 | 结果 |
|--------|------|
| `go test ./... -count=1` | ✅ 140 个唯一测试全 PASS，0 FAIL（`go test -json` 精确统计） |
| `go test -race ./...` | ✅ 全绿 |
| `go vet ./...` | ✅ 通过 |
| `go build ./...` | ✅ 通过 |
| `gofmt -l` | ✅ 无未格式化文件 |
| Linux amd64 交叉编译 | ✅ 成功 |
| Linux arm64 交叉编译 | ✅ 成功 |
| Windows amd64 交叉编译 | ✅ 成功 |
| v1.3.2 原有 Bash 代码 | ✅ 零改动（仅新增 `tests/version_diff.sh`） |
| 分支 / 工作树 | ✅ `feat/v2.0.0`，工作树干净，未推送 |

## 6. 阶段 3.0 设计产出

详见 `docs/phase3.0-design.md`，包含：

1. 六大官方数据源最新核验报告（端点/格式/体量/更新频率/校验，均重新核验非假定）。
2. 统一 Advisory 数据模型（不丢失原始证据，raw_payload + raw_hash）。
3. Feed 增量更新机制（ETag/304、changes.csv、SHA256 比对、原子 swap、失败回滚、断网降级）。
4. 数据真实性分层（HTTPS ≠ SHA256 ≠ 签名 ≠ cosign，严格区分）。
5. SQLite 0003 迁移设计（findings 三维状态独立）。
6. CVE 匹配规则（源码/二进制映射、架构/发行版/release 隔离、回移、UNKNOWN 语义）。
7. 漏洞状态判定（三维独立，不合并）。
8. 数据源支持矩阵。
9. 测试策略（REAL vs SYNTHETIC 夹具）。
10. 风险清单。

**关键核验发现**：Red Hat 端点已从 `www.redhat.com` 迁移至 `security.access.redhat.com`；SUSE 提供 `changes.csv`/`deletions.csv` 增量清单；Alpine 有 `last-update` 分钟级时间戳；Arch `all.json` 为顶层数组。

## 7. 尚未解决的问题

1. 原生差分测试 C 级：本地 BLOCKED，需 CI Linux 容器跑（工作流已备好，未实际执行，不得标记通过）。
2. Linux 实机采集验证 D 级：未做（需阶段 4/5 的 VM）。
3. Red Hat PGP 签名端点与验证流程需在阶段 3 实现时进一步确认细节。

## 8. 阶段 3 开工建议

1. 先落地 `internal/feed` 下载/缓存层（ETag + SHA256 + 原子 swap）。
2. 解析器按「Alpine → Arch → Debian → Ubuntu → RedHat/SUSE」先易后难实现。
3. 每源完成即做真实小样本解析 + 匹配差分验证。
4. 情报库写入走 staging + 单事务 swap，先通过「下载/解析失败不破坏已有库」测试。
5. 阶段 3 只交付 `VulnState` 判定，不实现修复可行性（`RemediationState`/`RebootState` 仅建模）。
