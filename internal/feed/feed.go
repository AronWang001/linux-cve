// Package feed 负责漏洞情报源的获取、缓存与不可变存储。
//
// 设计约束见 docs/phase3.0-design.md §2–§4：
//   - 原始文件按 sha256 内容寻址保存为不可变 Artifact，落盘后永不改写；
//   - 归一化数据与原始证据分离，advisory 只存 Artifact 引用与原始定位；
//   - HTTPS 与 SHA256 都不等于数字签名，signature_status 与 integrity_status
//     必须分别记录，禁止合并成一个 "verified"。
package feed

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// 下载与解析护栏默认值（docs/phase3.0-design.md §3.5）。
// 这些上限存在的意义是：损坏或恶意的情报文件不能把库写坏，
// 也不能让进程耗尽内存。
const (
	// DefaultHTTPTimeout 是单次 HTTP 请求的整体超时，禁止无限等待。
	DefaultHTTPTimeout = 60 * time.Second

	// DefaultMaxBytes 是单次下载的体积上限；具体源可覆盖（Debian 约 90MB）。
	DefaultMaxBytes int64 = 64 << 20

	// DebianMaxBytes 是 Debian Tracker 全量 JSON 的上限。
	DebianMaxBytes int64 = 140 << 20

	// MaxExpandRatio 是解压比上限，超出判定 zip-bomb 并拒绝。
	//
	// 设计稿原定 8:1，实测不成立：Ubuntu OVAL noble 的
	// com.ubuntu.noble.cve.oval.xml.bz2 压缩 11.9MB、解压 284MB，比率 23.8:1。
	// 按 8:1 会把所有 Ubuntu 数据判成 zip-bomb。上调到 30 仍能拦住
	// 典型的 1000:1 压缩炸弹，同时放行真实数据。
	MaxExpandRatio = 30

	// MaxExpandedBytes 是解压后总体积上限。
	// 实测最大单源（Ubuntu OVAL noble）为 284MB，留一倍余量。
	MaxExpandedBytes int64 = 512 << 20

	// MaxJSONDepth 是 JSON 嵌套深度上限，防止深递归拖垮解析。
	MaxJSONDepth = 64

	// MaxRecordBytes 是单条记录的最大字节数。
	MaxRecordBytes int64 = 1 << 20

	// DefaultMaxErrorRate 是单批解析允许的异常记录比例，超出整批拒绝。
	DefaultMaxErrorRate = 0.20

	// DefaultRetries 是失败重试次数（不含首次尝试）。
	DefaultRetries = 2

	// DefaultRetryBase 是指数退避的基数。
	DefaultRetryBase = 500 * time.Millisecond
)

// Source 是静态数据源配置。
//
// 这里是「应然」配置（该源声称提供什么、信任等级多少），
// 每次抓取的「实然」结果记在 Artifact 的 SignatureStatus / IntegrityStatus 上。
type Source struct {
	ID            domain.SourceID
	Name          string
	Kind          string // tracker | oval | csaf | csaf-vex | secdb | api
	URL           string
	TrustLevel    domain.TrustLevel
	SignatureKind string // none | gpg | csaf
	PublicKeyFP   string // A 级源固化的 PGP 指纹；为空表示不校验签名
	ParserVersion string
	MaxBytes      int64

	// NeedRelease 表示该源按发行版 release 分文件（Ubuntu OVAL、Alpine secdb）。
	// 为 true 时 URL 含 %s 占位符，由调用方传入 release 标识。
	NeedRelease bool

	// Disabled 表示本期不接入该源（含原因），不得静默跳到「无漏洞」结论。
	Disabled       bool
	DisabledReason string
}

// Validate 校验源配置的完整性。
func (s Source) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("feed: 情报源缺少 ID")
	}
	if s.URL == "" {
		return fmt.Errorf("feed: 情报源 %s 缺少 URL", s.ID)
	}
	if !s.TrustLevel.Valid() {
		return fmt.Errorf("feed: 情报源 %s 的信任等级非法: %q", s.ID, s.TrustLevel)
	}
	if s.TrustLevel == domain.TrustLevelA && s.PublicKeyFP == "" {
		// A 级源必须固化指纹，否则无法发现密钥轮换。
		return fmt.Errorf("feed: A 级情报源 %s 缺少固化公钥指纹", s.ID)
	}
	if s.MaxBytes <= 0 {
		return fmt.Errorf("feed: 情报源 %s 的下载上限必须为正", s.ID)
	}
	return nil
}

// URLFor 按 release 展开 URL。非按 release 分文件的源忽略参数。
func (s Source) URLFor(release string) (string, error) {
	if !s.NeedRelease {
		return s.URL, nil
	}
	if release == "" {
		return "", fmt.Errorf("feed: 情报源 %s 需要 release 参数", s.ID)
	}
	if !strings.Contains(s.URL, "%s") {
		return "", fmt.Errorf("feed: 情报源 %s 声明按 release 分文件但 URL 没有占位符", s.ID)
	}
	return fmt.Sprintf(s.URL, release), nil
}

// Artifact 是不可变的原始情报文件，按内容哈希内容寻址。
//
// 同一个 Debian Tracker JSON 可能被数千条 advisory 引用，因此原文只存一份，
// advisory 侧只保存 SHA256 + 原始定位。
type Artifact struct {
	SHA256          string
	SourceID        domain.SourceID
	SizeBytes       int64
	DownloadURL     string
	FetchedAt       time.Time
	SignatureStatus domain.SignatureStatus
	IntegrityStatus domain.IntegrityStatus
	StoredPath      string

	// ETag / LastModified 是下一次条件请求的依据，属缓存验证信息，
	// 不是完整性证明。
	ETag         string
	LastModified string
}

// Validate 校验 Artifact 记录自洽。
func (a Artifact) Validate() error {
	if len(a.SHA256) != 64 {
		return fmt.Errorf("feed: artifact 哈希长度非法: %q", a.SHA256)
	}
	if _, err := hex.DecodeString(a.SHA256); err != nil {
		return fmt.Errorf("feed: artifact 哈希不是十六进制: %w", err)
	}
	if a.SourceID == "" {
		return fmt.Errorf("feed: artifact %s 缺少情报源", a.SHA256[:8])
	}
	if a.SizeBytes < 0 {
		return fmt.Errorf("feed: artifact %s 体积为负", a.SHA256[:8])
	}
	if !a.SignatureStatus.Valid() {
		return fmt.Errorf("feed: artifact %s 签名状态非法: %q", a.SHA256[:8], a.SignatureStatus)
	}
	if !a.IntegrityStatus.Valid() {
		return fmt.Errorf("feed: artifact %s 完整性状态非法: %q", a.SHA256[:8], a.IntegrityStatus)
	}
	return nil
}

// HashBytes 返回字节内容的 sha256 十六进制串。
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Snapshot 是一次成功同步的归一化结果集。
// 只有完整提交后才翻转 IsActive，崩溃不会留下半更新的可读快照。
type Snapshot struct {
	ID            string
	SourceID      domain.SourceID
	StartedAt     time.Time
	CompletedAt   time.Time
	IsActive      bool
	ContentHash   string
	ParserVersion string
	Artifacts     []string // 引用的 artifact sha256

	// Counts 是本次归一化产出的记录数，用于质量检查与报告。
	Advisories  int
	Fixes       int
	NotAffected int
}

// Coverage 描述某个源的覆盖判定，直接进入报告，不允许含糊。
type Coverage struct {
	SourceID domain.SourceID
	// State: COVERED / PARTIAL / UNKNOWN
	State      string
	Reason     string
	LastSyncAt time.Time
	Age        time.Duration
	Stale      bool
}

// 覆盖状态取值。
const (
	CoverageCovered = "COVERED"
	CoveragePartial = "PARTIAL"
	CoverageUnknown = "UNKNOWN"
)
