package feed

import (
	"context"
	"fmt"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// ParseInput 是一次解析的输入。
//
// Body 用于单文件源（Debian/Arch/单个 Red Hat 文档），
// Files 用于多文件源（Alpine main+community），键为仓库名。
type ParseInput struct {
	Source      Source
	ArtifactSHA string
	Body        []byte
	Files       map[string][]byte
	// Release 是该源对应的发行版 release（按 release 分文件的源必须给）。
	Release   string
	FetchedAt time.Time
	// Now 便于测试注入固定时间；为空时用 time.Now。
	Now func() time.Time
}

func (in ParseInput) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now()
}

// ReleaseRef 是解析过程中遇到的发行版坐标。
// 归一化时若该坐标未登记，会以 lifecycle=unknown 落库：
// 允许记录事实，但不因此认为它受支持。
type ReleaseRef struct {
	DistroID domain.DistroID
	Release  string
	Codename string
}

// ParseResult 是一次解析的归一化产物。
//
// 约定：解析器只做「原始证据 → 统一模型」的转换，
// 不判断漏洞状态，不查库，不猜缺失字段。
// 拿不准的记录进 Skipped 并留 Warning，不得默认成某个结论。
type ParseResult struct {
	Advisories  []domain.Advisory
	Fixes       []domain.AdvisoryFix
	NotAffected []domain.NotAffected
	Releases    []ReleaseRef

	// Skipped 是被跳过的异常记录数；Warnings 是去重后的前若干条原因。
	Skipped  int
	Warnings []string

	Guard GuardStats
}

// warn 追加一条警告，超过上限后只计数不再累积，避免日志被格式漂移刷爆。
func (r *ParseResult) warn(format string, args ...any) {
	const maxWarnings = 20
	if len(r.Warnings) >= maxWarnings {
		return
	}
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Parser 把一个数据源的原始字节解析为归一化记录。
type Parser interface {
	SourceID() domain.SourceID
	Version() string
	Parse(ctx context.Context, in ParseInput) (*ParseResult, error)
}

// ParserFor 返回某个源对应的解析器；尚未实现时返回 nil 与原因。
//
// 未实现的源必须明确报错，不能静默返回「零条记录」：
// 零条记录会被上游误读成「这个发行版没有漏洞」。
func ParserFor(id domain.SourceID) (Parser, string) {
	switch id {
	case domain.SourceDebianTracker:
		return DebianParser{}, ""
	default:
		return nil, "该情报源的解析器尚未实现"
	}
}
