package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// SourceID 是情报源稳定标识。
type SourceID string

const (
	SourceDebianTracker SourceID = "debian-tracker"
	SourceUbuntuOVAL    SourceID = "ubuntu-oval"
	SourceUbuntuUSN     SourceID = "ubuntu-usn"
	SourceRHELOVAL      SourceID = "rhel-oval"
	SourceRHELAPI       SourceID = "rhel-api"
	SourceRHELCSAF      SourceID = "rhel-csaf"
	SourceSUSECSAF      SourceID = "suse-csaf"
	SourceAlpineSecDB   SourceID = "alpine-secdb"
	SourceArchTracker   SourceID = "arch-tracker"
	SourceALAS          SourceID = "alas"
	SourceAL2023Update  SourceID = "al2023-updateinfo"
	SourceAL2Update     SourceID = "al2-updateinfo"
	SourceNVD           SourceID = "nvd"
	SourceCVEOrg        SourceID = "cveorg"
)

// TrustLevel 是情报源信任分级，见 docs/architecture.md §3。
//
//	A = 官方数据自带密码学签名
//	B = 官方 HTTPS 发布，仅 TLS + 内容哈希
//	C = 仅元数据，不参与受影响判定
type TrustLevel string

const (
	TrustLevelA TrustLevel = "A"
	TrustLevelB TrustLevel = "B"
	TrustLevelC TrustLevel = "C"
)

// Valid 判断信任等级是否合法。
func (t TrustLevel) Valid() bool {
	return t == TrustLevelA || t == TrustLevelB || t == TrustLevelC
}

// SourceValidation 是该情报源当前实际达到的验证程度。
// 与 TrustLevel 分开：等级是「应然」，验证程度是「实然」。
type SourceValidation string

const (
	ValidationVerified      SourceValidation = "verified"       // 已完成真实解析/验签验证
	ValidationStructureOnly SourceValidation = "structure-only" // 仅确认结构与可达性
	ValidationUnverified    SourceValidation = "unverified"     // 尚未验证
)

// Valid 判断验证程度取值是否合法。
func (v SourceValidation) Valid() bool {
	return v == ValidationVerified || v == ValidationStructureOnly || v == ValidationUnverified
}

// Advisory 是一条官方安全公告与某个 CVE 的关联记录。
type Advisory struct {
	UID            string
	SourceID       SourceID
	AdvisoryID     string // DSA-5810-1 / USN-9018-1 / RHSA-2026:93414 / SUSE-SU-2026:1234-1
	CVEID          CVEID
	Title          string
	Severity       Severity
	SeveritySource string
	IssuedAt       *time.Time
	UpdatedAt      *time.Time
	URL            string
	FetchedAt      time.Time
}

// AdvisoryUID 由内容派生，保证重复导入幂等，且不依赖插入顺序。
func AdvisoryUID(source SourceID, advisoryID string, cve CVEID) string {
	h := sha256.Sum256([]byte(string(source) + "|" + advisoryID + "|" + string(cve)))
	return hex.EncodeToString(h[:])[:16]
}

// Validate 校验公告必填项。
func (a Advisory) Validate() error {
	if a.SourceID == "" {
		return domainErr("公告缺少情报源")
	}
	if a.AdvisoryID == "" {
		return domainErr("公告缺少公告编号")
	}
	if !a.CVEID.Valid() {
		return domainErr("公告 %q 的 CVE 编号非法: %q", a.AdvisoryID, a.CVEID)
	}
	want := AdvisoryUID(a.SourceID, a.AdvisoryID, a.CVEID)
	if a.UID != "" && a.UID != want {
		return domainErr("公告 UID 与内容不一致: 期望 %s，实际 %s", want, a.UID)
	}
	return nil
}

// AdvisoryFix 是「某发行版某 release 某渠道中，某包在哪个版本修复了该 CVE」。
// 这是版本比较的唯一输入，字段缺失即无法判定。
type AdvisoryFix struct {
	AdvisoryUID  string
	SourceID     SourceID
	AdvisoryID   string
	CVEID        CVEID
	DistroID     DistroID
	Release      string
	Channel      string
	Ref          PackageRef // Kind 可为 source 或 binary
	FixedVersion string     // 原始字符串，逐字保留
	FixedAt      *time.Time
	EvidenceURL  string
}

// Validate 校验修复记录。任何一项缺失都说明该记录不可用于判定。
func (f AdvisoryFix) Validate() error {
	if f.AdvisoryUID == "" {
		return domainErr("修复记录缺少公告 UID")
	}
	if !f.CVEID.Valid() {
		return domainErr("修复记录缺少合法 CVE")
	}
	if !f.DistroID.Valid() {
		return domainErr("修复记录缺少合法发行版: %q", f.DistroID)
	}
	if f.Release == "" {
		return domainErr("修复记录缺少 release")
	}
	if f.Channel == "" {
		return domainErr("修复记录缺少渠道")
	}
	if !f.Ref.Kind.Valid() {
		return domainErr("修复记录缺少包类型")
	}
	if f.Ref.Name == "" {
		return domainErr("修复记录缺少包名")
	}
	if f.Ref.Arch == "" {
		return domainErr("修复记录缺少架构")
	}
	if f.FixedVersion == "" {
		return domainErr("修复记录缺少固定版本")
	}
	return nil
}

// NotAffectedReason 是官方显式声明「不受影响」的类型。
type NotAffectedReason string

const (
	NotAffectedDeclared  NotAffectedReason = "not-affected"           // 官方声明该 release 不受影响
	NotInRelease         NotAffectedReason = "not-in-release"         // 该 release 未收录此包
	VulnerableCodeAbsent NotAffectedReason = "vulnerable-code-absent" // 易受影响代码不存在
	NotAffectedEndOfLife NotAffectedReason = "end-of-life"            // 已终止支持，不再评估
)

// Valid 判断不受影响原因是否合法。
func (r NotAffectedReason) Valid() bool {
	switch r {
	case NotAffectedDeclared, NotInRelease, VulnerableCodeAbsent, NotAffectedEndOfLife:
		return true
	}
	return false
}

// NotAffected 是官方显式的不受影响声明。
// 只有此记录能推出 NOT_AFFECTED；数据源未收录 CVE 不等于不受影响。
type NotAffected struct {
	SourceID    SourceID
	AdvisoryID  string
	CVEID       CVEID
	DistroID    DistroID
	Release     string
	Ref         PackageRef
	Reason      NotAffectedReason
	EvidenceURL string
}

// Validate 校验不受影响声明。
func (n NotAffected) Validate() error {
	if n.SourceID == "" {
		return domainErr("不受影响声明缺少情报源")
	}
	if !n.CVEID.Valid() {
		return domainErr("不受影响声明的 CVE 非法")
	}
	if !n.DistroID.Valid() || n.Release == "" {
		return domainErr("不受影响声明缺少发行版/release")
	}
	if n.Ref.Name == "" || !n.Ref.Kind.Valid() {
		return domainErr("不受影响声明缺少包身份")
	}
	if !n.Reason.Valid() {
		return domainErr("不受影响声明的原因为非法值: %q", n.Reason)
	}
	return nil
}

// MatchKind 描述证据对判定结果的支持方式。
type MatchKind string

const (
	MatchFixedVersion  MatchKind = "fixed_version" // 版本比较命中
	MatchNotAffected   MatchKind = "explicit_not_affected"
	MatchSourceGap     MatchKind = "source_gap"               // 该源无覆盖数据
	MatchBridgeFailed  MatchKind = "source_bridge_unresolved" // 源码包桥接失败
	MatchCompareError  MatchKind = "compare_error"            // 版本不可比
	MatchChannelAbsent MatchKind = "channel_unavailable"      // 渠道未启用
)

// Evidence 是判定依据，必须随每条 finding 落库并出现在报告中。
type Evidence struct {
	SourceID        SourceID
	ValidationLevel SourceValidation
	AdvisoryID      string
	URL             string
	MatchKind       MatchKind
	Detail          string // 人类可读说明，报告原样输出
	RetrievedAt     time.Time
}
