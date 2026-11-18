package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// cvePattern 是 CVE 编号的严格格式，用于拦截伪造与注入输入。
var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// CVEID 是标准 CVE 编号，形如 CVE-2026-98432。
type CVEID string

// ParseCVEID 解析并校验 CVE 编号，统一转为大写。
func ParseCVEID(s string) (CVEID, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	if !cvePattern.MatchString(up) {
		return "", domainErr("非法 CVE 编号: %q", s)
	}
	return CVEID(up), nil
}

// Valid 判断编号格式是否合法。
func (c CVEID) Valid() bool { return cvePattern.MatchString(string(c)) }

// String 返回编号字符串。
func (c CVEID) String() string { return string(c) }

// Year 返回 CVE 年份，用于按年份分片的情报拉取。
func (c CVEID) Year() (int, bool) {
	if !c.Valid() {
		return 0, false
	}
	var y int
	if _, err := fmt.Sscanf(string(c)[4:8], "%d", &y); err != nil {
		return 0, false
	}
	return y, true
}

// Severity 是严重程度。unknown 表示来源未给出评分，排序时视为最低可信。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
	SeverityUnknown  Severity = "unknown"
)

// Valid 判断严重程度取值是否合法。
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone, SeverityUnknown:
		return true
	}
	return false
}

// Rank 返回排序权重，越大越严重；unknown 返回 -1 以便单独排序。
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	case SeverityNone:
		return 0
	default:
		return -1
	}
}

// ParseSeverity 解析严重程度字符串。
func ParseSeverity(s string) (Severity, error) {
	sev := Severity(strings.ToLower(strings.TrimSpace(s)))
	if !sev.Valid() {
		return SeverityUnknown, domainErr("非法严重程度: %q", s)
	}
	return sev, nil
}

// SeverityFromCVSS 按 CVSS v3 分段把分数映射为严重程度。
// 分数超过 10 或小于 0 视为非法，返回 unknown。
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score < 0 || score > 10:
		return SeverityUnknown
	case score == 0:
		return SeverityNone
	case score < 4.0:
		return SeverityLow
	case score < 7.0:
		return SeverityMedium
	case score < 9.0:
		return SeverityHigh
	default:
		return SeverityCritical
	}
}
