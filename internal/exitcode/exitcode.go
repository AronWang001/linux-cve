// Package exitcode 定义进程统一退出码。
//
// 设计约束：退出码只由 cmd/linux-cve 一处调用 os.Exit，
// 其他包一律返回 error，避免多处退出导致状态不一致。
package exitcode

import "fmt"

// Code 是进程退出码。
type Code int

const (
	// OK 成功；scan 未发现漏洞同样返回 OK。
	OK Code = 0
	// Error 未分类运行时错误。
	Error Code = 1
	// Usage 参数错误、未知子命令。
	Usage Code = 2
	// Findings 命令成功但发现漏洞，便于脚本判定。
	Findings Code = 3
	// Unsupported 当前发行版/release/包管理器不支持该操作。
	Unsupported Code = 4
	// Permission 需要 root 或权限不足。
	Permission Code = 5
	// RemediationFailed 修复执行失败，或执行后复检未通过。
	RemediationFailed Code = 6
	// Integrity 数据库校验失败、迁移校验和不符、情报签名校验失败。
	Integrity Code = 7
	// NotImplemented 该阶段尚未实现。
	NotImplemented Code = 8
	// Interrupted 被 SIGINT 中断。
	Interrupted Code = 130
)

var names = map[Code]string{
	OK:                "OK",
	Error:             "ERROR",
	Usage:             "USAGE",
	Findings:          "FINDINGS",
	Unsupported:       "UNSUPPORTED",
	Permission:        "PERMISSION",
	RemediationFailed: "REMEDIATION_FAILED",
	Integrity:         "INTEGRITY",
	NotImplemented:    "NOT_IMPLEMENTED",
	Interrupted:       "INTERRUPTED",
}

// String 返回退出码的稳定名称，用于日志与 JSON 输出。
func (c Code) String() string {
	if n, ok := names[c]; ok {
		return n
	}
	return fmt.Sprintf("CODE_%d", int(c))
}

// Valid 判断是否为已定义退出码。
func (c Code) Valid() bool {
	_, ok := names[c]
	return ok
}

// Int 返回可直接传给 os.Exit 的整数。
func (c Code) Int() int { return int(c) }
