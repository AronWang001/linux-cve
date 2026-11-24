// Package apperr 提供带退出码的错误类型，以及错误到退出码的映射。
package apperr

import (
	"errors"
	"fmt"

	"github.com/AronWang001/linux-cve/internal/exitcode"
)

// Error 是携带退出码与操作上下文的错误。
type Error struct {
	Code exitcode.Code
	Op   string // 发生位置，如 "database.migrate"
	Msg  string // 面向用户的可读描述
	Err  error  // 底层错误，可为空
}

// Error 实现 error 接口。
func (e *Error) Error() string {
	switch {
	case e.Op != "" && e.Err != nil:
		return fmt.Sprintf("%s: %s: %v", e.Op, e.Msg, e.Err)
	case e.Op != "":
		return fmt.Sprintf("%s: %s", e.Op, e.Msg)
	case e.Err != nil:
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	default:
		return e.Msg
	}
}

// Unwrap 支持 errors.Is / errors.As 穿透。
func (e *Error) Unwrap() error { return e.Err }

// New 构造一个不含底层错误的 apperr。
func New(code exitcode.Code, op, msg string) *Error {
	return &Error{Code: code, Op: op, Msg: msg}
}

// Newf 构造格式化消息的 apperr。
func Newf(code exitcode.Code, op, format string, args ...any) *Error {
	return &Error{Code: code, Op: op, Msg: fmt.Sprintf(format, args...)}
}

// Wrap 包装底层错误。
func Wrap(code exitcode.Code, op, msg string, err error) *Error {
	return &Error{Code: code, Op: op, Msg: msg, Err: err}
}

// Usagef 构造参数错误。
func Usagef(format string, args ...any) *Error {
	return Newf(exitcode.Usage, "cli", format, args...)
}

// NotImplementedf 构造未实现错误。
func NotImplementedf(format string, args ...any) *Error {
	return Newf(exitcode.NotImplemented, "cli", format, args...)
}

// CodeOf 从任意 error 提取退出码。未包装的普通错误映射为 exitcode.Error。
func CodeOf(err error) exitcode.Code {
	if err == nil {
		return exitcode.OK
	}
	var ae *Error
	if errors.As(err, &ae) {
		if ae.Code.Valid() {
			return ae.Code
		}
	}
	return exitcode.Error
}
