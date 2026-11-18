// Command linux-cve 是 Linux CVE Fix v2.0 的唯一入口。
//
// 本文件只做三件事：建立信号感知 context、调用 app.Main、把退出码交给 os.Exit。
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/app"
)

func main() {
	// SIGINT/SIGTERM 触发 context 取消，长任务可及时退出并保持数据库一致
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(app.Main(ctx, os.Args[1:], os.Stdout, os.Stderr).Int())
}
