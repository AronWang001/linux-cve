package feed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// 锁相关错误。
var (
	// ErrLocked 表示同一情报源正被另一个进程更新。
	ErrLocked = errors.New("feed: 情报源正被其他进程更新")
)

// lockStale 是锁文件的过期时间。
// 取 30 分钟：Debian 全量下载加解析在慢网络上可能超过 10 分钟，
// 而进程崩溃留下的锁不能永久阻塞后续更新。
const lockStale = 30 * time.Minute

// sourceLock 是「同一源同一时刻只允许一个更新者」的跨进程互斥。
//
// 不用 flock 的原因：Windows 上没有等价的语义，而本工具要在
// Linux / macOS / Windows 上都能跑。用 O_EXCL 创建锁文件 + 过期判定，
// 行为可预期，代价是崩溃后最多等一个过期周期。
type sourceLock struct {
	path string
}

// acquireLock 获取某源的更新锁。
func (s *Store) acquireLock(sourceID string) (*sourceLock, error) {
	name := sanitizeLockName(sourceID)
	path := filepath.Join(s.root, name+".lock")

	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err == nil {
			_, _ = f.WriteString(strconv.FormatInt(time.Now().Unix(), 10) + "\n")
			_ = f.Close()
			return &sourceLock{path: path}, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("feed: 创建更新锁失败: %w", err)
		}
		// 锁已存在：只有确认过期才回收，否则如实报告占用。
		st, statErr := os.Stat(path)
		if statErr != nil {
			continue
		}
		if time.Since(st.ModTime()) < lockStale {
			return nil, fmt.Errorf("%w: %s", ErrLocked, path)
		}
		if rmErr := os.Remove(path); rmErr != nil {
			return nil, fmt.Errorf("feed: 清理过期锁失败: %w", rmErr)
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrLocked, path)
}

// Release 释放锁。只删除自己创建的锁文件。
func (l *sourceLock) Release() {
	if l == nil || l.path == "" {
		return
	}
	_ = os.Remove(l.path)
}

// sanitizeLockName 把源 ID 转成安全的文件名。
// 源 ID 来自静态配置，仍然清洗一次，避免将来动态化后引入路径穿越。
func sanitizeLockName(id string) string {
	out := make([]rune, 0, len(id))
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "source"
	}
	return string(out)
}
