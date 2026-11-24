package feed

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Store 是不可变 Artifact 的内容寻址存储。
//
// 布局：
//
//	<root>/artifacts/<sha 前两位>/<sha 全串>
//	<root>/tmp/<随机>.tmp
//
// 文件名即内容哈希，因此同一内容天然去重；Artifact 一旦落盘不再改写，
// 撤回的公告只改归一化层的状态，不删原始字节。
type Store struct {
	root string
}

// NewStore 创建（或复用）某个数据目录下的 Artifact 存储。
func NewStore(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("feed: Artifact 存储目录不能为空")
	}
	s := &Store{root: root}
	for _, d := range []string{s.artifactDir(), s.tmpDir()} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, fmt.Errorf("feed: 创建存储目录 %s 失败: %w", d, err)
		}
	}
	return s, nil
}

// Root 返回存储根目录。
func (s *Store) Root() string { return s.root }

func (s *Store) artifactDir() string { return filepath.Join(s.root, "artifacts") }
func (s *Store) tmpDir() string      { return filepath.Join(s.root, "tmp") }

// Path 返回某个哈希对应的落盘路径。
// 只接受 64 位十六进制串，避免路径穿越（哈希直接来自网络，必须当不可信输入）。
func (s *Store) Path(sha string) (string, error) {
	if err := validateSHA(sha); err != nil {
		return "", err
	}
	return filepath.Join(s.artifactDir(), sha[:2], sha), nil
}

// Has 判断某个 Artifact 是否已落盘且大小一致。
func (s *Store) Has(sha string, size int64) bool {
	p, err := s.Path(sha)
	if err != nil {
		return false
	}
	st, err := os.Stat(p)
	if err != nil {
		return false
	}
	if !st.Mode().IsRegular() {
		return false
	}
	// 大小不符说明落盘文件损坏或被截断，不能当作命中。
	return size < 0 || st.Size() == size
}

// Put 把内容写入不可变存储，返回落盘路径与是否为去重命中。
//
// 写入流程：临时文件 → fsync → rename。rename 在同一文件系统内是原子的，
// 因此不会出现「半个文件被当成完整 Artifact」的情况。
func (s *Store) Put(sha string, data []byte) (string, bool, error) {
	if err := validateSHA(sha); err != nil {
		return "", false, err
	}
	if got := HashBytes(data); got != sha {
		return "", false, fmt.Errorf("feed: 内容哈希与声明不符: 声明 %s，实际 %s", sha, got)
	}
	dst, err := s.Path(sha)
	if err != nil {
		return "", false, err
	}
	if s.Has(sha, int64(len(data))) {
		return dst, true, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return "", false, fmt.Errorf("feed: 创建 Artifact 目录失败: %w", err)
	}

	tmp, err := os.CreateTemp(s.tmpDir(), "artifact-*.tmp")
	if err != nil {
		return "", false, fmt.Errorf("feed: 创建临时文件失败: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return "", false, fmt.Errorf("feed: 写入临时文件失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return "", false, fmt.Errorf("feed: 同步临时文件失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", false, fmt.Errorf("feed: 关闭临时文件失败: %w", err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		_ = os.Remove(tmpName)
		return "", false, fmt.Errorf("feed: 设置 Artifact 权限失败: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return "", false, fmt.Errorf("feed: 落盘 Artifact 失败: %w", err)
	}
	return dst, false, nil
}

// Read 读回某个 Artifact 的全部字节。
func (s *Store) Read(sha string) ([]byte, error) {
	p, err := s.Path(sha)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("feed: 读取 Artifact %s 失败: %w", shortSHA(sha), err)
	}
	// 读回后自校验：磁盘损坏或人为改动必须被发现，不能拿坏数据去解析。
	if got := HashBytes(b); got != sha {
		return nil, fmt.Errorf("feed: Artifact %s 内容已损坏（实际哈希 %s）", shortSHA(sha), shortSHA(got))
	}
	return b, nil
}

// Open 以流方式打开 Artifact，供大文件（Debian 90MB）流式解析。
func (s *Store) Open(sha string) (io.ReadCloser, error) {
	p, err := s.Path(sha)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("feed: 打开 Artifact %s 失败: %w", shortSHA(sha), err)
	}
	return f, nil
}

// CleanTemp 清理上次崩溃残留的临时文件，返回删除数量。
// 进程启动时调用；只动 tmp 目录，不碰已落盘的 Artifact。
func (s *Store) CleanTemp(olderThan time.Duration) (int, error) {
	entries, err := os.ReadDir(s.tmpDir())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("feed: 读取临时目录失败: %w", err)
	}
	cutoff := time.Now().Add(-olderThan)
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(s.tmpDir(), e.Name())); err == nil {
			removed++
		}
	}
	return removed, nil
}

// validateSHA 校验 64 位小写十六进制。
func validateSHA(sha string) error {
	if len(sha) != 64 {
		return fmt.Errorf("feed: 哈希长度必须为 64，实际 %d", len(sha))
	}
	for i := 0; i < len(sha); i++ {
		c := sha[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("feed: 哈希含非十六进制字符: %q", sha)
		}
	}
	return nil
}

// shortSHA 返回前 12 位，用于日志与错误信息。
func shortSHA(sha string) string {
	if len(sha) <= 12 {
		return sha
	}
	return sha[:12]
}
