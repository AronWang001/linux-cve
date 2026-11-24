package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"time"
)

// 错误类别，供调用方判断是否需要换源或降级而不是重试。
var (
	// ErrNotFound 表示远端明确不存在该资源（404/410），重试无意义。
	ErrNotFound = errors.New("feed: 远端资源不存在")

	// ErrTooLarge 表示下载体积超过该源上限，说明格式变化或遭遇异常文件。
	ErrTooLarge = errors.New("feed: 下载体积超过上限")

	// ErrNotModified 在条件请求命中 304 时用于内部判定，不对外返回。
	errNotModified = errors.New("feed: 未修改")
)

// FetchOptions 是一次抓取的参数。
type FetchOptions struct {
	// ETag / LastModified 为空表示首次抓取；非空时走条件请求。
	ETag         string
	LastModified string
	// MaxBytes 为 0 时用 DefaultMaxBytes。
	MaxBytes int64
}

// FetchResult 是一次成功抓取的结果。
type FetchResult struct {
	// Body 仅在 NotModified 为 false 时有内容。
	Body         []byte
	SHA256       string
	Size         int64
	StatusCode   int
	NotModified  bool
	ETag         string
	LastModified string
	ContentType  string
	FetchedAt    time.Time
	Retries      int
	// Elapsed 是含重试在内的总耗时，进报告用于说明数据源响应情况。
	Elapsed time.Duration
}

// Fetcher 是带超时、重试与体积上限的 HTTP 抓取器。
//
// 所有请求都必须有超时：情报源响应慢不能拖死扫描进程。
type Fetcher struct {
	HTTP      *http.Client
	Retries   int
	RetryBase time.Duration
	UserAgent string
	Now       func() time.Time
}

// NewFetcher 构造抓取器。timeout<=0 时用 DefaultHTTPTimeout。
func NewFetcher(timeout time.Duration) *Fetcher {
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	return &Fetcher{
		HTTP: &http.Client{
			Timeout: timeout,
			// 情报源的重定向应当有界；超过 5 跳视为异常（防重定向放大）。
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("feed: 重定向次数过多")
				}
				if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
					return fmt.Errorf("feed: 拒绝非 HTTP(S) 重定向: %s", req.URL.Scheme)
				}
				return nil
			},
		},
		Retries:   DefaultRetries,
		RetryBase: DefaultRetryBase,
		UserAgent: "linux-cve/2.0 (+https://github.com/AronWang001/linux-cve-2026-98432-fix)",
		Now:       time.Now,
	}
}

// Get 抓取一个 URL。
//
// 重试策略：网络错误、5xx、429 重试；4xx（除 429）不重试，
// 因为再试也不会变。context 取消立即返回，不重试。
func (f *Fetcher) Get(ctx context.Context, rawURL string, opt FetchOptions) (*FetchResult, error) {
	maxBytes := opt.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	start := f.Now()
	attempts := f.Retries + 1
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			if err := f.sleep(ctx, attempt); err != nil {
				return nil, err
			}
		}
		res, retryable, err := f.doOnce(ctx, rawURL, opt, maxBytes, attempt)
		if err == nil {
			if res.Elapsed == 0 {
				res.Elapsed = f.Now().Sub(start)
			}
			res.Retries = attempt
			return res, nil
		}
		lastErr = err
		if !retryable || ctx.Err() != nil {
			break
		}
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("feed: 抓取被取消: %w", ctx.Err())
	}
	return nil, lastErr
}

// doOnce 执行单次请求，返回结果、是否可重试、错误。
func (f *Fetcher) doOnce(ctx context.Context, rawURL string, opt FetchOptions, maxBytes int64, attempt int) (*FetchResult, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("feed: 构造请求失败: %w", err)
	}
	req.Header.Set("User-Agent", f.UserAgent)
	req.Header.Set("Accept", "*/*")
	if opt.ETag != "" {
		req.Header.Set("If-None-Match", opt.ETag)
	}
	if opt.LastModified != "" {
		req.Header.Set("If-Modified-Since", opt.LastModified)
	}

	resp, err := f.HTTP.Do(req)
	if err != nil {
		// 传输层错误通常是网络抖动，值得重试；除非是明确不可达的协议错误。
		return nil, true, fmt.Errorf("feed: 请求 %s 失败: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return &FetchResult{
			StatusCode:   resp.StatusCode,
			NotModified:  true,
			ETag:         opt.ETag,
			LastModified: opt.LastModified,
			FetchedAt:    f.Now().UTC(),
		}, false, nil

	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return nil, false, fmt.Errorf("%w: %s (HTTP %d)", ErrNotFound, rawURL, resp.StatusCode)

	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, true, fmt.Errorf("feed: 请求 %s 被限流 (HTTP 429)", rawURL)

	case resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("feed: 请求 %s 服务端错误 (HTTP %d)", rawURL, resp.StatusCode)

	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, false, fmt.Errorf("feed: 请求 %s 返回 HTTP %d", rawURL, resp.StatusCode)
	}

	// 体积上限：多读 1 字节即可判断是否超限，避免把超大响应用完内存。
	limited := io.LimitReader(resp.Body, maxBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, true, fmt.Errorf("feed: 读取 %s 响应失败: %w", rawURL, err)
	}
	if int64(len(body)) > maxBytes {
		return nil, false, fmt.Errorf("%w: %s 超过 %d 字节", ErrTooLarge, rawURL, maxBytes)
	}
	if len(body) == 0 {
		return nil, false, fmt.Errorf("feed: %s 返回空响应体", rawURL)
	}

	sum := sha256.Sum256(body)
	return &FetchResult{
		Body:         body,
		SHA256:       hex.EncodeToString(sum[:]),
		Size:         int64(len(body)),
		StatusCode:   resp.StatusCode,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		ContentType:  resp.Header.Get("Content-Type"),
		FetchedAt:    f.Now().UTC(),
	}, false, nil
}

// sleep 按指数退避等待，带抖动避免多源同时重试形成尖峰。
func (f *Fetcher) sleep(ctx context.Context, attempt int) error {
	base := f.RetryBase
	if base <= 0 {
		base = DefaultRetryBase
	}
	d := base << (attempt - 1)
	if d > 10*time.Second {
		d = 10 * time.Second
	}
	// 抖动 0.5x–1.5x。
	jitter := time.Duration(float64(d) * (0.5 + rand.Float64()))
	timer := time.NewTimer(jitter)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("feed: 重试等待被取消: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

// RetryAfter 解析 Retry-After 响应头，用于限流场景。
// 解析失败返回 0，调用方自行决定是否退避。
func RetryAfter(h string, now time.Time) time.Duration {
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

// IsTimeout 判断错误是否为超时类，报告里需要区分「源慢」与「源坏」。
func IsTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return errors.Is(err, context.DeadlineExceeded)
}
