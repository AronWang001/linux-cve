package feed

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

func TestStorePutReadRoundTrip(t *testing.T) {
	st, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	data := []byte(`{"hello":"world"}`)
	sha := HashBytes(data)

	path, deduped, err := st.Put(sha, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if deduped {
		t.Fatal("首次写入不应判定为去重")
	}
	if !strings.HasSuffix(path, sha) {
		t.Fatalf("落盘文件名应为哈希，实际 %s", path)
	}

	got, err := st.Read(sha)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("读回内容不一致: %q", got)
	}
}

func TestStorePutIsIdempotent(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	data := []byte("payload")
	sha := HashBytes(data)

	if _, _, err := st.Put(sha, data); err != nil {
		t.Fatalf("首次 Put: %v", err)
	}
	_, deduped, err := st.Put(sha, data)
	if err != nil {
		t.Fatalf("二次 Put: %v", err)
	}
	if !deduped {
		t.Fatal("同内容二次写入应命中去重")
	}

	// 目录里只应有一份文件。
	entries, _ := os.ReadDir(filepath.Join(st.Root(), "artifacts", sha[:2]))
	if len(entries) != 1 {
		t.Fatalf("应只有 1 份 Artifact，实际 %d", len(entries))
	}
}

func TestStoreRejectsHashMismatch(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	data := []byte("real content")
	wrong := HashBytes([]byte("other content"))

	if _, _, err := st.Put(wrong, data); err == nil {
		t.Fatal("内容与声明哈希不符时必须拒绝写入")
	}
}

func TestStoreRejectsPathTraversal(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	for _, bad := range []string{
		"../../etc/passwd",
		strings.Repeat("a", 63),
		strings.Repeat("z", 64),
		"",
	} {
		if _, err := st.Path(bad); err == nil {
			t.Fatalf("非法哈希 %q 必须被拒绝", bad)
		}
	}
}

func TestStoreDetectsCorruption(t *testing.T) {
	st, _ := NewStore(t.TempDir())
	data := []byte("original")
	sha := HashBytes(data)
	path, _, err := st.Put(sha, data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// 情形一：字节数不变但内容被改写。文件名仍是哈希，
	// 因此只能靠读回后的哈希自校验发现。
	if err := os.WriteFile(path, []byte("tampered"), 0o640); err != nil {
		t.Fatalf("篡改文件: %v", err)
	}
	if _, err := st.Read(sha); err == nil {
		t.Fatal("内容与哈希不符时必须报错，不能返回坏数据")
	}

	// 情形二：字节数也变了，Has 直接判定为未命中（无需读全文）。
	if err := os.WriteFile(path, []byte("tampered-and-longer"), 0o640); err != nil {
		t.Fatalf("篡改文件: %v", err)
	}
	if st.Has(sha, int64(len(data))) {
		t.Fatal("大小不符时 Has 应为 false")
	}
}

func TestStoreCleanTemp(t *testing.T) {
	root := t.TempDir()
	st, _ := NewStore(root)

	old := filepath.Join(st.tmpDir(), "stale.tmp")
	if err := os.WriteFile(old, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	fresh := filepath.Join(st.tmpDir(), "fresh.tmp")
	if err := os.WriteFile(fresh, []byte("y"), 0o640); err != nil {
		t.Fatal(err)
	}

	n, err := st.CleanTemp(time.Hour)
	if err != nil {
		t.Fatalf("CleanTemp: %v", err)
	}
	if n != 1 {
		t.Fatalf("应清理 1 个陈旧临时文件，实际 %d", n)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatal("新鲜临时文件不应被删除")
	}
}

func TestFetcherSuccess(t *testing.T) {
	body := []byte(`{"ok":true}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("请求必须带 User-Agent")
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := NewFetcher(5 * time.Second)
	res, err := f.Get(context.Background(), srv.URL, FetchOptions{})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if res.NotModified {
		t.Fatal("首次抓取不应判定未修改")
	}
	if res.SHA256 != HashBytes(body) {
		t.Fatalf("哈希不符: %s", res.SHA256)
	}
	if res.ETag != `"v1"` {
		t.Fatalf("应保留 ETag，实际 %q", res.ETag)
	}
	if res.Size != int64(len(body)) {
		t.Fatalf("体积不符: %d", res.Size)
	}
}

func TestFetcherNotModified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") != `"v1"` {
			t.Errorf("应发送 If-None-Match，实际 %q", r.Header.Get("If-None-Match"))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	f := NewFetcher(5 * time.Second)
	res, err := f.Get(context.Background(), srv.URL, FetchOptions{ETag: `"v1"`})
	if err != nil {
		t.Fatalf("304 不应返回错误: %v", err)
	}
	if !res.NotModified {
		t.Fatal("应判定为未修改")
	}
	if len(res.Body) != 0 {
		t.Fatal("304 不应带回内容")
	}
}

func TestFetcherNotFoundIsNotRetried(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	f := NewFetcher(5 * time.Second)
	_, err := f.Get(context.Background(), srv.URL, FetchOptions{})
	if err == nil {
		t.Fatal("404 必须返回错误")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("应可识别为 ErrNotFound，实际 %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("404 不应重试，实际请求 %d 次", got)
	}
}

func TestFetcherRetriesServerError(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&hits, 1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	f := NewFetcher(5 * time.Second)
	f.RetryBase = time.Millisecond
	res, err := f.Get(context.Background(), srv.URL, FetchOptions{})
	if err != nil {
		t.Fatalf("第三次应成功: %v", err)
	}
	if res.Retries != 2 {
		t.Fatalf("应记录 2 次重试，实际 %d", res.Retries)
	}
	if string(res.Body) != "ok" {
		t.Fatalf("内容不符: %q", res.Body)
	}
}

func TestFetcherRejectsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", 2048)))
	}))
	defer srv.Close()

	f := NewFetcher(5 * time.Second)
	_, err := f.Get(context.Background(), srv.URL, FetchOptions{MaxBytes: 1024})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("超限应返回 ErrTooLarge，实际 %v", err)
	}
}

func TestFetcherHonoursContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	f := NewFetcher(5 * time.Second)
	start := time.Now()
	if _, err := f.Get(ctx, srv.URL, FetchOptions{}); err == nil {
		t.Fatal("超时上下文应返回错误")
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("取消应尽快生效，实际耗时 %v", elapsed)
	}
}

func TestSourceValidateRequiresFingerprintForA(t *testing.T) {
	base := Source{
		ID:            domain.SourceRHELCSAF,
		URL:           "https://example.invalid/x",
		TrustLevel:    domain.TrustLevelA,
		SignatureKind: "gpg",
		MaxBytes:      1024,
	}
	if err := base.Validate(); err == nil {
		t.Fatal("A 级源缺少固化指纹必须报错")
	}
	base.PublicKeyFP = "ABCD"
	if err := base.Validate(); err != nil {
		t.Fatalf("补齐指纹后应通过: %v", err)
	}
}

func TestSourceURLForRelease(t *testing.T) {
	ub, ok := SourceByID(domain.SourceUbuntuOVAL)
	if !ok {
		t.Fatal("应能找到 Ubuntu 源")
	}
	got, err := ub.URLFor("noble")
	if err != nil {
		t.Fatalf("URLFor: %v", err)
	}
	want := "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2"
	if got != want {
		t.Fatalf("URL 不符:\n got %s\nwant %s", got, want)
	}
	if _, err := ub.URLFor(""); err == nil {
		t.Fatal("按 release 分文件的源缺 release 必须报错")
	}

	deb, _ := SourceByID(domain.SourceDebianTracker)
	if _, err := deb.URLFor(""); err != nil {
		t.Fatalf("非分片源不应要求 release: %v", err)
	}
}

func TestRedHatVEXURLUsesCVEYear(t *testing.T) {
	got, err := RedHatVEXURL("CVE-2026-98432")
	if err != nil {
		t.Fatalf("RedHatVEXURL: %v", err)
	}
	want := "https://security.access.redhat.com/data/csaf/v2/vex/2026/cve-2026-98432.json"
	if got != want {
		t.Fatalf("URL 不符:\n got %s\nwant %s", got, want)
	}
	if _, err := RedHatVEXURL("not-a-cve"); err == nil {
		t.Fatal("非法 CVE 应报错")
	}
}

func TestAlpineSecDBURLValidatesRepo(t *testing.T) {
	got, err := AlpineSecDBURL("3.20", "main")
	if err != nil {
		t.Fatalf("AlpineSecDBURL: %v", err)
	}
	if want := "https://secdb.alpinelinux.org/v3.20/main.json"; got != want {
		t.Fatalf("URL 不符: %s", got)
	}
	if _, err := AlpineSecDBURL("3.20", "extras"); err == nil {
		t.Fatal("未知仓库应报错")
	}
}

func TestAllSourcesValid(t *testing.T) {
	srcs := Sources()
	if len(srcs) != 6 {
		t.Fatalf("应登记 6 个源，实际 %d", len(srcs))
	}
	seen := map[domain.SourceID]bool{}
	for _, s := range srcs {
		if err := s.Validate(); err != nil {
			t.Fatalf("源 %s 配置非法: %v", s.ID, err)
		}
		if seen[s.ID] {
			t.Fatalf("源 ID 重复: %s", s.ID)
		}
		seen[s.ID] = true
		if s.ParserVersion == "" {
			t.Fatalf("源 %s 缺少解析器版本", s.ID)
		}
	}
	// A 级源必须恰好是两个（Red Hat + SUSE）。
	aCount := 0
	for _, s := range srcs {
		if s.TrustLevel == domain.TrustLevelA {
			aCount++
		}
	}
	if aCount != 2 {
		t.Fatalf("A 级签名源应为 2 个，实际 %d", aCount)
	}
}

func TestArtifactValidate(t *testing.T) {
	ok := Artifact{
		SHA256:          HashBytes([]byte("x")),
		SourceID:        domain.SourceDebianTracker,
		SizeBytes:       1,
		SignatureStatus: domain.SignatureNotApplicable,
		IntegrityStatus: domain.IntegrityVerified,
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("合法 Artifact 不应报错: %v", err)
	}
	bad := ok
	bad.SHA256 = "short"
	if err := bad.Validate(); err == nil {
		t.Fatal("哈希长度非法必须报错")
	}
	bad = ok
	bad.SignatureStatus = "maybe"
	if err := bad.Validate(); err == nil {
		t.Fatal("非法签名状态必须报错")
	}
	bad = ok
	bad.IntegrityStatus = "trusted"
	if err := bad.Validate(); err == nil {
		t.Fatal("非法完整性状态必须报错")
	}
}

func TestRetryAfterParsing(t *testing.T) {
	now := time.Now()
	if d := RetryAfter("30", now); d != 30*time.Second {
		t.Fatalf("秒数解析错误: %v", d)
	}
	if d := RetryAfter("", now); d != 0 {
		t.Fatalf("空值应为 0: %v", d)
	}
	if d := RetryAfter("bogus", now); d != 0 {
		t.Fatalf("非法值应为 0: %v", d)
	}
	future := now.Add(20 * time.Second).UTC().Format(http.TimeFormat)
	if d := RetryAfter(future, now); d <= 0 || d > 21*time.Second {
		t.Fatalf("HTTP 日期解析异常: %v", d)
	}
}

func TestFetcherRejectsInvalidURL(t *testing.T) {
	f := NewFetcher(time.Second)
	if _, err := f.Get(context.Background(), "://bad", FetchOptions{}); err == nil {
		t.Fatal("非法 URL 必须报错")
	}
}

func TestFetchResultElapsedRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "x")
	}))
	defer srv.Close()
	f := NewFetcher(5 * time.Second)
	res, err := f.Get(context.Background(), srv.URL, FetchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Elapsed <= 0 {
		t.Fatal("应记录耗时")
	}
	if res.FetchedAt.IsZero() {
		t.Fatal("应记录抓取时间")
	}
}
