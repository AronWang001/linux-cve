package feed

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
)

// newUpdateFixture 组装一个可用的 Updater：临时数据库 + 临时 Artifact 目录。
//
// 测试用本地 HTTP 服务冒充情报源，因此不走网络也不依赖外部站点。
func newUpdateFixture(t *testing.T, handler http.HandlerFunc) (*Updater, *database.DB, string) {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()

	db, err := database.Open(ctx, filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("打开数据库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Migrate(ctx); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	rows := make([]database.FeedSourceRow, 0, 6)
	for _, s := range Sources() {
		rows = append(rows, database.FeedSourceRow{
			ID: s.ID, Name: s.Name, Kind: s.Kind, URL: s.URL,
			TrustLevel: s.TrustLevel, SignatureKind: s.SignatureKind,
		})
	}
	if err := db.UpsertFeedSources(ctx, rows); err != nil {
		t.Fatalf("写入源配置失败: %v", err)
	}

	store, err := NewStore(filepath.Join(dir, "feed"))
	if err != nil {
		t.Fatalf("创建 Artifact 存储失败: %v", err)
	}
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	u := &Updater{
		Store:   store,
		Fetcher: NewFetcher(5 * time.Second),
		DB:      db,
		Now:     func() time.Time { return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC) },
	}
	return u, db, srv.URL
}

// archSourceAt 把 Arch 源的地址改到本地测试服务。
func archSourceAt(url string) Source {
	s, _ := SourceByID(domain.SourceArchTracker)
	s.URL = url
	return s
}

func TestUpdateCommitsSnapshot(t *testing.T) {
	ctx := context.Background()
	var hits int
	u, db, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(archFixture))
	})

	src := archSourceAt(base + "/all.json")
	res, err := u.UpdateSource(ctx, src, "")
	if err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	if res.Skipped || res.SnapshotID == "" {
		t.Fatalf("应产出快照，实际 %+v", res)
	}
	if res.Advisories != 6 || res.Fixes != 4 {
		t.Errorf("统计错误: 公告 %d 修复 %d", res.Advisories, res.Fixes)
	}
	if res.Artifact.SHA256 != HashBytes([]byte(archFixture)) {
		t.Error("返回的 Artifact 哈希与内容不符")
	}

	// 快照必须成为生效快照，源状态记为成功。
	active, err := db.ActiveSnapshot(ctx, domain.SourceArchTracker)
	if err != nil {
		t.Fatalf("查询生效快照失败: %v", err)
	}
	if active != res.SnapshotID {
		t.Errorf("生效快照应为 %s，实际 %s", res.SnapshotID, active)
	}
	st, err := db.FeedStatus(ctx)
	if err != nil {
		t.Fatalf("查询源状态失败: %v", err)
	}
	var found bool
	for _, s := range st {
		if s.ID == domain.SourceArchTracker {
			found = true
			if s.LastError != "" {
				t.Errorf("成功更新后不应有错误: %s", s.LastError)
			}
			if s.LastSuccessAt == nil {
				t.Error("成功更新后应记录时间")
			}
		}
	}
	if !found {
		t.Fatal("源状态里找不到 Arch")
	}
	if hits != 1 {
		t.Errorf("应只请求一次，实际 %d", hits)
	}
}

func TestUpdateSkipsWhenContentUnchanged(t *testing.T) {
	ctx := context.Background()
	u, _, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(archFixture))
	})
	src := archSourceAt(base + "/all.json")

	first, err := u.UpdateSource(ctx, src, "")
	if err != nil {
		t.Fatalf("首次更新失败: %v", err)
	}
	second, err := u.UpdateSource(ctx, src, "")
	if err != nil {
		t.Fatalf("二次更新失败: %v", err)
	}
	// 该源没有 ETag，靠内容哈希判断未变化。
	if !second.Skipped {
		t.Fatalf("内容一致时应跳过，实际 %+v", second)
	}
	if second.SnapshotID == first.SnapshotID && second.SnapshotID != "" {
		t.Error("跳过时不应复用上次快照 ID")
	}
	if !strings.Contains(second.SkipReason, "未变化") {
		t.Errorf("跳过原因不明确: %q", second.SkipReason)
	}
}

func TestUpdateHonours304(t *testing.T) {
	ctx := context.Background()
	const etag = `"v1"`
	var conditional int
	u, _, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == etag {
			conditional++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(archFixture))
	})
	src := archSourceAt(base + "/all.json")

	if _, err := u.UpdateSource(ctx, src, ""); err != nil {
		t.Fatalf("首次更新失败: %v", err)
	}
	res, err := u.UpdateSource(ctx, src, "")
	if err != nil {
		t.Fatalf("二次更新失败: %v", err)
	}
	if !res.Skipped {
		t.Fatalf("304 应视为未变化，实际 %+v", res)
	}
	if conditional != 1 {
		t.Errorf("第二次请求应带 If-None-Match，实际条件请求 %d 次", conditional)
	}
}

func TestUpdateRejectsUntrustedTrustLevelA(t *testing.T) {
	ctx := context.Background()
	u, _, _ := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("A 级源缺少验签器时不应发起请求")
	})
	src, _ := SourceByID(domain.SourceRHELCSAF)

	_, err := u.UpdateSource(ctx, src, "")
	if err == nil {
		t.Fatal("A 级源没有验签器时必须拒绝")
	}
	if !strings.Contains(err.Error(), "签名") {
		t.Errorf("错误信息应说明签名问题，实际: %v", err)
	}
}

func TestUpdateRejectsOffline(t *testing.T) {
	ctx := context.Background()
	u, _, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("离线模式不应发起请求")
	})
	u.Offline = true
	src := archSourceAt(base + "/all.json")

	if _, err := u.UpdateSource(ctx, src, ""); !errors.Is(err, ErrOffline) {
		t.Fatalf("离线模式应返回 ErrOffline，实际 %v", err)
	}
}

func TestUpdateRejectsSourceWithoutParser(t *testing.T) {
	ctx := context.Background()
	u, _, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("没有解析器时不应发起请求")
	})
	// 用合成的 B 级源，而不是拿某个真实源顶替：
	// 真实源会随着解析器陆续接入而失效，这条用例就会莫名其妙地变成
	// 「测解析器还没写」的假阳性，掩盖真正的回归。
	src := archSourceAt(base + "/all.json")
	src.ID = domain.SourceID("synthetic-no-parser")
	src.TrustLevel = domain.TrustLevelB

	if _, err := u.UpdateSource(ctx, src, ""); err == nil {
		t.Fatal("缺少解析器时必须明确报错")
	} else if !strings.Contains(err.Error(), "解析器") {
		t.Errorf("错误信息应说明缺解析器，实际: %v", err)
	}
}

func TestUpdateMarksSourceErrorOnFailure(t *testing.T) {
	ctx := context.Background()
	u, db, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	src := archSourceAt(base + "/all.json")

	if _, err := u.UpdateSource(ctx, src, ""); err == nil {
		t.Fatal("服务端 5xx 时必须失败")
	}
	st, err := db.FeedStatus(ctx)
	if err != nil {
		t.Fatalf("查询源状态失败: %v", err)
	}
	for _, s := range st {
		if s.ID == domain.SourceArchTracker {
			if s.LastError == "" {
				t.Error("失败后必须记录错误，否则用户会以为情报是最新的")
			}
			if s.LastSuccessAt != nil {
				t.Error("从未成功过，不应有成功时间")
			}
		}
	}
}

func TestUpdateKeepsPreviousSnapshotOnParseFailure(t *testing.T) {
	ctx := context.Background()
	body := archFixture
	u, db, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	src := archSourceAt(base + "/all.json")

	first, err := u.UpdateSource(ctx, src, "")
	if err != nil {
		t.Fatalf("首次更新失败: %v", err)
	}

	// 第二次返回损坏数据：解析失败不得影响上一份有效情报。
	body = `[{"name": "AVG-9", broken`
	if _, err := u.UpdateSource(ctx, src, ""); err == nil {
		t.Fatal("损坏数据必须失败")
	}
	active, err := db.ActiveSnapshot(ctx, domain.SourceArchTracker)
	if err != nil {
		t.Fatalf("查询生效快照失败: %v", err)
	}
	if active != first.SnapshotID {
		t.Errorf("失败更新不得改变生效快照：期望 %s，实际 %s", first.SnapshotID, active)
	}
}

func TestSourceLockExcludesConcurrentUpdate(t *testing.T) {
	ctx := context.Background()
	u, _, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(archFixture))
	})

	// 手动占住 Arch 的锁，模拟另一个进程正在更新。
	lock, err := u.Store.acquireLock(string(domain.SourceArchTracker))
	if err != nil {
		t.Fatalf("获取锁失败: %v", err)
	}
	defer lock.Release()

	src := archSourceAt(base + "/all.json")
	if _, err := u.UpdateSource(ctx, src, ""); !errors.Is(err, ErrLocked) {
		t.Fatalf("并发更新应返回 ErrLocked，实际 %v", err)
	}
}

// TestUpdateAlpineCompletesHalfChangedSnapshot 验证「只变一份」不能写成半份快照。
//
// 这是多文件源最容易写坏库的地方：main 未变（304）、community 变了，
// 如果只把拿到的文件写库，replaceNormalized 会删掉该源全部归一化数据，
// 社区仓库的漏洞会凭空消失。正确行为是补齐未变化的文件再提交。
func TestUpdateAlpineCompletesHalfChangedSnapshot(t *testing.T) {
	ctx := context.Background()

	mainBody := `{"reponame":"main","distroversion":"v3.20","packages":[{"pkg":{"name":"aom","secfixes":{"1-r0":["CVE-2021-30473"]}}}]}`
	communityV1 := `{"reponame":"community","distroversion":"v3.20","packages":[{"pkg":{"name":"foo","secfixes":{"1-r0":["CVE-2021-1111"]}}}]}`
	communityV2 := `{"reponame":"community","distroversion":"v3.20","packages":[{"pkg":{"name":"foo","secfixes":{"1-r0":["CVE-2021-1111","CVE-2021-2222"]}}}]}`

	community := communityV1
	var mainFetches, communityFetches int

	u, _, base := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/main.json"):
			mainFetches++
			w.Header().Set("ETag", `"main-1"`)
			_, _ = w.Write([]byte(mainBody))
		case strings.HasSuffix(r.URL.Path, "/community.json"):
			communityFetches++
			_, _ = w.Write([]byte(community))
		default:
			http.NotFound(w, r)
		}
	})

	src, _ := SourceByID(domain.SourceAlpineSecDB)
	src.URL = base + "/v%s/%s.json"

	first, err := u.UpdateSource(ctx, src, "3.20")
	if err != nil {
		t.Fatalf("首次更新失败: %v", err)
	}
	if first.Advisories != 2 {
		t.Fatalf("首次应写入 2 条公告，实际 %d", first.Advisories)
	}

	// 只改 community：main 这次必然拿到 304。
	community = communityV2
	second, err := u.UpdateSource(ctx, src, "3.20")
	if err != nil {
		t.Fatalf("二次更新失败: %v", err)
	}
	if second.Skipped {
		t.Fatal("有一份文件变化时必须提交新快照")
	}
	if second.Advisories != 3 {
		t.Fatalf("补齐全量后应有 3 条公告（main 1 + community 2），实际 %d", second.Advisories)
	}
	// main 被抓三次：首次下载、二次判定未变化（该服务不返回 304，
	// 走内容哈希比对）、第三次为补齐内容重新下载。正是第三次
	// 保证了提交的是完整快照而不是半份。
	if mainFetches != 3 {
		t.Errorf("main 应被抓三次（下载 / 判未变 / 补齐），实际 %d", mainFetches)
	}
	if communityFetches != 2 {
		t.Errorf("community 应被抓两次，实际 %d", communityFetches)
	}
}

func TestSourceLockReclaimsStaleLock(t *testing.T) {
	u, _, _ := newUpdateFixture(t, func(w http.ResponseWriter, r *http.Request) {})

	lock, err := u.Store.acquireLock("stale-source")
	if err != nil {
		t.Fatalf("获取锁失败: %v", err)
	}
	// 把锁文件改成很久以前，模拟进程崩溃留下的残留。
	old := time.Now().Add(-2 * lockStale)
	if err := os.Chtimes(lock.path, old, old); err != nil {
		t.Fatalf("调整锁文件时间失败: %v", err)
	}
	second, err := u.Store.acquireLock("stale-source")
	if err != nil {
		t.Fatalf("过期锁应被回收，实际 %v", err)
	}
	second.Release()
}
