package app

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve/internal/apperr"
	"github.com/AronWang001/linux-cve/internal/database"
	"github.com/AronWang001/linux-cve/internal/domain"
	"github.com/AronWang001/linux-cve/internal/exitcode"
	"github.com/AronWang001/linux-cve/internal/feed"
	"github.com/AronWang001/linux-cve/internal/support"
)

// openDB 打开数据库并确保迁移到位。
// 情报与判定命令都需要 schema 就绪，重复迁移是幂等的。
func (e *env) openDB(ctx context.Context) (*database.DB, error) {
	d, err := database.Open(ctx, e.cfg.General.DBPath)
	if err != nil {
		return nil, err
	}
	if _, err := d.Migrate(ctx); err != nil {
		_ = d.Close()
		return nil, err
	}
	if err := d.UpsertFeedSources(ctx, feedSourceRows()); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// feedSourceRows 把静态源配置转成入库行。
func feedSourceRows() []database.FeedSourceRow {
	srcs := feed.Sources()
	rows := make([]database.FeedSourceRow, 0, len(srcs))
	for _, s := range srcs {
		rows = append(rows, database.FeedSourceRow{
			ID: s.ID, Name: s.Name, Kind: s.Kind, URL: s.URL,
			TrustLevel: s.TrustLevel, SignatureKind: s.SignatureKind,
		})
	}
	return rows
}

// artifactDir 返回不可变 Artifact 的根目录。
func (e *env) artifactDir() string {
	dir := e.cfg.General.DataDir
	if dir == "" {
		dir = filepath.Dir(e.cfg.General.DBPath)
	}
	return filepath.Join(dir, "artifacts")
}

// runFeed 处理 feed 子命令。
//
// 用法：
//
//	linux-cve feed status [--json]
//	linux-cve feed update [源ID...] [--release R] [--all]
func (e *env) runFeed(ctx context.Context, args []string) (exitcode.Code, error) {
	if len(args) == 0 {
		return exitcode.Usage, apperr.New(exitcode.Usage, "cli.feed",
			"feed 需要子命令：status 或 update")
	}
	switch args[0] {
	case "status":
		return e.feedStatus(ctx, args[1:])
	case "update":
		return e.feedUpdate(ctx, args[1:])
	default:
		return exitcode.Usage, apperr.Newf(exitcode.Usage, "cli.feed",
			"未知的 feed 子命令 %q（可用：status、update）", args[0])
	}
}

// feedStatus 展示各情报源的当前状态。
//
// 这里必须把「没接入」「取过但过期」「有错误」分开显示：
// 把它们都显示成「正常」会让用户以为情报是最新的。
func (e *env) feedStatus(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("feed status", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}
	d, err := e.openDB(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	defer func() { _ = d.Close() }()

	rows, err := d.FeedStatus(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	adv, err := d.CountAdvisories(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	fixes, err := d.CountFixes(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}

	type sourceDTO struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		TrustLevel  string `json:"trust_level"`
		Signature   string `json:"signature_kind"`
		ParserReady bool   `json:"parser_ready"`
		Status      string `json:"status"`
		LastSuccess string `json:"last_success_at,omitempty"`
		LastError   string `json:"last_error,omitempty"`
		Snapshot    string `json:"active_snapshot,omitempty"`
	}
	out := make([]sourceDTO, 0, len(rows))
	for _, r := range rows {
		_, reason := feed.ParserReason(r.ID)
		dto := sourceDTO{
			ID: string(r.ID), Name: r.Name, TrustLevel: string(r.TrustLevel),
			Signature: r.SignatureKind, ParserReady: reason == "",
			Status: r.Status, LastError: r.LastError, Snapshot: r.ActiveSnapshot,
		}
		if r.LastSuccessAt != nil {
			dto.LastSuccess = r.LastSuccessAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}

	if asJSON {
		payload := map[string]any{
			"schema_version": 1,
			"advisories":     adv,
			"fixes":          fixes,
			"sources":        out,
		}
		b, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return exitcode.Error, apperr.Wrap(exitcode.Error, "cli.feed", "序列化失败", err)
		}
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}

	fmt.Fprintf(e.stdout, "情报库：公告 %d 条，修复记录 %d 条\n\n", adv, fixes)
	fmt.Fprintf(e.stdout, "%-22s %-6s %-8s %-9s %s\n", "情报源", "信任", "解析器", "状态", "最近成功")
	for _, s := range out {
		parser := "就绪"
		if !s.ParserReady {
			parser = "未实现"
		}
		status := s.Status
		if s.Status == "" {
			status = "未同步"
		}
		last := s.LastSuccess
		if last == "" {
			last = "从未成功"
		}
		fmt.Fprintf(e.stdout, "%-22s %-6s %-8s %-9s %s\n", s.ID, s.TrustLevel, parser, status, last)
		if s.LastError != "" {
			fmt.Fprintf(e.stdout, "  └ 最近错误：%s\n", s.LastError)
		}
	}
	return exitcode.OK, nil
}

// feedUpdate 抓取并入库一个或多个情报源。
func (e *env) feedUpdate(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("feed update", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var release string
	var all, asJSON bool
	var since int
	fs.StringVar(&release, "release", "", "目标 release（Ubuntu 用 codename，Alpine 用 3.20 形式）")
	fs.BoolVar(&all, "all", false, "更新全部已实现解析器的情报源")
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	fs.IntVar(&since, "since", 0, "只同步该年份及以后发布的公告（仅 CSAF 源有效，0 表示全部）")
	// Go 的 flag 遇到第一个位置参数就停止解析，`feed update rhel-csaf --since 2026`
	// 会把 --since 当成源名。这里先把参数分成「标志」与「位置参数」两段，
	// 让两种写法都能用——命令行工具不该因为词序不同就报「未知情报源」。
	flagArgs, positional := splitFlags(args, map[string]bool{"all": true, "json": true})
	if err := fs.Parse(flagArgs); err != nil {
		return exitcode.Usage, nil
	}
	if err := e.ensureConfig(); err != nil {
		return exitcode.Error, err
	}

	ids := positional
	if !all && len(ids) == 0 {
		return exitcode.Usage, apperr.New(exitcode.Usage, "cli.feed",
			"feed update 需要指定情报源，或用 --all 更新全部")
	}

	targets := make([]feed.Source, 0, len(ids))
	if all {
		for _, s := range feed.Sources() {
			if ok, reason := feed.ParserReady(s); !ok {
				fmt.Fprintf(e.stderr, "跳过 %s：%s\n", s.ID, reason)
				continue
			}
			targets = append(targets, s)
		}
	} else {
		for _, id := range ids {
			s, ok := feed.SourceByID(domain.SourceID(id))
			if !ok {
				return exitcode.Usage, apperr.Newf(exitcode.Usage, "cli.feed",
					"未知的情报源 %q", id)
			}
			targets = append(targets, s)
		}
	}

	// --since 只对按文档发布的源有意义：单文件源本身就是全量快照，
	// 按年份裁剪没有语义。这里统一应用，未使用该字段的源自然忽略。
	if since > 0 {
		for i := range targets {
			if targets[i].DocumentSet {
				targets[i].SinceYear = since
			}
		}
	}

	d, err := e.openDB(ctx)
	if err != nil {
		return apperr.CodeOf(err), err
	}
	defer func() { _ = d.Close() }()

	store, err := feed.NewStore(e.artifactDir())
	if err != nil {
		return exitcode.Error, err
	}
	u := &feed.Updater{
		Store:   store,
		Fetcher: feed.NewFetcher(time.Duration(e.cfg.Feed.HTTPTimeout)),
		DB:      d,
		Offline: e.flags.offline || e.cfg.General.Offline,
		Logf: func(format string, a ...any) {
			fmt.Fprintf(e.stderr, format+"\n", a...)
		},
	}

	type resultDTO struct {
		SourceID string `json:"source_id"`
		Release  string `json:"release,omitempty"`
		Skipped  bool   `json:"skipped"`
		Reason   string `json:"reason,omitempty"`
		Snapshot string `json:"snapshot_id,omitempty"`
		Advisory int    `json:"advisories"`
		Fixes    int    `json:"fixes"`
		Bad      int    `json:"bad_records"`
		Elapsed  string `json:"elapsed,omitempty"`
		Error    string `json:"error,omitempty"`
	}
	var results []resultDTO
	failed := 0

	for _, src := range targets {
		rel, derr := e.releaseForSource(ctx, src, release)
		if derr != nil {
			results = append(results, resultDTO{SourceID: string(src.ID), Error: derr.Error()})
			fmt.Fprintf(e.stderr, "%s：%s\n", src.ID, derr)
			failed++
			continue
		}
		// A 级源：公钥按固化指纹加载，验签器随源装配。
		// 加载失败必须让该源整体失败——没有验签就不是 A 级，
		// 不能悄悄降级成「HTTPS 拿到了就算数」。
		if src.TrustLevel == domain.TrustLevelA {
			v, verr := feed.LoadKeyFromURL(ctx, u.Fetcher, src.KeyURL, src.PublicKeyFP)
			if verr != nil {
				results = append(results, resultDTO{SourceID: string(src.ID), Error: verr.Error()})
				fmt.Fprintf(e.stderr, "%s：%s\n", src.ID, verr)
				failed++
				continue
			}
			u.Verifier = v
		}

		res, uerr := u.UpdateSource(ctx, src, rel)
		if uerr != nil {
			results = append(results, resultDTO{SourceID: string(src.ID), Release: rel, Error: uerr.Error()})
			fmt.Fprintf(e.stderr, "%s：%s\n", src.ID, uerr)
			failed++
			continue
		}
		dto := resultDTO{
			SourceID: string(res.SourceID), Release: res.Release, Skipped: res.Skipped,
			Reason: res.SkipReason, Snapshot: res.SnapshotID, Advisory: res.Advisories,
			Fixes: res.Fixes, Bad: res.BadRecords, Elapsed: res.Elapsed.String(),
		}
		results = append(results, dto)
		for _, w := range res.Warnings {
			fmt.Fprintf(e.stderr, "  注意：%s\n", w)
		}
		if !res.Skipped {
			fmt.Fprintf(e.stdout, "%s：公告 %d、修复 %d（用时 %s）\n",
				src.ID, res.Advisories, res.Fixes, res.Elapsed.Round(time.Millisecond))
		} else {
			fmt.Fprintf(e.stdout, "%s：%s\n", src.ID, res.SkipReason)
		}
	}

	if asJSON {
		b, _ := json.MarshalIndent(map[string]any{"schema_version": 1, "results": results}, "", "  ")
		fmt.Fprintln(e.stdout, string(b))
	}
	if failed > 0 {
		return exitcode.Error, apperr.Newf(exitcode.Error, "cli.feed", "%d 个情报源更新失败", failed)
	}
	return exitcode.OK, nil
}

// releaseForSource 决定某个源这次要抓哪个 release。
//
// 按 release 分文件的源必须给出 release，否则抓的是别的东西：
// Ubuntu 的 URL 里是 codename，Alpine 是 3.20 形式，两者不可互换。
func (e *env) releaseForSource(ctx context.Context, src feed.Source, override string) (string, error) {
	if !src.NeedRelease {
		return "", nil
	}
	if override != "" {
		return override, nil
	}
	// 没指定时尝试用本机事实推导，推不出来就明确报错，不猜。
	c := e.collector()
	result, err := c.Collect(ctx)
	if err != nil {
		return "", apperr.Wrap(exitcode.Error, "cli.feed",
			fmt.Sprintf("%s 需要 --release 参数（本机事实不可用）", src.ID), err)
	}
	switch src.ID {
	case domain.SourceUbuntuOVAL:
		if result.System.DistroID == domain.DistroUbuntu && result.System.Codename != "" {
			return result.System.Codename, nil
		}
		return "", apperr.Newf(exitcode.Usage, "cli.feed",
			"Ubuntu OVAL 需要 --release <codename>（如 noble）；本机是 %s/%s",
			result.System.DistroID, result.System.Release)
	case domain.SourceAlpineSecDB:
		if result.System.DistroID == domain.DistroAlpine {
			if k := feed.AlpineReleaseKey(result.System.Release); k != "" {
				return k, nil
			}
		}
		return "", apperr.Newf(exitcode.Usage, "cli.feed",
			"Alpine secdb 需要 --release <3.20 形式>；本机是 %s/%s",
			result.System.DistroID, result.System.Release)
	default:
		return "", apperr.Newf(exitcode.Usage, "cli.feed",
			"情报源 %s 需要 --release 参数", src.ID)
	}
}

// runSupport 展示支持矩阵。
func (e *env) runSupport(ctx context.Context, args []string) (exitcode.Code, error) {
	fs := flag.NewFlagSet("support", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage, nil
	}
	now := time.Now().UTC()
	entries := support.Entries()

	if asJSON {
		type dto struct {
			Distro    string `json:"distro"`
			Version   string `json:"version"`
			Codename  string `json:"codename,omitempty"`
			Lifecycle string `json:"lifecycle"`
			EOLDate   string `json:"eol_date,omitempty"`
			AutoFix   bool   `json:"auto_fix"`
			Note      string `json:"note,omitempty"`
		}
		out := make([]dto, 0, len(entries))
		for _, en := range entries {
			d := dto{
				Distro: string(en.Distro), Version: en.Version, Codename: en.Codename,
				Lifecycle: string(support.Lifecycle(en.Distro, en.Version, now)),
				AutoFix:   support.AutoFixAllowed(en.Distro, en.Version, now), Note: en.Note,
			}
			if !en.EOLDate.IsZero() {
				d.EOLDate = en.EOLDate.Format("2006-01-02")
			}
			out = append(out, d)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Distro != out[j].Distro {
				return out[i].Distro < out[j].Distro
			}
			return out[i].Version < out[j].Version
		})
		b, _ := json.MarshalIndent(map[string]any{"schema_version": 1, "entries": out}, "", "  ")
		fmt.Fprintln(e.stdout, string(b))
		return exitcode.OK, nil
	}

	fmt.Fprintf(e.stdout, "%-16s %-10s %-8s %-12s %-8s %s\n",
		"发行版", "版本", "代号", "生命周期", "自动修复", "结束支持")
	for _, en := range entries {
		life := support.Lifecycle(en.Distro, en.Version, now)
		fix := "不开放"
		if support.AutoFixAllowed(en.Distro, en.Version, now) {
			fix = "开放"
		}
		eol := "-"
		if !en.EOLDate.IsZero() {
			eol = en.EOLDate.Format("2006-01-02")
		}
		fmt.Fprintf(e.stdout, "%-16s %-10s %-8s %-12s %-8s %s\n",
			en.Distro, en.Version, en.Codename, life, fix, eol)
	}
	fmt.Fprintln(e.stdout, "\n未列入本表的发行版/版本一律按 unknown 处理：只做只读展示，不给出修复建议。")
	return exitcode.OK, nil
}

// truncateText 按字符截断，避免超长标题撑坏表格。
func truncateText(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n-1]) + "…"
}

// splitFlags 把命令行参数拆成「标志」与「位置参数」。
//
// boolFlags 列出不需要取值的标志，其余带 "-" 的参数按「后面跟一个值」处理；
// 含 "=" 的写法（--since=2026）自身已带值，不再吞下一个参数。
// 这样既能 `feed update --since 2026 rhel-csaf`，也能
// `feed update rhel-csaf --since 2026`。
func splitFlags(args []string, boolFlags map[string]bool) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' {
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		if boolFlags[name] {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, positional
}
