package version

import (
	"strings"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// Alpine / apk 版本比较：忠实移植 apk-tools src/version.c 的 tokenizer
// 与 apk_version_compare（非 fuzzy 路径）。
//
// 语法（上游注释）：digit{.digit}...{letter}{_suf{#}}...{~hash}{-r#}
//   - 无 epoch 概念（apk 管道里没有 ':' 分隔符，含 ':' 一律非法）；
//   - 预发布后缀 _alpha/_beta/_pre/_rc 排序早于无后缀版本；
//   - _cvs/_svn/_git/_hg/_p 与 _pN（补丁）排序晚于无后缀版本；
//   - ~hexhash 为提交哈希标记；-rN 为修订号，必须位于末尾；
//   - 数字段含前导零时退化为原始串比较（Gentoo 风格）。
//
// 枚举序号是排序语义的一部分（token 种类数值越大越「新」的终局规则、
// suffix 数值决定预/后发布），移植时不得重排。

// apk token 种类，序号与上游 enum 严格一致。
const (
	apkTokenInitialDigit = iota // 0
	apkTokenDigit               // 1
	apkTokenLetter              // 2
	apkTokenSuffix              // 3
	apkTokenSuffixNo            // 4
	apkTokenCommitHash          // 5
	apkTokenRevisionNo          // 6
	apkTokenEnd                 // 7
	apkTokenInvalid             // 8
)

// apk 后缀等级，序号与上游 enum 严格一致（NONE 是预/后发布分界）。
const (
	apkSuffixInvalid = iota // 0
	apkSuffixAlpha          // 1
	apkSuffixBeta           // 2
	apkSuffixPre            // 3
	apkSuffixRC             // 4
	apkSuffixNone           // 5
	apkSuffixCVS            // 6
	apkSuffixSVN            // 7
	apkSuffixGIT            // 8
	apkSuffixHG             // 9
	apkSuffixP              // 10
)

// apkToken 是一个已解析的语法单元。
type apkToken struct {
	kind   int
	suffix int    // 仅 TOKEN_SUFFIX 有效
	number uint64 // 数字类 token 的数值
	value  string // 原始片段（前导零比较与调试用）
}

// apkParser 是流式 tokenizer 状态。
type apkParser struct {
	s    string
	pos  int
	prev int // 上一 token 种类
}

// apkSuffixValue 按上游 suffix_value() 解析后缀名。
// 先按首字母定位候选，再做全串精确匹配；空串与不匹配一律非法。
func apkSuffixValue(suf string) int {
	if suf == "" {
		return apkSuffixInvalid
	}
	var val int
	switch suf[0] {
	case 'a':
		val = apkSuffixAlpha
	case 'b':
		val = apkSuffixBeta
	case 'c':
		val = apkSuffixCVS
	case 'g':
		val = apkSuffixGIT
	case 'h':
		val = apkSuffixHG
	case 'p':
		if len(suf) > 1 {
			val = apkSuffixPre
		} else {
			val = apkSuffixP
		}
	case 'r':
		val = apkSuffixRC
	case 's':
		val = apkSuffixSVN
	default:
		return apkSuffixInvalid
	}
	want := map[int]string{
		apkSuffixAlpha: "alpha",
		apkSuffixBeta:  "beta",
		apkSuffixPre:   "pre",
		apkSuffixRC:    "rc",
		apkSuffixCVS:   "cvs",
		apkSuffixSVN:   "svn",
		apkSuffixGIT:   "git",
		apkSuffixHG:    "hg",
		apkSuffixP:     "p",
	}[val]
	if want != suf {
		return apkSuffixInvalid
	}
	return val
}

// parseAPKDigits 解析十进制数字段；无数字或溢出 → INVALID。
func (p *apkParser) parseDigits(t *apkToken) {
	start := p.pos
	for p.pos < len(p.s) && isDigit(p.s[p.pos]) {
		p.pos++
	}
	if p.pos == start {
		t.kind = apkTokenInvalid
		t.value = ""
		return
	}
	t.value = p.s[start:p.pos]
	n := uint64(0)
	for i := 0; i < len(t.value); i++ {
		d := uint64(t.value[i] - '0')
		if n > (^uint64(0)-d)/10 { // 与 apk_blob_pull_uint 一致：溢出即非法
			t.kind = apkTokenInvalid
			t.value = ""
			return
		}
		n = n*10 + d
	}
	t.number = n
}

// first 强制起始 token 为数字段（版本必须以数字开头）。
func (p *apkParser) first() apkToken {
	t := apkToken{kind: apkTokenInitialDigit}
	p.parseDigits(&t)
	p.prev = t.kind
	return t
}

// next 按上游 token_next() 的状态机取下一个 token。
func (p *apkParser) next() apkToken {
	if p.pos >= len(p.s) {
		p.prev = apkTokenEnd
		return apkToken{kind: apkTokenEnd}
	}
	var t apkToken
	switch c := p.s[p.pos]; {
	case c >= 'a' && c <= 'z':
		if p.prev > apkTokenDigit {
			t.kind = apkTokenInvalid
			break
		}
		t.kind = apkTokenLetter
		t.value = p.s[p.pos : p.pos+1]
		p.pos++
	case c == '.':
		if p.prev > apkTokenDigit {
			t.kind = apkTokenInvalid
			break
		}
		p.pos++
		// 落入数字分支（上游 fallthrough）
		fallthrough
	case c >= '0' && c <= '9':
		switch p.prev {
		case apkTokenInitialDigit, apkTokenDigit:
			t.kind = apkTokenDigit
		case apkTokenSuffix:
			t.kind = apkTokenSuffixNo
		default:
			t.kind = apkTokenInvalid
			break
		}
		if t.kind == apkTokenInvalid {
			break
		}
		p.parseDigits(&t)
	case c == '_':
		if p.prev > apkTokenSuffixNo {
			t.kind = apkTokenInvalid
			break
		}
		p.pos++
		start := p.pos
		for p.pos < len(p.s) && p.s[p.pos] >= 'a' && p.s[p.pos] <= 'z' {
			p.pos++
		}
		t.value = p.s[start:p.pos]
		t.suffix = apkSuffixValue(t.value)
		if t.suffix == apkSuffixInvalid {
			t.kind = apkTokenInvalid
			break
		}
		t.kind = apkTokenSuffix
	case c == '~':
		if p.prev >= apkTokenCommitHash {
			t.kind = apkTokenInvalid
			break
		}
		p.pos++
		start := p.pos
		for p.pos < len(p.s) && isHexDigit(p.s[p.pos]) {
			p.pos++
		}
		if p.pos == start {
			t.kind = apkTokenInvalid
			break
		}
		t.kind = apkTokenCommitHash
		t.value = p.s[start:p.pos]
	case c == '-':
		if p.prev >= apkTokenRevisionNo {
			t.kind = apkTokenInvalid
			break
		}
		if !strings.HasPrefix(p.s[p.pos:], "-r") {
			t.kind = apkTokenInvalid
			break
		}
		p.pos += 2
		t.kind = apkTokenRevisionNo
		p.parseDigits(&t)
		if t.kind == apkTokenInvalid {
			break
		}
	default:
		t.kind = apkTokenInvalid
	}
	p.prev = t.kind
	return t
}

// isHexDigit 判断十六进制数字（~hash 片段字符类）。
func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// apkVersionValid 对应 apk_version_validate：完整走到 END 才算合法。
func apkVersionValid(s string) bool {
	if s == "" {
		return false
	}
	p := &apkParser{s: s}
	for t := p.first(); t.kind < apkTokenEnd; t = p.next() {
		if t.kind == apkTokenInvalid {
			return false
		}
	}
	return p.prev == apkTokenEnd
}

// apkBlobSort 对应 apk_blob_sort：先按公共长度逐字节比较，再比长度。
func apkBlobSort(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// apkTokenCmp 对应 token_cmp：按 token 种类选择数值 / 字符 / 后缀级 / 串比较。
func apkTokenCmp(ta, tb *apkToken) int {
	switch ta.kind {
	case apkTokenDigit:
		if strings.HasPrefix(ta.value, "0") || strings.HasPrefix(tb.value, "0") {
			// 前导零：退化为原始串比较（Gentoo 风格）
			return apkBlobSort(ta.value, tb.value)
		}
		fallthrough
	case apkTokenInitialDigit, apkTokenSuffixNo, apkTokenRevisionNo:
		switch {
		case ta.number < tb.number:
			return -1
		case ta.number > tb.number:
			return 1
		default:
			return 0
		}
	case apkTokenLetter:
		switch {
		case ta.value[0] < tb.value[0]:
			return -1
		case ta.value[0] > tb.value[0]:
			return 1
		default:
			return 0
		}
	case apkTokenSuffix:
		switch {
		case ta.suffix < tb.suffix:
			return -1
		case ta.suffix > tb.suffix:
			return 1
		default:
			return 0
		}
	default:
		return apkBlobSort(ta.value, tb.value)
	}
}

// ParseAPK 解析 Alpine 版本串，Raw 逐字保留。
// Upstream 为 -rN 之前的部分（不含 epoch），Release 为 rN 形式。
func ParseAPK(raw string) (domain.Version, error) {
	if raw == "" {
		return domain.Version{}, versionErr("apk", "版本串为空")
	}
	if hasSpace(raw) {
		return domain.Version{}, versionErr("apk", "版本串含空白字符: %q", raw)
	}
	if strings.Contains(raw, ":") {
		return domain.Version{}, versionErr("apk", "apk 版本不含 epoch，发现 ':': %q", raw)
	}
	if !apkVersionValid(raw) {
		return domain.Version{}, versionErr("apk", "版本串不符合 apk 语法: %q", raw)
	}

	// 语法保证 '-' 只可能是末尾 -rN（其余位置的 '-' 均使 token 失效）
	upstream, release := raw, ""
	if i := strings.Index(raw, "-"); i >= 0 {
		upstream = raw[:i]
		release = raw[i+1:] // 形如 r0
	}
	return domain.Version{
		Raw:      raw,
		Epoch:    0,
		Upstream: upstream,
		Release:  release,
	}, nil
}

// CompareAPK 按 apk_version_compare 规则比较两个版本串，返回 -1 / 0 / 1。
func CompareAPK(a, b string) (int, error) {
	va, err := ParseAPK(a)
	if err != nil {
		return 0, err
	}
	vb, err := ParseAPK(b)
	if err != nil {
		return 0, err
	}
	return CompareAPKVersion(va, vb), nil
}

// CompareAPKVersion 比较已解析的 Alpine 版本（以完整原始串做语法级比较）。
func CompareAPKVersion(a, b domain.Version) int {
	return apkVersionCompare(a.String(), b.String())
}

// apkVersionCompare 对应 apk_version_compare（非 fuzzy）。
func apkVersionCompare(a, b string) int {
	pa := &apkParser{s: a}
	pb := &apkParser{s: b}
	ta := pa.first()
	tb := pb.first()

	for ta.kind == tb.kind && ta.kind < apkTokenEnd {
		if r := apkTokenCmp(&ta, &tb); r != 0 {
			return r
		}
		ta = pa.next()
		tb = pb.next()
	}

	if ta.kind == tb.kind {
		return 0
	}
	// 预发布后缀（alpha/beta/pre/rc）：带后缀者更旧
	if ta.kind == apkTokenSuffix && ta.suffix < apkSuffixNone {
		return -1
	}
	if tb.kind == apkTokenSuffix && tb.suffix < apkSuffixNone {
		return 1
	}
	// 终局规则：token 种类数值更大者更「新」但排序更靠后？
	// 上游：if (ta.token > tb.token) return LESS;（END > 其他 → 有修订/后缀者胜）
	if ta.kind > tb.kind {
		return -1
	}
	if tb.kind > ta.kind {
		return 1
	}
	return 0
}
