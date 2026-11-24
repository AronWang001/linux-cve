package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AronWang001/linux-cve-2026-98432-fix/internal/domain"
)

// UbuntuParser 解析 Ubuntu OVAL（每个 release 一份 bz2 压缩 XML）。
//
// 结构（2026-11-24 实测 noble：11.9MB bz2 → 271MB XML，37,612 条 definition、
// 4,005 条 dpkginfo_test、2,767 条 dpkginfo_object、1,514 条 dpkginfo_state、
// 2,767 条 constant_variable、745,143 条 criterion 引用）：
//
//	<oval_definitions>
//	  <definitions><definition id="...def:2006100020000000" class="vulnerability">
//	    <metadata>...<severity>Medium</severity><public_date>...</public_date>
//	      <cve>...</cve><reference source="USN" .../></metadata>
//	    <criteria>
//	      <extend_definition applicability_check="true" definition_ref="...def:100"/>
//	      <criterion test_ref="...tst:2006100020000000"/>
//	    </criteria>
//	  </definition></definitions>
//	  <tests><linux-def:dpkginfo_test id="...tst:x">
//	    <linux-def:object object_ref="...obj:x"/><linux-def:state state_ref="...ste:x"/>
//	  </linux-def:dpkginfo_test></tests>
//	  <objects><linux-def:dpkginfo_object id="...obj:x">
//	    <linux-def:name var_ref="...var:x"/></linux-def:dpkginfo_object></objects>
//	  <states><linux-def:dpkginfo_state id="...ste:x">
//	    <linux-def:evr datatype="debian_evr_string" operation="less than">2.47-1ubuntu0.24.04.1</linux-def:evr>
//	  </linux-def:dpkginfo_state></states>
//	  <variables><constant_variable id="...var:x"><value>pkg</value>...</constant_variable></variables>
//	</oval_definitions>
//
// 修复版本必须沿 definition → test → object/state → variable 这条链解析出来，
// 不能用 definition 里的 description 文本或 criterion 的 comment 去正则提取：
// 那些是人类可读说明，措辞随时可能改，而 evr 状态是机器可判的语义。
//
// 四个实测事实：
//  1. definition 与 CVE 一一对应（37,611 条 definition、37,611 个不同 CVE），
//     所以一条 definition 就对应一条公告。
//  2. 一条 definition 可含多个 criterion（最多 83 条），代表同一条 CVE
//     在该 release 的多个受影响的包上分别成立。
//  3. constant_variable 可以有多个 <value>（如 gcc-arm-none-eabi 与其
//     -source 二进制包），一个 test 因此可能对应多个包名。
//  4. 只有 1,514 条 state 带 evr，其余 test 没有 state：语义是「装了就算受影响、
//     尚无修复版本」。这类记录只产出公告，不产出修复记录。
type UbuntuParser struct{}

// SourceID 实现 Parser。
func (UbuntuParser) SourceID() domain.SourceID { return domain.SourceUbuntuOVAL }

// Version 实现 Parser。
func (UbuntuParser) Version() string { return ParserVersionUbuntu }

// ubuntuPlatformVersion 从 <platform>Ubuntu 24.04 LTS</platform> 取版本号。
var ubuntuPlatformVersion = regexp.MustCompile(`Ubuntu\s+(\d+\.\d+)`)

// ubuntuCodenameVersion 是 platform 缺失时的兜底映射。
// 新增 codename 时补一行即可，未收录且 platform 也没有会直接报错，不猜。
var ubuntuCodenameVersion = map[string]string{
	"xenial":   "16.04",
	"bionic":   "18.04",
	"focal":    "20.04",
	"jammy":    "22.04",
	"lunar":    "23.04",
	"mantic":   "23.10",
	"noble":    "24.04",
	"oracular": "24.10",
	"plucky":   "25.04",
	"questing": "25.10",
	"resolute": "26.04",
}

// ovalDefinitionXML 是 <definition> 的解码目标。
// description 故意不接收：它单条可达数千字节，解析期用不到。
type ovalDefinitionXML struct {
	ID       string `xml:"id,attr"`
	Class    string `xml:"class,attr"`
	Metadata struct {
		Title  string `xml:"title"`
		Affect struct {
			Platform []string `xml:"platform"`
		} `xml:"affected"`
		Refs []struct {
			Source string `xml:"source,attr"`
			ID     string `xml:"ref_id,attr"`
			URL    string `xml:"ref_url,attr"`
		} `xml:"reference"`
		Advisory struct {
			Severity   string `xml:"severity"`
			PublicDate string `xml:"public_date"`
			CVE        []struct {
				Value string `xml:",chardata"`
			} `xml:"cve"`
		} `xml:"advisory"`
	} `xml:"metadata"`
	Criteria ovalCriteriaXML `xml:"criteria"`
}

// ovalCriteriaXML 递归承载 criteria 树。
type ovalCriteriaXML struct {
	Operator  string             `xml:"operator,attr"`
	Criterion []ovalCriterionXML `xml:"criterion"`
	Extend    []ovalExtendXML    `xml:"extend_definition"`
	Nested    []ovalCriteriaXML  `xml:"criteria"`
}

type ovalCriterionXML struct {
	TestRef string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
}

type ovalExtendXML struct {
	DefRef        string `xml:"definition_ref,attr"`
	Applicability string `xml:"applicability_check,attr"`
}

type ovalTestXML struct {
	ID     string `xml:"id,attr"`
	Object struct {
		Ref string `xml:"object_ref,attr"`
	} `xml:"object"`
	State *struct {
		Ref string `xml:"state_ref,attr"`
	} `xml:"state"`
}

type ovalObjectXML struct {
	ID   string `xml:"id,attr"`
	Name struct {
		VarRef string `xml:"var_ref,attr"`
		Value  string `xml:",chardata"`
	} `xml:"name"`
}

type ovalStateXML struct {
	ID  string `xml:"id,attr"`
	EVR []struct {
		Datatype  string `xml:"datatype,attr"`
		Operation string `xml:"operation,attr"`
		Value     string `xml:",chardata"`
	} `xml:"evr"`
}

type ovalVariableXML struct {
	ID     string   `xml:"id,attr"`
	Values []string `xml:"value"`
}

// ovalTestInfo 是解析后的 test 指向关系。
type ovalTestInfo struct {
	ObjectID int64
	StateID  int64 // 0 表示没有 state
	HasState bool
}

// ovalTables 是一次扫描收集到的全部可引用对象。
//
// 单独拆出来是为了能在测试里直接检查「桥接是否完整」：
// definition 引用的 test 是否存在、object 的包名是否解析得出来。
type ovalTables struct {
	Defs      []ovalDefinitionXML
	Tests     map[int64]ovalTestInfo
	Objects   map[int64]string
	States    map[int64]string
	Variables map[int64][]string
	// NonPackageTests 记录 uname_test / family_test / variable_test 的 id。
	// 它们表达的是「本机内核是否为某 flavor」这类环境条件，不指向任何包，
	// 混进包解析会凭空造出不存在的包名。
	NonPackageTests map[int64]bool
	PlatformVersion string
}

// scanOval 扫一遍 XML，收齐 definition 与 test/object/state/variable。
//
// 必须整份收完再解析：OVAL 的引用全部是 id 引用，且被引用项位于
// definition 之后（tests 在第 200 万行附近）。单遍流式解析无法前瞻。
func scanOval(ctx context.Context, body []byte) (*ovalTables, error) {
	t := &ovalTables{
		Tests:           map[int64]ovalTestInfo{},
		Objects:         map[int64]string{},
		States:          map[int64]string{},
		Variables:       map[int64][]string{},
		NonPackageTests: map[int64]bool{},
	}
	rootSeen := false

	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("feed: Ubuntu OVAL XML 解析失败: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "oval_definitions":
			rootSeen = true
		case "definition":
			var d ovalDefinitionXML
			if err := dec.DecodeElement(&d, &se); err != nil {
				return nil, fmt.Errorf("feed: Ubuntu OVAL definition 解码失败: %w", err)
			}
			// 只有 vulnerability 类定义参与受影响判定；
			// inventory / patch / compliance 类不属于漏洞情报。
			if d.Class != "vulnerability" {
				continue
			}
			t.Defs = append(t.Defs, d)
			if t.PlatformVersion == "" && len(d.Metadata.Affect.Platform) > 0 {
				if m := ubuntuPlatformVersion.FindStringSubmatch(d.Metadata.Affect.Platform[0]); len(m) > 1 {
					t.PlatformVersion = m[1]
				}
			}
		case "dpkginfo_test":
			var x ovalTestXML
			if err := dec.DecodeElement(&x, &se); err != nil {
				return nil, fmt.Errorf("feed: Ubuntu OVAL test 解码失败: %w", err)
			}
			info := ovalTestInfo{ObjectID: scalarID(x.Object.Ref)}
			if x.State != nil {
				info.StateID = scalarID(x.State.Ref)
				info.HasState = info.StateID != 0
			}
			t.Tests[scalarID(x.ID)] = info
		case "dpkginfo_object":
			var o ovalObjectXML
			if err := dec.DecodeElement(&o, &se); err != nil {
				return nil, fmt.Errorf("feed: Ubuntu OVAL object 解码失败: %w", err)
			}
			if o.Name.VarRef != "" {
				// 变量可能出现在文档更后面，先记引用，解析阶段再展开。
				t.Objects[scalarID(o.ID)] = "\x00var:" + o.Name.VarRef
			} else {
				t.Objects[scalarID(o.ID)] = strings.TrimSpace(o.Name.Value)
			}
		case "dpkginfo_state":
			var x ovalStateXML
			if err := dec.DecodeElement(&x, &se); err != nil {
				return nil, fmt.Errorf("feed: Ubuntu OVAL state 解码失败: %w", err)
			}
			if v, ok := ubuntuFixedVersion(x); ok {
				t.States[scalarID(x.ID)] = v
			}
		case "constant_variable":
			var v ovalVariableXML
			if err := dec.DecodeElement(&v, &se); err != nil {
				return nil, fmt.Errorf("feed: Ubuntu OVAL variable 解码失败: %w", err)
			}
			vals := make([]string, 0, len(v.Values))
			for _, s := range v.Values {
				if val := strings.TrimSpace(s); val != "" {
					vals = append(vals, val)
				}
			}
			t.Variables[scalarID(v.ID)] = vals
		default:
			// 其余 *Test 类型（uname/family/variable…）只表达环境条件。
			// 只需要它们的 id，据此在解析阶段区分「环境条件」与「桥接失败」。
			if strings.HasSuffix(se.Name.Local, "_test") {
				var x struct {
					ID string `xml:"id,attr"`
				}
				if err := dec.DecodeElement(&x, &se); err != nil {
					return nil, fmt.Errorf("feed: Ubuntu OVAL test 解码失败: %w", err)
				}
				if id := scalarID(x.ID); id != 0 {
					t.NonPackageTests[id] = true
				}
			}
		}
	}

	if !rootSeen {
		return nil, fmt.Errorf("feed: Ubuntu OVAL 根元素不是 oval_definitions")
	}
	if len(t.Defs) == 0 {
		return nil, fmt.Errorf("feed: Ubuntu OVAL 未解析到任何 vulnerability definition")
	}
	return t, nil
}

// Parse 实现 Parser。
func (p UbuntuParser) Parse(ctx context.Context, in ParseInput) (*ParseResult, error) {
	body := in.Body
	if len(body) == 0 {
		body = in.Files[""]
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("feed: Ubuntu OVAL 解析缺少内容")
	}
	codename := strings.TrimSpace(in.Release)
	if codename == "" {
		return nil, fmt.Errorf("feed: Ubuntu OVAL 解析缺少 codename")
	}

	tables, err := scanOval(ctx, body)
	if err != nil {
		return nil, err
	}

	// release 坐标：优先用 platform 声明的版本号，缺失时回退 codename 映射。
	version := tables.PlatformVersion
	if version == "" {
		version = ubuntuCodenameVersion[codename]
	}
	if version == "" {
		return nil, fmt.Errorf("feed: Ubuntu OVAL 无法确定 %s 的版本号（platform 缺失且 codename 未收录）", codename)
	}

	res := &ParseResult{}
	res.Guard = GuardStats{InputBytes: int64(len(body)), DecodedBytes: int64(len(body))}
	res.Releases = []ReleaseRef{{DistroID: domain.DistroUbuntu, Release: version, Codename: codename}}

	for _, d := range tables.Defs {
		p.parseIntDefinition(d, version, tables, in, res)
	}

	if maxErrorRate(res.Skipped, len(tables.Defs)+res.Skipped) {
		return nil, fmt.Errorf("%w: Ubuntu OVAL 异常记录 %d/%d 超过阈值 %.0f%%",
			ErrUnsafeInput, res.Skipped, len(tables.Defs)+res.Skipped, DefaultMaxErrorRate*100)
	}
	return res, nil
}

// parseIntDefinition 处理一条 definition，产出 1 条公告与 0..n 条修复记录。
func (p UbuntuParser) parseIntDefinition(d ovalDefinitionXML, version string,
	tables *ovalTables, in ParseInput, res *ParseResult) {

	cveStr := ubuntuDefCVE(d)
	if cveStr == "" {
		res.Skipped++
		res.warn("%s 缺少 CVE 编号", d.ID)
		return
	}
	cve := domain.CVEID(cveStr)
	if !cve.Valid() {
		res.Skipped++
		res.warn("%s 的 CVE 编号非法: %q", d.ID, cveStr)
		return
	}

	advisoryID := fmt.Sprintf("%s/%s", cveStr, version)
	uid := domain.AdvisoryUID(domain.SourceUbuntuOVAL, advisoryID, cve)

	var issued *time.Time
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(d.Metadata.Advisory.PublicDate)); err == nil {
		issued = &t
	}

	// 逐条 criterion 解析出包与修复版本。
	var targets []ubuntuFixTarget
	unresolved := 0
	bridgeFailed := 0

	refs := make([]int64, 0, 4)
	int64Refs := make(map[int64]bool, 4)
	var walk func(c ovalCriteriaXML)
	walk = func(c ovalCriteriaXML) {
		for _, cr := range c.Criterion {
			id := scalarID(cr.TestRef)
			if id == 0 || int64Refs[id] {
				continue
			}
			int64Refs[id] = true
			refs = append(refs, id)
		}
		for _, e := range c.Extend {
			// applicability_check 只是「本机是否为该发行版」的前置判断，
			// 不是受影响条件，必须排除，否则每个 CVE 都会错误地关联到
			// 平台检查定义上。
			if strings.EqualFold(e.Applicability, "true") {
				continue
			}
			unresolved++
		}
		for _, n := range c.Nested {
			walk(n)
		}
	}
	walk(d.Criteria)
	if unresolved > 0 {
		res.warn("%s 含有 %d 个未展开的 extend_definition（桥接未解析）", d.ID, unresolved)
	}

	sort.Slice(refs, func(i, j int) bool { return refs[i] < refs[j] })

	envRefs := 0
	for _, ref := range refs {
		info, ok := tables.Tests[ref]
		if !ok {
			if tables.NonPackageTests[ref] {
				// uname/family/variable 这类 test 是环境条件，不指向包。
				envRefs++
				continue
			}
			// 引用了根本不存在的 test。实测 noble 有 298 个这样的悬空引用，
			// 属于上游数据缺失，不是我们解析失败：计入桥接失败并如实告警。
			bridgeFailed++
			res.warn("%s 引用了不存在的 test %d（上游数据缺失）", d.ID, ref)
			continue
		}
		names := ovalObjectNames(tables.Objects[info.ObjectID], tables.Variables)
		if len(names) == 0 {
			bridgeFailed++
			res.warn("%s 的 test %d 无法解析出包名", d.ID, ref)
			continue
		}
		fixed := ""
		if info.HasState {
			fixed = tables.States[info.StateID]
		}
		for _, name := range names {
			targets = append(targets, ubuntuFixTarget{Package: name, Version: fixed})
		}
	}
	targets = mergeUbuntuTargets(targets)

	// 解析不出包不代表这条记录不存在：CVE 编号、严重程度、发布时间、
	// USN 链接都是真实事实，只是缺少包级细节。丢掉它会让「该 CVE 影响
	// 本 release」这条信息消失，比保留一条无修复记录的公告危险得多。
	vendorStatus := ubuntuUnresolvedStatus
	if len(targets) > 0 {
		vendorStatus = "affected-no-fix"
	}
	hasFix := false
	for _, t := range targets {
		if t.Version != "" {
			hasFix = true
			break
		}
	}
	if hasFix {
		vendorStatus = "fixed"
	}
	if len(targets) == 0 {
		res.BridgeFailed++
		if envRefs > 0 {
			res.warn("%s 的条件全部是内核/环境判断（%d 条），没有包级信息", d.ID, envRefs)
		}
	}

	url := ""
	for _, r := range d.Metadata.Refs {
		if r.Source == "USN" && r.URL != "" {
			url = r.URL
			break
		}
	}
	if url == "" {
		url = "https://ubuntu.com/security/" + cveStr
	}

	res.Advisories = append(res.Advisories, domain.Advisory{
		UID:            uid,
		SourceID:       domain.SourceUbuntuOVAL,
		AdvisoryID:     advisoryID,
		CVEID:          cve,
		Title:          "",
		Severity:       ubuntuSeverity(d.Metadata.Advisory.Severity),
		SeveritySource: "ubuntu-oval",
		IssuedAt:       issued,
		URL:            url,
		FetchedAt:      in.FetchedAt,
		ArtifactSHA256: in.ArtifactSHA,
		RawLocator:     d.ID,
		RawRecordHash:  hashUbuntuDefinition(d, targets),
		ParserVersion:  ParserVersionUbuntu,
		VendorStatus:   vendorStatus,
	})

	for _, t := range targets {
		if t.Version == "" {
			// 无 evr 状态：装了即受影响且尚无修复版本，
			// 不能凭空给一个版本号让匹配器去比较。
			continue
		}
		res.Fixes = append(res.Fixes, domain.AdvisoryFix{
			AdvisoryUID: uid,
			SourceID:    domain.SourceUbuntuOVAL,
			AdvisoryID:  advisoryID,
			CVEID:       cve,
			DistroID:    domain.DistroUbuntu,
			Release:     version,
			// OVAL 不说明修复来自哪个 pocket（-security / -updates），
			// 记 any 表示「任一已启用仓库」，不猜具体来源。
			Channel: "any",
			Ref: domain.PackageRef{
				// dpkginfo 针对的是可安装的二进制包。
				Kind: domain.PackageKindBinary,
				Name: t.Package,
				Arch: domain.ArchAny,
			},
			FixedVersion:       t.Version,
			FixedVersionSource: domain.FixVersionOfficial,
			EvidenceURL:        url,
		})
	}
}

// ubuntuFixedVersion 从 state 中取出「小于该版本即受影响」的版本号。
//
// 只接受 evr 的 less than：那是 OVAL 表达「首次修复版本」的标准写法。
// 其他 operation（equals / greater than 等）语义不同，不得当成修复版本。
func ubuntuFixedVersion(s ovalStateXML) (string, bool) {
	for _, e := range s.EVR {
		op := strings.ToLower(strings.TrimSpace(e.Operation))
		if op != "less than" && op != "lessthan" {
			continue
		}
		v := strings.TrimSpace(e.Value)
		if v == "" {
			continue
		}
		return v, true
	}
	return "", false
}

// ovalObjectNames 把 object 的 name 展开为包名列表。
//
// name 可能是 var_ref 指向 constant_variable（可有多个 value），
// 也可能是内联文本。变量未收录时返回空，由调用方计入异常。
func ovalObjectNames(name string, variables map[int64][]string) []string {
	if strings.HasPrefix(name, "\x00var:") {
		id := scalarID(strings.TrimPrefix(name, "\x00var:"))
		vals := variables[id]
		out := make([]string, 0, len(vals))
		seen := map[string]bool{}
		for _, v := range vals {
			if seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
		return out
	}
	if name == "" {
		return nil
	}
	return []string{name}
}

// ubuntuDefCVE 从 definition 取 CVE 编号。
// 优先取 advisory/cve 的文本（Canonical 自己的字段），
// 缺失时回退到 reference source="CVE"。
func ubuntuDefCVE(d ovalDefinitionXML) string {
	for _, c := range d.Metadata.Advisory.CVE {
		if v := strings.TrimSpace(c.Value); v != "" {
			return v
		}
	}
	for _, r := range d.Metadata.Refs {
		if r.Source == "CVE" && r.ID != "" {
			return strings.TrimSpace(r.ID)
		}
	}
	return ""
}

// ubuntuSeverity 把 Canonical 的严重程度映射到统一取值。
func ubuntuSeverity(s string) domain.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low", "negligible":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

// ubuntuUnresolvedStatus 表示「已知该 CVE 影响本 release，但包级细节未能解析」。
//
// 它和 affected-no-fix 必须分开：后者是「确认有包受影响、发布方尚未给出修复
// 版本」，前者是「我们没能把 OVAL 的引用链解开」。混成一个值会让报告读者
// 误以为发布方没有修复方案。
const ubuntuUnresolvedStatus = "unresolved"

// ubuntuFixTarget 是「某包在某版本开始不再受影响」。
type ubuntuFixTarget struct {
	Package string
	Version string
}

// mergeUbuntuTargets 按包名归并，后者覆盖前者，并保证输出顺序稳定。
//
// 同一条 definition 里同一个包既可能出现在「有 evr 状态」的 test 中，
// 也可能出现在「仅检查存在」的 test 中；不归并会同时产出「已修复」
// 与「无修复」两条互相矛盾的结论。
func mergeUbuntuTargets(in []ubuntuFixTarget) []ubuntuFixTarget {
	merged := map[string]string{}
	order := make([]string, 0, len(in))
	for _, t := range in {
		if _, ok := merged[t.Package]; !ok {
			order = append(order, t.Package)
		}
		// 非空版本优先：有明确修复版本的结论强于「没有修复版本」。
		if t.Version != "" || merged[t.Package] == "" {
			merged[t.Package] = t.Version
		}
	}
	sort.Strings(order)
	out := make([]ubuntuFixTarget, 0, len(order))
	for _, pkg := range order {
		out = append(out, ubuntuFixTarget{Package: pkg, Version: merged[pkg]})
	}
	return out
}

// hashUbuntuDefinition 计算单条 definition 的归一化内容哈希。
func hashUbuntuDefinition(d ovalDefinitionXML, targets []ubuntuFixTarget) string {
	var sb strings.Builder
	sb.WriteString(d.ID)
	sb.WriteByte('|')
	sb.WriteString(d.Metadata.Advisory.Severity)
	sb.WriteByte('|')
	sb.WriteString(d.Metadata.Advisory.PublicDate)
	for _, t := range targets {
		sb.WriteByte('|')
		sb.WriteString(t.Package)
		sb.WriteByte('=')
		sb.WriteString(t.Version)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// scalarID 取 OVAL id 末尾的数字部分作为紧凑键。
//
// 形如 oval:com.ubuntu.noble:tst:200224390000000。用 int64 而不是保留整串，
// 是因为 noble 一份文件里有 74 万条 criterion 引用，保留字符串会多占几十 MB。
// 无法解析时返回 0，由调用方计入异常，不做猜测。
func scalarID(id string) int64 {
	s := strings.TrimSpace(id)
	if s == "" {
		return 0
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		s = s[i+1:]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
