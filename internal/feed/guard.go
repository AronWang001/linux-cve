package feed

import (
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
)

// ErrUnsafeInput 表示输入触发了防护阈值（超深嵌套、压缩炸弹等）。
// 这类失败一律整批拒绝，不做「尽量解析」。
var ErrUnsafeInput = errors.New("feed: 输入超出安全限制")

// CheckJSONDepth 扫描原始 JSON 字节并返回最大嵌套深度。
//
// 只统计结构括号，跳过字符串内容与转义序列，
// 因此 "}{\" 之类的文本不会被误计为结构。
// 原始字节可能来自网络，必须按不可信输入处理。
func CheckJSONDepth(data []byte, max int) (int, error) {
	depth, maxSeen := 0, 0
	inString, escaped := false, false
	for _, c := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > maxSeen {
				maxSeen = depth
			}
			if max > 0 && depth > max {
				return maxSeen, fmt.Errorf("%w: JSON 嵌套深度超过 %d 层", ErrUnsafeInput, max)
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return maxSeen, nil
}

// Decompress 解压 gzip / bzip2，未压缩输入原样返回。
//
// 两道限制同时生效：
//   - 绝对体积上限（默认 MaxExpandedBytes）
//   - 解压比上限（默认 MaxExpandRatio）
//
// 前者防「解压后炸内存」，后者防「压缩比异常」。注意真实数据的比率
// 可以到 24:1（Ubuntu OVAL），阈值按实测设定，不按直觉设定。
func Decompress(data []byte, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxExpandedBytes
	}
	var r io.Reader
	switch {
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("%w: gzip 头损坏: %v", ErrUnsafeInput, err)
		}
		defer func() { _ = gr.Close() }()
		r = gr
	case len(data) >= 3 && data[0] == 'B' && data[1] == 'Z' && data[2] == 'h':
		r = bzip2.NewReader(bytes.NewReader(data))
	default:
		// 未压缩：仍受绝对体积约束，避免有人塞一个 600MB 明文。
		if int64(len(data)) > maxBytes {
			return nil, fmt.Errorf("%w: 明文体积 %d 超过上限 %d", ErrTooLarge, len(data), maxBytes)
		}
		return data, nil
	}

	// 多读 1 字节用于判断是否超限，避免刚好等于上限时的误判。
	out, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: 解压失败: %v", ErrUnsafeInput, err)
	}
	if int64(len(out)) > maxBytes {
		return nil, fmt.Errorf("%w: 解压后体积超过 %d 字节", ErrTooLarge, maxBytes)
	}
	if len(data) > 0 && MaxExpandRatio > 0 {
		if int64(len(out)) > int64(len(data))*MaxExpandRatio {
			return nil, fmt.Errorf("%w: 解压比 %d:1 超过上限 %d:1",
				ErrUnsafeInput, len(out)/len(data), MaxExpandRatio)
		}
	}
	return out, nil
}

// GuardStats 记录一次解析的安全检查结果，进快照统计供排查。
type GuardStats struct {
	MaxDepth     int
	InputBytes   int64
	DecodedBytes int64
	Skipped      int
}

// minErrorSample 是应用比例阈值的样本量下限。
//
// 样本太小时比例没有统计意义：4 条里 1 条异常就是 25%，但那是脏数据，
// 不是格式漂移。低于该值时只拦「过半异常」，避免正常的小规模源被误杀
// （例如只有几十条记录的情报源）。
const minErrorSample = 100

// maxErrorRate 计算异常记录比例是否超阈值。
// 超阈值意味着「格式变了」而不是「个别脏数据」，必须整批拒绝，
// 否则会把残缺情报写进库，导致漏判。
func maxErrorRate(skipped, total int) bool {
	if total <= 0 {
		return false
	}
	if total < minErrorSample {
		return skipped*2 > total
	}
	return float64(skipped)/float64(total) > DefaultMaxErrorRate
}
