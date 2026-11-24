package feed

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/AronWang001/linux-cve/internal/domain"
)

// PGPVerifier 校验 A 级情报源的分离签名（.asc），并钉死签名者指纹。
//
// 设计约束：A 级信任建立在「厂商用私钥签发过这份字节」上。
// 指纹必须来自固定配置（Red Hat 的 provider-metadata.json、
// SUSE 的 security-automation.asc），不得在运行时接受「谁签的都行」——
// 那样只要拿到任意一把密钥就能冒充厂商。
type PGPVerifier struct {
	ring   openpgp.EntityList
	wantFP string
}

// NewPGPVerifier 用 armored 公钥环与固化指纹构造校验器。
//
// 指纹必须已在密钥环中：配置写错时应当立刻失败，
// 而不是等第一次同步才发现「所有文档都验签失败」。
func NewPGPVerifier(armoredKey []byte, wantFP string) (*PGPVerifier, error) {
	fp := normalizeFingerprint(wantFP)
	if fp == "" {
		return nil, fmt.Errorf("feed: A 级源未固化签名指纹，拒绝构造校验器")
	}
	if len(armoredKey) == 0 {
		return nil, fmt.Errorf("feed: 签名校验器缺少公钥内容")
	}
	// 厂商发布的公钥多为 armored，但二进制格式同样合法；
	// 两种都接受，避免因为编码形式不同就判定「公钥坏了」。
	ring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(armoredKey))
	if err != nil {
		ring, err = openpgp.ReadKeyRing(bytes.NewReader(armoredKey))
	}
	if err != nil {
		return nil, fmt.Errorf("feed: 解析 OpenPGP 公钥失败: %w", err)
	}
	for _, e := range ring {
		if normalizeFingerprint(fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)) == fp {
			return &PGPVerifier{ring: ring, wantFP: fp}, nil
		}
	}
	got := make([]string, 0, len(ring))
	for _, e := range ring {
		got = append(got, fmt.Sprintf("%X", e.PrimaryKey.Fingerprint))
	}
	return nil, fmt.Errorf("feed: 公钥环中找不到固化指纹 %s（实际包含：%s）",
		fp, strings.Join(got, ", "))
}

// VerifyDetached 实现 Verifier。
//
// 返回 SignatureVerified 当且仅当「字节未被篡改，且签名者就是那把固化的钥匙」。
// 其他情况一律 SignatureFailed + error：签名过期、指纹不符、格式错误，
// 都按「未通过」处理，不允许降级成「无签名但继续」。
func (v *PGPVerifier) VerifyDetached(_ context.Context, _ Source,
	data, sig []byte) (domain.SignatureStatus, string, error) {

	if len(sig) == 0 {
		return domain.SignatureFailed, "缺少签名文件", fmt.Errorf("feed: 缺少签名文件")
	}
	cfg := &packet.Config{Time: time.Now}
	signer, err := openpgp.CheckArmoredDetachedSignature(
		v.ring, bytes.NewReader(data), bytes.NewReader(sig), cfg)
	if err != nil {
		return domain.SignatureFailed, "签名校验失败", fmt.Errorf("feed: 签名校验失败: %w", err)
	}
	got := normalizeFingerprint(fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint))
	if got != v.wantFP {
		return domain.SignatureFailed,
			"签名者指纹 " + got + " 与固化指纹 " + v.wantFP + " 不符",
			fmt.Errorf("feed: 签名者指纹不符")
	}
	return domain.SignatureVerified, "签名者 " + got, nil
}

// Fingerprint 返回固化指纹，用于日志与报告。
func (v *PGPVerifier) Fingerprint() string { return v.wantFP }

// LoadKeyFromURL 抓取公钥并按固化指纹构造校验器。
//
// 公钥本身走 HTTPS 取回，但只有指纹匹配才可用：即使中间人换掉了公钥，
// 指纹不符也会立刻失败。这正是 CSAF 2.0 用 provider-metadata.json
// 声明指纹、再由我们固化一份的原因。
func LoadKeyFromURL(ctx context.Context, f *Fetcher, keyURL, wantFP string) (*PGPVerifier, error) {
	if f == nil {
		return nil, fmt.Errorf("feed: 缺少抓取器，无法加载公钥")
	}
	res, err := f.Get(ctx, keyURL, FetchOptions{MaxBytes: DefaultMaxBytes})
	if err != nil {
		return nil, fmt.Errorf("feed: 抓取公钥失败: %w", err)
	}
	return NewPGPVerifier(res.Body, wantFP)
}

// normalizeFingerprint 去掉空格与分隔符并统一大写，便于比较。
//
// 指纹的不同写法（带空格、小写、0x 前缀）在配置里都出现过，
// 比较前必须先归一，否则会因书写差异误判为「换钥」。
func normalizeFingerprint(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			// 数字必须原样保留：曾经把数字也减 32，结果 77E79ABE…
			// 这类含数字的指纹被算成控制字符，永远匹配不上。
			b.WriteRune(r)
		case r >= 'a' && r <= 'f':
			b.WriteRune(r - 32)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r)
		}
	}
	return b.String()
}
