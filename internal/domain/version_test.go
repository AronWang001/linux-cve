package domain

import "testing"

// TestVersionRawLossless 固化 P1-2：原始版本串无损保留，String() 优先返回 Raw。
// 覆盖 epoch、dpkg tilde 回移、rpm EVR、apk 修订、pacman pkgrel、预发布标识。
func TestVersionRawLossless(t *testing.T) {
	cases := []Version{
		// dpkg 带 epoch 与 tilde 回移
		{Raw: "1:2.0-1", Epoch: 1, Upstream: "2.0", Release: "1"},
		{Raw: "6.12.113-1~deb12u1", Upstream: "6.12.113", Release: "1~deb12u1"},
		// rpm EVR（epoch 0 可省略）
		{Raw: "0:4.18.0-553.182.1.el8_10", Epoch: 0, Upstream: "4.18.0", Release: "553.182.1.el8_10"},
		{Raw: "4.18.0-553.182.1.el8_10", Epoch: 0, Upstream: "4.18.0", Release: "553.182.1.el8_10"},
		// 预发布标识
		{Raw: "2.0~rc1-1", Upstream: "2.0~rc1", Release: "1"},
		// apk 修订
		{Raw: "6.6.30-r0", Upstream: "6.6.30", Release: "r0"},
		// pacman pkgrel
		{Raw: "6.12.11.arch1-1", Upstream: "6.12.11.arch1", Release: "1"},
		// 仅 Raw 的未解析版本也必须逐字保留
		{Raw: "1:2.0-1~bpo12+1"},
	}
	for _, v := range cases {
		if got := v.String(); got != v.Raw {
			t.Errorf("String() 必须原样返回 Raw：期望 %q，实际 %q", v.Raw, got)
		}
		if v.IsZero() {
			t.Errorf("%q 不应被视为空版本", v.Raw)
		}
	}
}

// TestVersionReconstruction 无 Raw 时按 epoch:upstream-release 重建，但写入 Raw 后 Raw 优先。
func TestVersionReconstruction(t *testing.T) {
	v := Version{Epoch: 1, Upstream: "2.0", Release: "1"}
	if got := v.String(); got != "1:2.0-1" {
		t.Errorf("重建应为 1:2.0-1，实际 %q", got)
	}

	withRaw := v
	withRaw.Raw = "1:2.0-1-custom-alias"
	if got := withRaw.String(); got != "1:2.0-1-custom-alias" {
		t.Errorf("Raw 必须优先，实际 %q", got)
	}

	noEpoch := Version{Upstream: "3.0.11", Release: "1~deb12u2"}
	if got := noEpoch.String(); got != "3.0.11-1~deb12u2" {
		t.Errorf("期望 3.0.11-1~deb12u2，实际 %q", got)
	}

	empty := Version{}
	if !empty.IsZero() || empty.String() != "" {
		t.Error("空版本应 IsZero 且 String 为空")
	}
}

// TestVersionStructurallyEqual 确认 StructurallyEqual 只做判重、不做排序比较。
func TestVersionStructurallyEqual(t *testing.T) {
	a := Version{Epoch: 1, Upstream: "2.0", Release: "1", Raw: "1:2.0-1"}
	b := Version{Epoch: 1, Upstream: "2.0", Release: "1", Raw: "1:2.0-1"}
	if !a.StructurallyEqual(b) {
		t.Error("结构相同的版本应相等")
	}

	c := Version{Epoch: 1, Upstream: "2.0", Release: "2"}
	if a.StructurallyEqual(c) {
		t.Error("不同 release 不应相等")
	}

	// 回移版本在字符串语义下绝不等于正式版本，且本包不提供大小比较
	backport := Version{Raw: "6.12.113-1~deb12u1"}
	official := Version{Raw: "6.12.113-1"}
	if backport.StructurallyEqual(official) {
		t.Error("回移版本与正式版本不应判为相同")
	}
}
