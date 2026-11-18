package exitcode

import "testing"

func TestCodeValues(t *testing.T) {
	cases := []struct {
		code Code
		want int
		name string
	}{
		{OK, 0, "OK"},
		{Error, 1, "ERROR"},
		{Usage, 2, "USAGE"},
		{Findings, 3, "FINDINGS"},
		{Unsupported, 4, "UNSUPPORTED"},
		{Permission, 5, "PERMISSION"},
		{RemediationFailed, 6, "REMEDIATION_FAILED"},
		{Integrity, 7, "INTEGRITY"},
		{NotImplemented, 8, "NOT_IMPLEMENTED"},
		{Interrupted, 130, "INTERRUPTED"},
	}
	for _, c := range cases {
		if c.code.Int() != c.want {
			t.Errorf("%s 退出码应为 %d，实际 %d", c.name, c.want, c.code.Int())
		}
		if got := c.code.String(); got != c.name {
			t.Errorf("String() 应为 %q，实际 %q", c.name, got)
		}
		if !c.code.Valid() {
			t.Errorf("%s 应被识别为合法退出码", c.name)
		}
	}
}

func TestInvalidCode(t *testing.T) {
	c := Code(42)
	if c.Valid() {
		t.Error("42 不应被识别为合法退出码")
	}
	if got := c.String(); got != "CODE_42" {
		t.Errorf("未知退出码应输出 CODE_42，实际 %q", got)
	}
}
