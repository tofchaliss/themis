package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestNewCVEID_NormalizeAndValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want string
	}{
		"canonical":       {"CVE-2024-1234", "CVE-2024-1234"},
		"lowercase":       {"cve-2024-1234", "CVE-2024-1234"},
		"whitespace":      {"  CVE-2024-1234  ", "CVE-2024-1234"},
		"alpineAlias":     {"ALPINE-CVE-2024-1234", "CVE-2024-1234"},
		"distroAliasLow":  {"alpine-cve-2024-1234", "CVE-2024-1234"},
		"longSequential":  {"CVE-2024-1234567", "CVE-2024-1234567"},
	} {
		got, err := value.NewCVEID(tc.in)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", name, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("%s: NewCVEID(%q) = %q, want %q", name, tc.in, got.String(), tc.want)
		}
	}
}

func TestNewCVEID_Invalid(t *testing.T) {
	for name, in := range map[string]string{
		"empty":         "",
		"whitespace":    "   ",
		"nonCVE":        "GHSA-abcd-1234-wxyz",
		"shortYear":     "CVE-24-1",
		"trailingJunk":  "CVE-2024-1234-extra",
		"prefixNoMatch": "FOO-BAR",
	} {
		if got, err := value.NewCVEID(in); err == nil {
			t.Errorf("%s: expected error, got %q", name, got.String())
		}
	}
}

func TestCVEID_Equal_Zero(t *testing.T) {
	a, _ := value.NewCVEID("CVE-2024-1")
	b, _ := value.NewCVEID("alpine-cve-2024-1")
	c, _ := value.NewCVEID("CVE-2024-2")
	if !a.Equal(b) {
		t.Error("canonically-equal CVE ids reported unequal")
	}
	if a.Equal(c) {
		t.Error("different CVE ids reported equal")
	}

	var zero value.CVEID
	if !zero.IsZero() {
		t.Error("zero CVEID should report IsZero")
	}
	if zero.String() != "" {
		t.Errorf("zero CVEID String = %q, want empty", zero.String())
	}
	if a.IsZero() {
		t.Error("constructed CVEID reports IsZero")
	}
}
