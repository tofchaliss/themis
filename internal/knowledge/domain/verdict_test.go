package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The fail-safe direction is the whole point of the state vocabulary: only an affirmative
// clearance closes an occurrence; every other value — including the empty string a
// pre-feature row decodes to — keeps it live (EDR-VERDICT-01 D2).
func TestVerdictState_IsOpen(t *testing.T) {
	cases := []struct {
		state domain.VerdictState
		open  bool
	}{
		{domain.VerdictOpen, true},
		{domain.VerdictState(""), true},              // pre-feature row / absent field
		{domain.VerdictState("unrecognized"), true},  // future vocabulary from a newer writer
		{domain.VerdictClearedVendorFix, false},
	}
	for _, tc := range cases {
		if got := tc.state.IsOpen(); got != tc.open {
			t.Errorf("VerdictState(%q).IsOpen() = %v, want %v", tc.state, got, tc.open)
		}
	}
}

func TestOpenVerdict(t *testing.T) {
	v := domain.OpenVerdict()
	if v.State != domain.VerdictOpen || v.Grade != "" || v.Reason != "" {
		t.Errorf("OpenVerdict() = %+v, want open/no-grade/no-reason", v)
	}
	if !v.State.IsOpen() {
		t.Error("OpenVerdict must be open")
	}
}

func TestClearedVendorFix(t *testing.T) {
	v := domain.ClearedVendorFix(domain.VerdictGradeObserved, "vendor fix 0:39.2.0-9.el8_10 present (python-setuptools)")
	if v.State != domain.VerdictClearedVendorFix {
		t.Errorf("state = %q, want cleared_vendor_fix", v.State)
	}
	if v.Grade != domain.VerdictGradeObserved {
		t.Errorf("grade = %q, want observed", v.Grade)
	}
	if v.Reason == "" {
		t.Error("a clearance must state its premise")
	}
	if v.State.IsOpen() {
		t.Error("a clearance must not read as open")
	}
}
