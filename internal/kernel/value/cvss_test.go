package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestNewCVSS_Valid(t *testing.T) {
	c, err := value.NewCVSS(9.8, "  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  ")
	if err != nil {
		t.Fatalf("valid cvss: %v", err)
	}
	if c.Score() != 9.8 {
		t.Errorf("Score = %v, want 9.8", c.Score())
	}
	if c.Vector() != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("Vector not trimmed: %q", c.Vector())
	}
	if c.Severity() != value.SeverityCritical {
		t.Errorf("Severity = %q, want critical", c.Severity())
	}
	if c.IsZero() {
		t.Error("constructed cvss reports IsZero")
	}
}

func TestNewCVSS_Invalid(t *testing.T) {
	for name, score := range map[string]float64{
		"negative": -0.1,
		"tooHigh":  10.1,
	} {
		if _, err := value.NewCVSS(score, ""); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestCVSS_Zero(t *testing.T) {
	var zero value.CVSS
	if !zero.IsZero() {
		t.Error("zero cvss should report IsZero")
	}
	// A score of 0 with no vector is treated as unset.
	empty, err := value.NewCVSS(0, "")
	if err != nil {
		t.Fatalf("cvss(0): %v", err)
	}
	if !empty.IsZero() {
		t.Error("cvss(0, \"\") should report IsZero")
	}
	if empty.Severity() != value.SeverityNone {
		t.Errorf("Severity for score 0 = %q, want none", empty.Severity())
	}
}
