package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func TestSeverity_Valid(t *testing.T) {
	valid := []value.Severity{
		value.SeverityUnknown, value.SeverityNone, value.SeverityLow,
		value.SeverityMedium, value.SeverityHigh, value.SeverityCritical,
	}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
		if s.String() != string(s) {
			t.Errorf("String() = %q, want %q", s.String(), string(s))
		}
	}
	if value.Severity("bogus").Valid() {
		t.Error("bogus severity reported valid")
	}
}

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]value.Severity{
		"none":      value.SeverityNone,
		"LOW":       value.SeverityLow,
		"Medium":    value.SeverityMedium,
		"moderate":  value.SeverityMedium,
		"high":      value.SeverityHigh,
		"important": value.SeverityHigh,
		"CRITICAL":  value.SeverityCritical,
		"  high  ":  value.SeverityHigh,
		"":          value.SeverityUnknown,
		"gibberish": value.SeverityUnknown,
	} {
		if got := value.ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSeverityFromCVSSScore(t *testing.T) {
	for _, tc := range []struct {
		score float64
		want  value.Severity
	}{
		{-1, value.SeverityUnknown},
		{10.1, value.SeverityUnknown},
		{0, value.SeverityNone},
		{0.1, value.SeverityLow},
		{3.9, value.SeverityLow},
		{4.0, value.SeverityMedium},
		{6.9, value.SeverityMedium},
		{7.0, value.SeverityHigh},
		{8.9, value.SeverityHigh},
		{9.0, value.SeverityCritical},
		{10.0, value.SeverityCritical},
	} {
		if got := value.SeverityFromCVSSScore(tc.score); got != tc.want {
			t.Errorf("SeverityFromCVSSScore(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}
