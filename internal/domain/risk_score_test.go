package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestSeverityBaseScore(t *testing.T) {
	cases := map[string]int{
		"critical": 90, "CRITICAL": 90, " high ": 70, "medium": 40,
		"low": 10, "unknown": 0, "": 0, "bogus": 0,
	}
	for in, want := range cases {
		if got := domain.SeverityBaseScore(in); got != want {
			t.Errorf("SeverityBaseScore(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestComputeRiskScore(t *testing.T) {
	cases := []struct {
		severity string
		state    string
		want     int
	}{
		{"critical", domain.EffectiveStateDetected, 90},
		{"high", "", 70},
		{"medium", domain.EffectiveStateConfirmed, 48},    // 40 × 1.2
		{"critical", domain.EffectiveStateConfirmed, 100}, // 90 × 1.2 capped
		{"high", domain.EffectiveStateResolved, 0},
		{"high", domain.EffectiveStateSuppressed, 7}, // round(70 × 0.1)
		{"high", domain.EffectiveStateFalsePositive, 7},
		{"high", domain.EffectiveStateAcceptedRisk, 7},
		{"high", domain.EffectiveStateNotAffected, 7},  // not_affected damped like suppressed
		{"unknown", domain.EffectiveStateConfirmed, 0}, // base 0
	}
	for _, c := range cases {
		if got := domain.ComputeRiskScore(c.severity, c.state); got != c.want {
			t.Errorf("ComputeRiskScore(%q,%q) = %d, want %d", c.severity, c.state, got, c.want)
		}
	}
}
