package enrichment_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func TestComputeRiskScoreMatrix(t *testing.T) {
	tests := []struct {
		severity string
		state    string
		want     int
	}{
		{"critical", domain.EffectiveStateDetected, 90},
		{"high", domain.EffectiveStateSuppressed, 7},
		{"medium", domain.EffectiveStateConfirmed, 48},
		{"low", domain.EffectiveStateAcceptedRisk, 1},
		{"none", domain.EffectiveStateFalsePositive, 0},
		{"high", domain.EffectiveStateResolved, 0},
		{"critical", domain.EffectiveStateInTriage, 90},
	}
	for _, tc := range tests {
		if got := enrichment.ComputeRiskScore(tc.severity, tc.state); got != tc.want {
			t.Fatalf("%s/%s = %d want %d", tc.severity, tc.state, got, tc.want)
		}
	}
}

func TestResolveEffectiveStateVariants(t *testing.T) {
	winner := &domain.VEXAssertionMatch{
		ID:            "a1",
		VEXDocumentID: "vex-1",
		Status:        domain.VEXStatusNotAffected,
		Justification: "component_not_present",
	}
	state, status, reason, id := enrichment.ResolveEffectiveState(winner)
	if state != domain.EffectiveStateSuppressed || status != domain.VEXStatusNotAffected || id != "a1" || reason == "" {
		t.Fatalf("got %q %q %q %q", state, status, reason, id)
	}
}
