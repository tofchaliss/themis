package enrichment_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// TestUnknownSeverityRiskFloor covers the CR-5 interim floor: an unknown-severity
// finding (no CVSS yet) still scores non-zero when it carries a confirming signal,
// but stays 0 when dismissed or signal-free.
func TestUnknownSeverityRiskFloor(t *testing.T) {
	cases := []struct {
		name         string
		state        string
		kev, exploit bool
		want         int
	}{
		{"unknown no signal → 0", domain.EffectiveStateDetected, false, false, 0},
		{"unknown + KEV → KEV floor", domain.EffectiveStateDetected, true, false, domain.RiskScoreUnknownKEVFloor},
		{"unknown + exploit → confirmed floor", domain.EffectiveStateDetected, false, true, domain.RiskScoreUnknownConfirmedFloor},
		{"unknown + confirmed state → confirmed floor", domain.EffectiveStateConfirmed, false, false, domain.RiskScoreUnknownConfirmedFloor},
		{"unknown + KEV but suppressed → 0", domain.EffectiveStateSuppressed, true, true, 0},
		{"unknown + KEV but false_positive → 0", domain.EffectiveStateFalsePositive, true, false, 0},
		{"unknown + KEV but accepted_risk → 0", domain.EffectiveStateAcceptedRisk, true, false, 0},
		{"unknown + KEV but not_affected → 0", domain.EffectiveStateNotAffected, true, false, 0},
		{"unknown + KEV but resolved → 0", domain.EffectiveStateResolved, true, false, 0},
	}
	for _, tc := range cases {
		got := enrichment.ComputeRiskScoreV2("unknown", tc.state, nil, tc.kev, tc.exploit,
			string(domain.DeterministicLevelInformational), 1.0)
		if got != tc.want {
			t.Errorf("%s: score = %d, want %d", tc.name, got, tc.want)
		}
	}

	// A known severity is unaffected by the floor logic.
	if got := enrichment.ComputeRiskScoreV2("high", domain.EffectiveStateDetected, nil, false, false,
		string(domain.DeterministicLevelInformational), 1.0); got != 70 {
		t.Fatalf("known high severity score = %d, want 70", got)
	}
}
