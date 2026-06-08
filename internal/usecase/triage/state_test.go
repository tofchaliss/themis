package triage_test

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/triage"
)

func TestStateMappings(t *testing.T) {
	tests := []struct {
		decision string
		state    string
		vex      string
		hasVEX   bool
	}{
		{domain.TriageDecisionFalsePositive, domain.EffectiveStateFalsePositive, domain.VEXStatusNotAffected, true},
		{domain.TriageDecisionAcceptedRisk, domain.EffectiveStateAcceptedRisk, domain.VEXStatusAffected, true},
		{domain.TriageDecisionConfirmed, domain.EffectiveStateConfirmed, domain.VEXStatusAffected, true},
		{domain.TriageDecisionResolved, domain.EffectiveStateResolved, domain.VEXStatusFixed, true},
		{domain.TriageDecisionEscalate, domain.EffectiveStateInTriage, "", false},
	}
	for _, tc := range tests {
		if got := triage.MapDecisionToEffectiveState(tc.decision); got != tc.state {
			t.Fatalf("%s state = %q", tc.decision, got)
		}
		status, ok := triage.MapDecisionToVEXStatus(tc.decision)
		if ok != tc.hasVEX || (tc.hasVEX && status != tc.vex) {
			t.Fatalf("%s vex = %q ok=%v", tc.decision, status, ok)
		}
	}
}

func TestComputeRiskScoreMatrix(t *testing.T) {
	if triage.ComputeRiskScore("critical", domain.EffectiveStateConfirmed) != 100 {
		t.Fatal("confirmed critical")
	}
	if triage.ComputeRiskScore("high", domain.EffectiveStateFalsePositive) != 7 {
		t.Fatal("false positive high")
	}
	if triage.ComputeRiskScore("low", domain.EffectiveStateInTriage) != 10 {
		t.Fatal("in triage low")
	}
}
