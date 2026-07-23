package triage

import (
	"github.com/themis-project/themis/internal/domain"
)

// MapDecisionToEffectiveState maps an L4 triage decision to risk_context state.
func MapDecisionToEffectiveState(decision string) string {
	switch decision {
	case domain.TriageDecisionFalsePositive:
		return domain.EffectiveStateFalsePositive
	case domain.TriageDecisionAcceptedRisk:
		return domain.EffectiveStateAcceptedRisk
	case domain.TriageDecisionConfirmed:
		return domain.EffectiveStateConfirmed
	case domain.TriageDecisionResolved:
		return domain.EffectiveStateResolved
	case domain.TriageDecisionEscalate:
		return domain.EffectiveStateInTriage
	default:
		return domain.EffectiveStateDetected
	}
}

// MapDecisionToVEXStatus returns the VEX assertion status for a triage decision.
// Escalate does not generate VEX.
func MapDecisionToVEXStatus(decision string) (string, bool) {
	switch decision {
	case domain.TriageDecisionFalsePositive:
		return domain.VEXStatusNotAffected, true
	case domain.TriageDecisionAcceptedRisk:
		return domain.VEXStatusAffected, true
	case domain.TriageDecisionConfirmed:
		return domain.VEXStatusAffected, true
	case domain.TriageDecisionResolved:
		return domain.VEXStatusFixed, true
	default:
		return "", false
	}
}

// ComputeRiskScore applies the Phase 1 severity × effective-state formula for
// triage outcomes. It delegates to the canonical domain.ComputeRiskScore so
// enrichment and triage cannot drift.
func ComputeRiskScore(rawSeverity, effectiveState string) int {
	return domain.ComputeRiskScore(rawSeverity, effectiveState)
}
