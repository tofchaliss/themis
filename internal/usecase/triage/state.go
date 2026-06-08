package triage

import (
	"math"
	"strings"

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

// ComputeRiskScore applies the Phase 1 severity × effective-state formula for triage outcomes.
func ComputeRiskScore(rawSeverity, effectiveState string) int {
	base := baseScore(rawSeverity)
	switch strings.ToLower(effectiveState) {
	case domain.EffectiveStateSuppressed, domain.EffectiveStateFalsePositive, domain.EffectiveStateAcceptedRisk:
		return int(math.Round(float64(base) * 0.1))
	case domain.EffectiveStateConfirmed:
		return int(math.Min(100, math.Round(float64(base)*1.2)))
	case domain.EffectiveStateResolved:
		return 0
	default:
		return base
	}
}

func baseScore(rawSeverity string) int {
	switch strings.ToLower(strings.TrimSpace(rawSeverity)) {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 40
	case "low":
		return 10
	default:
		return 0
	}
}
