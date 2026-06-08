package enrichment

import (
	"math"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ComputeRiskScore applies the Phase 1 severity × effective-state formula.
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
