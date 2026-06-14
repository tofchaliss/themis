package enrichment

import (
	"math"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ComputeRiskScoreV2 applies the Phase 2a composite formula:
//
//	base      = f(raw_severity, effective_state)
//	layer1    = 100 when deterministic_level is Critical, else base
//	epss_adj  = base × (1 + epss_score × 0.3); NULL epss_score is treated as 0.0
//	kev_adj   = +15 when kev_listed
//	blast_adj = base × blast_radius_score (defaults to 1.0 when unset)
//	final     = min(100, round(layer1 + epss_adj + kev_adj + blast_adj))
func ComputeRiskScoreV2(
	rawSeverity, effectiveState string,
	epssScore *float64,
	kevListed, exploitPublic bool,
	deterministicLevel string,
	blastRadiusScore float64,
) int {
	_ = exploitPublic

	base := float64(ComputeRiskScore(rawSeverity, effectiveState))
	if base == 0 {
		return 0
	}

	layer1 := base
	if strings.EqualFold(strings.TrimSpace(deterministicLevel), string(domain.DeterministicLevelCritical)) {
		layer1 = 100
	}

	epssAdj := base * (1 + epssValue(epssScore)*domain.RiskScoreEPSSMultiplierMax)

	kevAdj := 0.0
	if kevListed {
		kevAdj = float64(domain.RiskScoreKEVAdjustment)
	}

	if blastRadiusScore <= 0 {
		blastRadiusScore = domain.RiskScoreBlastRadiusMin
	}
	blastAdj := base * blastRadiusScore

	final := layer1 + epssAdj + kevAdj + blastAdj
	return int(math.Min(100, math.Round(final)))
}

// ComputeRiskScore applies the Phase 1 severity × effective-state formula.
func ComputeRiskScore(rawSeverity, effectiveState string) int {
	base := baseScore(rawSeverity)
	switch strings.ToLower(effectiveState) {
	case domain.EffectiveStateSuppressed, domain.EffectiveStateFalsePositive, domain.EffectiveStateAcceptedRisk, domain.EffectiveStateNotAffected:
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
