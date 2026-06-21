package enrichment

import (
	"math"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ComputeRiskScoreV2 applies the Phase 2a composite formula. Blast radius is a
// multiplier on the severity base only (1.0× adds nothing); EPSS (+30% of base
// max) and KEV (+15) are additive bumps; a Critical deterministic level is a hard
// override to 100. Keeping EPSS/KEV additive (not folded into the blast multiplier)
// means their contribution is independent of blast — and scoring base once, not
// three times, keeps severities discriminated: a plain medium with no threat
// signals scores 40, not 100.
//
//	base      = f(raw_severity, effective_state); 0 ⇒ score 0
//	Critical override: deterministic_level == Critical ⇒ score 100
//	blast     = blast_radius_score (1.0–2.0×; ≤0 defaults to 1.0)
//	epss_adj  = base × epss_score × 0.3  (NULL/0 ⇒ 0; max +30% of base)
//	kev_adj   = +15 when kev_listed
//	final     = min(100, round(base × blast + epss_adj + kev_adj))
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
	if strings.EqualFold(strings.TrimSpace(deterministicLevel), string(domain.DeterministicLevelCritical)) {
		return 100
	}

	if blastRadiusScore <= 0 {
		blastRadiusScore = domain.RiskScoreBlastRadiusMin
	}

	epssAdj := base * epssValue(epssScore) * domain.RiskScoreEPSSMultiplierMax

	kevAdj := 0.0
	if kevListed {
		kevAdj = float64(domain.RiskScoreKEVAdjustment)
	}

	final := base*blastRadiusScore + epssAdj + kevAdj
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
