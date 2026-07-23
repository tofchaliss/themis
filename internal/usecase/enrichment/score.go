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
	base := float64(ComputeRiskScore(rawSeverity, effectiveState))
	if base == 0 {
		// CR-5: severity unknown (no CVSS yet). Don't hide a finding that carries a
		// confirming signal behind a 0 while CVSS backfill is pending.
		return unknownSeverityFloor(effectiveState, kevListed, exploitPublic)
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

// unknownSeverityFloor returns a non-zero interim risk score for a finding with
// unknown severity that still carries a confirming signal (CR-5). Dismissed
// states (suppressed / false_positive / accepted_risk / not_affected / resolved)
// never receive a floor — a human or vendor has already de-prioritised them.
func unknownSeverityFloor(effectiveState string, kevListed, exploitPublic bool) int {
	switch strings.ToLower(strings.TrimSpace(effectiveState)) {
	case domain.EffectiveStateSuppressed, domain.EffectiveStateFalsePositive,
		domain.EffectiveStateAcceptedRisk, domain.EffectiveStateNotAffected, domain.EffectiveStateResolved:
		return 0
	}
	switch {
	case kevListed:
		return domain.RiskScoreUnknownKEVFloor
	case exploitPublic, strings.EqualFold(strings.TrimSpace(effectiveState), domain.EffectiveStateConfirmed):
		return domain.RiskScoreUnknownConfirmedFloor
	default:
		return 0
	}
}

// ComputeRiskScore applies the Phase 1 severity × effective-state formula. It
// delegates to the canonical domain.ComputeRiskScore so enrichment and triage
// cannot drift.
func ComputeRiskScore(rawSeverity, effectiveState string) int {
	return domain.ComputeRiskScore(rawSeverity, effectiveState)
}
