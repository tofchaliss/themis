package domain

import (
	"math"
	"strings"
)

// SeverityBaseScore maps a raw CVSS severity label to the Phase 1 base score.
// An unrecognised/empty severity returns 0 (unknown — no CVSS yet).
func SeverityBaseScore(rawSeverity string) int {
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

// ComputeRiskScore applies the Phase 1 severity × effective-state formula. It is
// the single canonical implementation shared by the enrichment and triage use
// cases (previously duplicated, and drifted on the not_affected input). Dismissed
// states damp the base to 10%, a confirmed finding is boosted 20% (capped at 100),
// a resolved finding scores 0, and any other state keeps the base.
func ComputeRiskScore(rawSeverity, effectiveState string) int {
	base := SeverityBaseScore(rawSeverity)
	switch strings.ToLower(strings.TrimSpace(effectiveState)) {
	case EffectiveStateSuppressed, EffectiveStateFalsePositive,
		EffectiveStateAcceptedRisk, EffectiveStateNotAffected:
		return int(math.Round(float64(base) * 0.1))
	case EffectiveStateConfirmed:
		return int(math.Min(100, math.Round(float64(base)*1.2)))
	case EffectiveStateResolved:
		return 0
	default:
		return base
	}
}
