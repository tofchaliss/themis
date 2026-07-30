package domain

import (
	"math"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Deterministic exploitability priority levels (Layer-1, first-match), ported from the v0.3.x
// monolith. These are CVE-INTRINSIC — the release-scoped blast multiplier and any VEX-state
// modifier are deliberately NOT applied on the Faultline (they are Governance concerns).
const (
	PriorityCritical      = "critical"
	PriorityHighPlus      = "high+"
	PriorityHigh          = "high"
	PriorityElevated      = "elevated"
	PriorityInformational = "informational"
)

// Priority is the deterministic exploitability level for the reconciled view: the first rule
// that matches wins, combining the headline CVSS/severity with the KEV, public-exploit and
// EPSS signals.
func (v EnterpriseView) Priority() string {
	c := v.effectiveCVSS()
	switch {
	case c >= 9 && v.KEV:
		return PriorityCritical
	case c >= 9 && v.ExploitPublic:
		return PriorityHighPlus
	case v.KEV && c < 9:
		return PriorityHigh
	case v.EPSS >= 0.5 && c >= 7 && !v.KEV && !v.ExploitPublic:
		return PriorityElevated
	case c >= 9:
		return PriorityHigh
	default:
		return PriorityInformational
	}
}

// Score is the CVE-intrinsic composite priority score (0–100): a severity baseline lifted by
// EPSS (up to +30% of the base) and KEV (+15), clamped to 100; a Critical priority pins to 100.
// Unknown severity floors on the exploitability signal (KEV 50 / public exploit 25 / else 0).
func (v EnterpriseView) Score() int {
	if v.Priority() == PriorityCritical {
		return 100
	}
	base := severityBaseline(v.effectiveSeverity())
	if base == 0 {
		switch {
		case v.KEV:
			base = 50
		case v.ExploitPublic:
			base = 25
		default:
			return 0
		}
	}
	score := float64(base) + float64(base)*v.EPSS*0.3
	if v.KEV {
		score += 15
	}
	return int(math.Min(100, math.Round(score)))
}

// effectiveCVSS is the reconciled CVSS base score, falling back to a severity-word proxy
// (critical 9 / high 7 / medium 4 / low 1) when no CVSS was supplied.
func (v EnterpriseView) effectiveCVSS() float64 {
	if s := v.CVSS.Score(); s > 0 {
		return s
	}
	switch v.effectiveSeverity() {
	case value.SeverityCritical:
		return 9
	case value.SeverityHigh:
		return 7
	case value.SeverityMedium:
		return 4
	case value.SeverityLow:
		return 1
	default:
		return 0
	}
}

// effectiveSeverity prefers the reconciled headline severity, deriving it from the CVSS score
// when the headline is unknown/none but a score is present.
func (v EnterpriseView) effectiveSeverity() value.Severity {
	if v.Severity == value.SeverityUnknown || v.Severity == value.SeverityNone || v.Severity == "" {
		if s := v.CVSS.Score(); s > 0 {
			return value.SeverityFromCVSSScore(s)
		}
	}
	return v.Severity
}

func severityBaseline(s value.Severity) int {
	switch s {
	case value.SeverityCritical:
		return 90
	case value.SeverityHigh:
		return 70
	case value.SeverityMedium:
		return 40
	case value.SeverityLow:
		return 10
	default:
		return 0
	}
}
