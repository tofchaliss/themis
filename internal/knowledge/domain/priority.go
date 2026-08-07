package domain

import (
	"math"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Deterministic exploitability priority levels (Layer-1, first-match), ported from the v0.3.x
// monolith. These are CVE-INTRINSIC — the release-scoped blast multiplier and any VEX-state
// modifier are deliberately NOT applied on the Faultline (they are Governance concerns).
// nearCertainEPSS is the exploitation probability at which a CVE is treated as "already being
// exploited" rather than merely likely — far above `elevated`'s 0.5, which covers elevated risk.
const nearCertainEPSS = 0.9

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
	// A near-certain EPSS lifts a LOW-CVSS CVE out of `informational`, exactly as the KEV arm
	// above does (KN-EPSS-BAND-1).
	//
	// Without this arm, EPSS reached the band only through the `elevated` rule below, which also
	// demands c >= 7. A medium-CVSS CVE therefore fell to the default arm and was reported as
	// `informational` HOWEVER certain its exploitation. Measured on a live estate: CVE-2021-45105
	// (CVSS 5.9, EPSS 99%) was labelled `informational`. That is not a neutral fallback — it is a
	// claim, and it tells an operator to ignore something FIRST rates near-certain to be attacked.
	//
	// Scoped tightly to the cases that were MISLABELLED, and no wider. The 0.9 floor is far above
	// `elevated`'s 0.5 — this arm is for "already being exploited", not merely elevated
	// probability — and `c < 7` leaves every CVE the `elevated` rule already handles exactly
	// where it was. Fixing a wrong label is the mandate; re-banding cases that were already
	// sensible is a separate decision and not one to smuggle in.
	//
	// KEV remains stronger regardless: it is a CONFIRMED exploitation record where EPSS is a
	// prediction, so the KEV arms above match first and this one cannot overtake them.
	case v.EPSS >= nearCertainEPSS && c < 7:
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
	// The score must not CONTRADICT the band (KN-EPSS-BAND-1 (b), decided 2026-08-07): anything the
	// band calls `high` or `high+` scores at least the high baseline.
	//
	// The band is EXPLOITABILITY priority and the score is severity-led, so the two can disagree
	// about the same CVE. Measured: CVE-2021-45105 (CVSS 5.9, EPSS 99.999%) banded `high` and
	// scored 52, below a plain high at 70. Worse, and found while testing this: a **KEV-listed**
	// low-CVSS CVE bands `high` — CONFIRMED active exploitation — and scored **25**, which puts it
	// near the bottom of a triage queue sorted by score.
	//
	// The decision was NOT to let likelihood outrank severity in general; the 30% lift stands and
	// impact still orders WITHIN a band. What is forbidden is a CVE scoring beneath the band it was
	// just assigned, because two artefacts describing one CVE must not tell a reader opposite
	// things. A floor does that without re-ranking anything the band did not already re-label.
	if b := v.Priority(); b == PriorityHigh || b == PriorityHighPlus {
		if base, computed := severityBaseline(value.SeverityHigh), v.scoreFromSeverity(); computed < base {
			return base
		}
	}
	return v.scoreFromSeverity()
}

// scoreFromSeverity is the severity-baseline computation, lifted by EPSS and KEV.
func (v EnterpriseView) scoreFromSeverity() int {
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
