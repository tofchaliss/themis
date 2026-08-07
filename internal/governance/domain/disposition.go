package domain

import "time"

// ExploitSignals is the exploitability picture behind a decision at a point in time.
//
// It is recorded on a Position so a later signal change can be compared against what was actually
// believed when the decision was made — "has the premise moved?" is not answerable from the
// current values alone.
type ExploitSignals struct {
	KEV           bool    // CISA Known-Exploited listing
	ExploitPublic bool    // a public exploit exists
	EPSS          float64 // exploitation probability 0.0–1.0
}

// SuppressesTriage reports whether a stance zeroes a Finding's residual priority — i.e. whether
// taking it removes the Finding from the work queue entirely (D14).
//
// These are exactly the stances the watcher guards. `mitigated` and `deferred` keep a non-zero
// weight, so a Finding holding one is still visible and does not need re-surfacing to be noticed.
func SuppressesTriage(s Stance) bool {
	return s == StanceNotAffected || s == StanceAcceptedRisk
}

// DefaultEPSSDriftThreshold is the EPSS increase that counts as material drift.
//
// Absolute, not relative: 0.02 → 0.25 matters (a fringe CVE became a likely one) while 0.60 → 0.75
// is the same story told louder. A relative threshold would fire constantly in the noise near zero,
// which is where EPSS is least stable and where a re-surfaced Finding is least likely to be real.
const DefaultEPSSDriftThreshold = 0.20

// Expired reports whether a suppressing decision has passed its own review-by date.
//
// This is the TIME-based sibling of signal drift, and it exists because the two answer different
// questions. Drift asks "has the world changed?"; expiry asks "has anyone looked at this lately?".
// An accepted risk with no signal movement is not thereby still acceptable — the business
// justification behind it ages (the compensating control was decommissioned, the component moved
// to a public network, the person who accepted it left), and none of that is visible in EPSS or KEV.
//
// Zero `until` means no review-by date was set, which is NOT the same as "never expires": it means
// the decision was taken without one, and this returns false rather than inventing a deadline the
// decider did not agree to.
func Expired(until, now time.Time) bool {
	return !until.IsZero() && now.After(until)
}

// DispositionDrift explains why a suppressed decision should be re-opened. A zero value means the
// premise still holds.
type DispositionDrift struct {
	KEVListed           bool // the CVE entered CISA's Known-Exploited catalog after the decision
	ExploitBecamePublic bool
	EPSSRose            bool
	// EPSSBefore/After are carried so the re-surfacing says what moved, not merely that
	// something did. "EPSS 0.03 → 0.71" is actionable; "signals changed" is not.
	EPSSBefore, EPSSAfter float64
}

// Material reports whether anything drifted.
func (d DispositionDrift) Material() bool {
	return d.KEVListed || d.ExploitBecamePublic || d.EPSSRose
}

// Reason renders the drift for a human, in the words of what actually changed.
func (d DispositionDrift) Reason() string {
	switch {
	case d.KEVListed:
		return "the CVE is now listed in CISA's Known Exploited Vulnerabilities catalog"
	case d.ExploitBecamePublic:
		return "a public exploit now exists for this CVE"
	case d.EPSSRose:
		return "exploitation probability rose materially (EPSS " +
			formatEPSS(d.EPSSBefore) + " → " + formatEPSS(d.EPSSAfter) + ")"
	default:
		return ""
	}
}

// DetectDispositionDrift compares the signals a decision rested on against the signals now, and
// reports what — if anything — invalidates the premise (GOV-14b / EDR-GOVERNANCE-01 D14).
//
// It is deliberately ONE-DIRECTIONAL: only signals getting WORSE count. A CVE leaving KEV, or its
// EPSS falling, does not re-open a suppression — the decision to suppress remains at least as well
// founded as it was. Treating improvement as drift would re-surface Findings for getting safer,
// which trains people to ignore the signal.
//
// It is also purely deterministic. AI is the optional upgrade on top (reasoning about whether the
// drift actually invalidates the ORIGINAL justification), never the thing that decides a Finding
// comes back — the whole value of this rule is that it fires without anyone having to be clever.
func DetectDispositionDrift(decidedWith, now ExploitSignals, epssThreshold float64) DispositionDrift {
	if epssThreshold <= 0 || epssThreshold > 1 {
		epssThreshold = DefaultEPSSDriftThreshold
	}
	return DispositionDrift{
		KEVListed:           now.KEV && !decidedWith.KEV,
		ExploitBecamePublic: now.ExploitPublic && !decidedWith.ExploitPublic,
		EPSSRose:            now.EPSS-decidedWith.EPSS >= epssThreshold,
		EPSSBefore:          decidedWith.EPSS,
		EPSSAfter:           now.EPSS,
	}
}

// formatEPSS renders a probability as a percentage without pulling in fmt at the domain edge.
func formatEPSS(p float64) string {
	pct := int(p*100 + 0.5)
	if pct == 0 && p > 0 {
		return "<1%"
	}
	return itoa(pct) + "%"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 && i > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
