package domain

import "github.com/themis-project/themis/internal/kernel/value"

// ProvablyOutOfRange reports whether EVERY matched component of the Finding is provably
// outside the reconciled affected range — the deterministic version-range rule
// (EDR-TRUST-01 T5). It is a pure function over evidence the caller supplies, so it is
// fully explainable and replayable.
//
// It is certain in one direction only. It decides `not_affected` when every component is
// provably out of range, and **defers on everything else** — an in-range component, an
// undecidable comparison, a missing or unparseable version, or no reconciled range at all.
// "In range" is not a verdict this rule makes; a parse gap must never drop a real
// vulnerability.
//
// The range MUST be the **reconciled, backport-aware** one, not a feed's query-time filter.
// That is the whole point: a distro backport (upstream flags the version; the distribution's
// build is not vulnerable) is exactly the case the reconciled view catches and the raw feed
// does not. Passing an unreconciled range here would produce silent, wrong `not_affected`
// verdicts — the most dangerous defect class in this system.
//
// This mirrors the rule the Intelligence runtime evaluates today, but reaches a Finding that
// correlation could not: one created BEFORE the range was known, which correlation's own
// gate (which only runs at match time) will never revisit.
func ProvablyOutOfRange(components []MatchedComponent, reconciledRanges []string) bool {
	if len(reconciledRanges) == 0 || len(components) == 0 {
		return false // nothing to decide against — defer
	}
	for _, c := range components {
		if c.Version == "" {
			return false // cannot read a version → not certain → defer
		}
		r := value.AffectedRange{Ecosystem: c.Ecosystem, Groups: reconciledRanges}
		if r.Applicability(c.Version) != value.RangeOutOfRange {
			return false // in range or undecidable → defer
		}
	}
	return true
}
