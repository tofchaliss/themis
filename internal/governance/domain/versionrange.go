package domain

import (
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
)

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
func ProvablyOutOfRange(components []MatchedComponent, reconciledRanges []string, statements ...value.RangeStatement) bool {
	if len(reconciledRanges) == 0 || len(components) == 0 {
		return false // nothing to decide against — defer
	}
	for _, c := range components {
		if c.Version == "" {
			return false // cannot read a version → not certain → defer
		}
		// Only the ranges that speak about THIS component's world (KN-RANGE-ECO-1): a card for
		// one CVE holds ranges for several products, and a foreign product's range must neither
		// clear nor hold a component it never spoke about. With no statements on the card the
		// flat list is judged, as before; with statements but none for this world, SelectRanges
		// returns nothing and the verdict is undecidable — defer, never clear.
		groups := value.SelectRanges(c.Ecosystem, []string{c.Name, purlName(c.PURL), c.Source}, statements, reconciledRanges)
		r := value.AffectedRange{Ecosystem: c.Ecosystem, Groups: groups}
		if r.Applicability(c.Version) != value.RangeOutOfRange {
			return false // in range or undecidable → defer
		}
	}
	return true
}

// purlName extracts the name from `pkg:type[/namespace]/name[@version][?qualifiers]`, "" when
// the PURL has no name segment.
func purlName(purl string) string {
	const prefix = "pkg:"
	if !strings.HasPrefix(purl, prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	slash := strings.LastIndex(rest, "/")
	if slash < 0 {
		return ""
	}
	return rest[slash+1:]
}
