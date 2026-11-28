package domain

import "github.com/themis-project/themis/internal/kernel/value"

// VerdictGeneration versions the OCCURRENCE-JUDGEMENT LOGIC — judgeOccurrence, the vendor
// fixed-verdict rules, FixesFor/StrictFixesFor and the name rules they lean on. Bump it in the
// SAME change as any edit to those, and the D6 catch-up sweep re-judges the estate once.
//
// It exists because a code change advances no card version, so the "judged against card version
// N" stamp cannot see one. Measured on KN-FIX-4 (2026-09-10): the normalized fix-lookup rule
// shipped, every row was stamp-current, the sweep honestly reported `rejudged:0`, and the new
// rule's effect waited on unrelated feed drift. The operator reset stamps by hand, twice.
//
// Same mechanism as domain.ClassifierGeneration, deliberately: two stamps, one idea — a rule
// change IS staleness, and the query is the only place that can know it.
//
// Generations: 1 = the pre-stamp baseline (everything through 2026-09-16) ·
// 2 = versioned interpreter wrappers reach the fix lookup and the bridge (2026-09-17, KN-FIX-5) ·
// 3 = an open rpm verdict states its premise (2026-10-26, D10 / KN-OPEN-REASON-1) — no state
// moves, but every open row's reason is new text, and only the sweep can write it onto history ·
// 4 = an rpm install is compared with its epoch restored from the purl (2026-10-27, KN-EPOCH-1) ·
// 5 = an open verdict records the vendor bounds it is BEHIND (2026-11-02, EDR-INCIDENT-01 D1) —
// no state moves; the first judgement under this generation writes the bounds onto every open
// row silently, so that a bound arriving AFTER it can be told apart from one that was already
// there and announced as news.
const VerdictGeneration = 5

// Occurrence verdict state (EDR-VERDICT-01 D2). An occurrence is one component row matched to a
// card on one release. Its verdict records what the vendor-fix machinery concluded about THIS
// occurrence — recorded state, never a deletion: "checked and fine" and "never looked" must not
// look alike (the live KN-VERDICT-1 investigation could not distinguish them).

// VerdictState is what the fixed-verdict concluded about one occurrence.
type VerdictState string

const (
	// VerdictOpen — the occurrence is (or must be treated as) a live match. This is also what
	// every missing/unknown state reads as: the fail-safe direction is always toward "affected".
	VerdictOpen VerdictState = "open"
	// VerdictClearedVendorFix — the installed build provably carries the vendor's fix
	// (EDR-VEX-01 Phase 3 rpm stream verdict / D9 apk bounds, or the D3 ownership bridge).
	VerdictClearedVendorFix VerdictState = "cleared_vendor_fix"
)

// IsOpen reports whether this state keeps the occurrence live. Anything that is not an
// affirmative clearance — including "" from a row predating the field — is open (D2).
func (s VerdictState) IsOpen() bool { return s != VerdictClearedVendorFix }

// VerdictGrade is the strength of the evidence a clearance rests on (EDR-VERDICT-01 D3,
// expressed in the EDR-TRUST-01 vocabulary). Set only when cleared.
type VerdictGrade string

const (
	// VerdictGradeObserved — the clearance rests on direct evidence: the component's own
	// version compared against the vendor bound, or an explicit SBOM ownership relationship.
	VerdictGradeObserved VerdictGrade = "observed"
	// VerdictGradeInferred — the clearance rests on a same-inventory match Themis worked out
	// itself (the D3 bridge's guess grade). Always labeled; switchable off (D4).
	VerdictGradeInferred VerdictGrade = "inferred"
)

// OccurrenceVerdict is the judged outcome for one occurrence: the state, the evidence grade
// behind it, and the plain-language premise a drawer renders verbatim.
type OccurrenceVerdict struct {
	State  VerdictState
	Grade  VerdictGrade
	Reason string
	// Behind are the vendor fix bounds this OPEN occurrence is below — the same-stream rpm
	// bounds, or the strict apk bounds, the install was compared against and fell short of
	// (EDR-INCIDENT-01 D1). Nil for a clearance, and nil when nothing comparable is on record
	// (no fix for the package, a fix only for another EL major, a version that names no
	// stream). It is the structured half of the open premise: a bound that appears here for
	// the first time on a row already judged is a fix PUBLISHED for something the estate has
	// open — the fact the fix-available alert announces. Sorted, deduplicated.
	Behind []string
	// Advisories names the vendor advisories that shipped the Behind bounds, where the card's
	// vendor statements say (EDR-VEX-02 D14: a `fixed` statement carries its RHSA). Best
	// effort, display only; empty when no statement names one.
	Advisories []string
}

// NewlyBehind returns the bounds in Behind that were not in prev — the fixes published since
// the occurrence was last judged. Order follows Behind; an empty prev returns all of Behind.
func (v OccurrenceVerdict) NewlyBehind(prev []string) []string {
	if len(v.Behind) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(prev))
	for _, b := range prev {
		seen[b] = struct{}{}
	}
	var out []string
	for _, b := range v.Behind {
		if _, ok := seen[b]; !ok {
			out = append(out, b)
		}
	}
	return out
}

// OpenVerdict is the default judgement: a live occurrence, no grade, no premise.
func OpenVerdict() OccurrenceVerdict { return OccurrenceVerdict{State: VerdictOpen} }

// ClearedVendorFix builds an affirmative clearance with its evidence grade and premise.
func ClearedVendorFix(grade VerdictGrade, reason string) OccurrenceVerdict {
	return OccurrenceVerdict{State: VerdictClearedVendorFix, Grade: grade, Reason: reason}
}

// FixStanding answers one question about an occurrence: is there a published fix this install
// has not picked up (EDR-REBUILD-01 D19, D30)? It is read off the recorded verdict, never a new
// comparison, so a consumer in another context does not have to order version strings.
type FixStanding string

const (
	// FixKnown — the occurrence is open AND below at least one vendor bound published for its
	// own package and world. The same fact the fix-available alert announces.
	FixKnown FixStanding = "known"
	// FixOtherStream — the occurrence is open and below vendor bounds, but every one of them is a
	// build of ANOTHER module stream (EDR-REBUILD-01 KN-BEHIND-MODULE-1). A plain update or
	// rebuild never reaches such a build; switching the stream is a person's change. So it is a
	// fix that exists, and not one a rebuild can pick up. The caller decides this from the
	// bounds (the app's reach rule); FixStandingOf never returns it.
	FixOtherStream FixStanding = "other_stream"
	// FixNone — nothing to pick up: the install already carries the fix (a clearance), or the
	// comparison ran and no bound for this package and world is on record.
	FixNone FixStanding = "none"
	// FixUnknown — the comparison could not run: an ecosystem the fixed-verdict does not cover,
	// or an rpm build that names no EL stream. Unknown is NOT a known fix (D30 item 2).
	FixUnknown FixStanding = "unknown"
)

// FixStandingOf derives the standing from a recorded occurrence: its verdict state, the bounds
// it was found behind, and the ecosystem and version it was judged with. The fail direction is
// deliberate and the opposite of attribution's: an occurrence Themis cannot compare is
// `unknown`, so that it never starts a build that could not be shown to help.
func FixStandingOf(state VerdictState, ecosystem, version string, behind []string) FixStanding {
	if !state.IsOpen() {
		return FixNone
	}
	if len(behind) > 0 {
		return FixKnown
	}
	switch value.ClassifyEcosystem(ecosystem) {
	case value.VersionClassRPM:
		if value.RPMReleaseMajor(version) == "" {
			return FixUnknown
		}
		return FixNone
	case value.VersionClassAPK:
		return FixNone
	default:
		return FixUnknown
	}
}
