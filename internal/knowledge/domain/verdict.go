package domain

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
}

// OpenVerdict is the default judgement: a live occurrence, no grade, no premise.
func OpenVerdict() OccurrenceVerdict { return OccurrenceVerdict{State: VerdictOpen} }

// ClearedVendorFix builds an affirmative clearance with its evidence grade and premise.
func ClearedVendorFix(grade VerdictGrade, reason string) OccurrenceVerdict {
	return OccurrenceVerdict{State: VerdictClearedVendorFix, Grade: grade, Reason: reason}
}
