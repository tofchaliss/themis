package app

import (
	"fmt"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// judgeOccurrence is the ONE place a component meets the card's fix knowledge
// (EDR-VERDICT-01 D2): both intake paths — discovery correlation and scanner-report
// ingestion — and every later re-judgement run through it, so "recorded" and "judged" can
// never drift apart again (the drift was the KN-VERDICT-1 defect: correlation judged then
// dropped, the scanner path recorded without judging).
//
// It returns a verdict, never a drop decision: an occurrence the verdict clears is recorded
// as cleared, with the evidence grade and the plain-language premise the drawer renders.
// Every undecidable input — no fixes for this package, a non-verdict-capable ecosystem, a
// version that cannot be placed — yields the open verdict: the fail-safe direction is always
// toward "affected".
func judgeOccurrence(view domain.EnterpriseView, comp InventoryComponent) domain.OccurrenceVerdict {
	pkg := componentPackage(comp)

	// Vendor fixed-verdict for rpm-class components (EDR-VEX-01 Phase 3): the installed build
	// at/above a same-EL-stream vendor fix carries the backported fix. FixesFor aggregates every
	// source's fix for THIS package and excludes unattributed ones (KN-FIX-1), so the verdict
	// rests on evidence about this component and nothing else. The per-fix loop exists so the
	// clearance can NAME the bound it rests on — a premise is part of the verdict (D2).
	for _, fix := range view.FixesFor(pkg, comp.Ecosystem) {
		if value.RPMFixedByStream(comp.Ecosystem, comp.Version, []string{fix}) {
			return domain.ClearedVendorFix(domain.VerdictGradeObserved,
				fmt.Sprintf("vendor fix %s present: installed %s is at/above the same-stream bound for %s", fix, comp.Version, pkg))
		}
	}

	// The apk analogue (EDR-VEX-01 D9): at/above EVERY strictly-stamped apk bound for the
	// package. The bound set is the STRICT selection — fail-open is for display, fail-closed is
	// for verdicts — and soundness comes from the max-bound rule, because an apk version names
	// no branch a compare could scope to.
	if bounds := view.StrictFixesFor(pkg, comp.Ecosystem); len(bounds) > 0 &&
		value.APKFixedByBounds(comp.Ecosystem, comp.Version, bounds) {
		return domain.ClearedVendorFix(domain.VerdictGradeObserved,
			fmt.Sprintf("installed %s is at/above every apk fix bound for %s", comp.Version, pkg))
	}

	return domain.OpenVerdict()
}
