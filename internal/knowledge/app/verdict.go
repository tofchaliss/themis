package app

import (
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// BridgeContext is what the ownership bridge (EDR-VERDICT-01 D3) knows about the inventory an
// occurrence was observed in: its sibling components, the SBOM's explicit ownership edges, and
// whether the guess grade is armed (D4). Both intake paths build one — correlation from the
// release inventory, the scanner path from the report's own component set — and the zero value
// is honest: no siblings, no owners, no guessing.
type BridgeContext struct {
	// Siblings are the other components observed in the SAME inventory/report. The bridge may
	// only reach a verdict through a component that is actually on record here — never through
	// anything imagined.
	Siblings []InventoryComponent
	// Owners maps an owned component's PURL to its owning component's PURL, from explicit SBOM
	// ownership relationships (Observed-grade evidence).
	Owners map[string]string
	// InferredBridge arms the D4 guess grade; when false, only explicit ownership evidence can
	// bridge (strict mode).
	InferredBridge bool
}

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
//
// Order of judgement: the component's own direct verdicts first (rpm stream, apk bounds),
// then the ownership bridge (D3) — the Observed hop through an explicit SBOM ownership edge,
// then the Inferred hop through a labeled same-inventory match. First affirmative clearance
// wins; the grades exist so a reader can always see WHICH kind of evidence cleared a row.
func judgeOccurrence(view domain.EnterpriseView, comp InventoryComponent, bridge BridgeContext) domain.OccurrenceVerdict {
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

	// The ownership bridge (EDR-VERDICT-01 D3): a language-package occurrence — the .egg-info
	// shadow of files an rpm installed — can be cleared only THROUGH its owning rpm, because
	// the language row's bare version (39.2.0, no build release) can never satisfy an rpm
	// compare on its own. Measured on CVE-2025-47273/MRF: the patched rpm sat in the same
	// inventory while its pypi shadow stayed flagged forever.
	if v, ok := bridgeObserved(view, comp, bridge); ok {
		return v
	}
	if bridge.InferredBridge {
		if v, ok := bridgeInferred(view, comp, bridge); ok {
			return v
		}
	}

	return domain.OpenVerdict()
}

// bridgeObserved is the D3 Observed hop: the SBOM states which component OWNS this one
// (Syft's ownership-by-file-overlap edge), so the owner's own fixed-verdict covers the shadow.
// Every precondition is affirmative — an edge on record, the owner present in the same
// inventory, an rpm-class owner, and the owner's full build at/above a same-stream vendor
// bound; any gap keeps the occurrence open.
func bridgeObserved(view domain.EnterpriseView, comp InventoryComponent, bridge BridgeContext) (domain.OccurrenceVerdict, bool) {
	ownerPURL := bridge.Owners[comp.PURL]
	if ownerPURL == "" || comp.PURL == "" {
		return domain.OccurrenceVerdict{}, false
	}
	for _, owner := range bridge.Siblings {
		if owner.PURL != ownerPURL || value.ClassifyEcosystem(owner.Ecosystem) != value.VersionClassRPM {
			continue
		}
		ownerPkg := componentPackage(owner)
		for _, fix := range view.FixesFor(ownerPkg, owner.Ecosystem) {
			if value.RPMFixedByStream(owner.Ecosystem, owner.Version, []string{fix}) {
				return domain.ClearedVendorFix(domain.VerdictGradeObserved, fmt.Sprintf(
					"owned by %s %s (SBOM ownership): vendor fix %s present for %s",
					owner.Name, owner.Version, fix, ownerPkg)), true
			}
		}
	}
	return domain.OccurrenceVerdict{}, false
}

// bridgeInferred is the D3 guess grade: no ownership edge exists, but the SAME inventory holds
// an rpm component that (a) shares the language row's normalized name with its fix-attribution
// key, (b) carries exactly the language row's version as its upstream version segment, and
// (c) is itself at/above a same-stream vendor bound for this CVE. That is the
// distro-owns-these-files shape — and it is a match Themis worked out itself, so the clearance
// is labeled Inferred (D4: it still leaves the queue by default; strict estates switch it off).
//
// The name-affinity guard (a) is what keeps version equality from clearing strangers: without
// it, any pypi row at 3.9 would clear against python3-ply@3.9-9.el8 on a shared module-stream
// card. NormalizeProduct strips exactly one distro wrapper (python-setuptools -> setuptools),
// and the comparison demands EQUALITY, not containment — under-matching keeps a row open,
// which is the safe direction here (the opposite of claim classification, where under-matching
// would hide a vulnerability).
func bridgeInferred(view domain.EnterpriseView, comp InventoryComponent, bridge BridgeContext) (domain.OccurrenceVerdict, bool) {
	if value.ClassifyEcosystem(comp.Ecosystem) != value.VersionClassGeneric ||
		value.CanonicalEcosystem(comp.Ecosystem) == "deb" ||
		strings.TrimSpace(comp.Version) == "" || strings.TrimSpace(comp.Name) == "" {
		return domain.OccurrenceVerdict{}, false
	}
	want := domain.NormalizeProduct(comp.Name)
	for _, sib := range bridge.Siblings {
		if sib.PURL == comp.PURL || value.ClassifyEcosystem(sib.Ecosystem) != value.VersionClassRPM {
			continue
		}
		sibPkg := componentPackage(sib)
		if domain.NormalizeProduct(sibPkg) != want && domain.NormalizeProduct(sib.Name) != want {
			continue
		}
		if rpmUpstreamVersion(sib.Version) != strings.TrimSpace(comp.Version) {
			continue
		}
		for _, fix := range view.FixesFor(sibPkg, sib.Ecosystem) {
			if value.RPMFixedByStream(sib.Ecosystem, sib.Version, []string{fix}) {
				return domain.ClearedVendorFix(domain.VerdictGradeInferred, fmt.Sprintf(
					"matched to %s %s at the distro version (inferred, no ownership edge): vendor fix %s present for %s",
					sib.Name, sib.Version, fix, sibPkg)), true
			}
		}
	}
	return domain.OccurrenceVerdict{}, false
}

// rpmUpstreamVersion reduces an rpm build version to its upstream segment — the number a
// language-package shadow of the same files reports ("0:39.2.0-9.el8_10" -> "39.2.0").
// RPM versions never contain a hyphen, so everything before the first hyphen of the EVR
// (epoch stripped) is exact.
func rpmUpstreamVersion(v string) string {
	evr := value.RPMEVR(v)
	if i := strings.Index(evr, ":"); i >= 0 {
		evr = evr[i+1:]
	}
	if i := strings.Index(evr, "-"); i >= 0 {
		evr = evr[:i]
	}
	return evr
}
