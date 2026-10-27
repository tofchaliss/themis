package app

import (
	"fmt"
	"sort"
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
	// Compared WITH its epoch (KN-EPOCH-1): a producer that keeps the epoch on the purl only
	// (the Nessus inventory) must not read as "below" every epoch-carrying bound of the same build.
	comp.Version = value.RPMInstalledVersion(comp.Ecosystem, comp.Version, comp.PURL)

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

	// An open verdict states its premise too (EDR-VERDICT-01 D10, KN-OPEN-REASON-1). Until
	// 2026-10-26 only a clearance said why; an open row said nothing, and the operator was left
	// to compare versions by hand. Measured on a fully patched RHEL 8 host: ~1,300 open rows
	// whose el8 fixes are all mysql 8.4 / ruby 3.x module builds while the host runs the 8.0 /
	// 2.5 streams — real, not reachable by `dnf update`, and indistinguishable on the page from
	// "the vendor shipped nothing". The text is audit prose: nothing branches on it.
	open := domain.OpenVerdict()
	open.Reason = openReason(view, comp, pkg)
	return open
}

// openReason explains why an rpm-class occurrence stays open, in the vocabulary of the direct
// rpm verdict above: which same-stream bounds the install was compared against and where it
// fell. Three honest shapes, and nothing else:
//
//   - no fix for this package on the card at all;
//   - fixes exist, but none in the install's EL major (RPMFixedByStream never compares across
//     majors — a RHEL 9 bound says nothing about a RHEL 8 install);
//   - same-major fixes exist and the install is below every one of them. When the install and
//     all of those fixes are module-stream builds of a DIFFERENT upstream series, the reason says
//     so: a module stream pins its series, so a plain update inside the stream cannot reach a fix
//     published for another one (mysql:8.0 never receives the mysql:8.4 build). Phrased as
//     "likely", deliberately — a rolling stream (container-tools:rhel8) does move its series,
//     and the install's version names no stream the rule could read.
//
// Only the rpm class gets a premise: it is the one world where the open verdict rests on an
// actual comparison. Elsewhere "open" still means "not cleared", which is already honest.
func openReason(view domain.EnterpriseView, comp InventoryComponent, pkg string) string {
	if value.ClassifyEcosystem(comp.Ecosystem) != value.VersionClassRPM || pkg == "" {
		return ""
	}
	fixes := view.FixesFor(pkg, comp.Ecosystem)
	if len(fixes) == 0 {
		return fmt.Sprintf("no vendor fix on record for %s", pkg)
	}
	major := value.RPMReleaseMajor(comp.Version)
	if major == "" {
		return fmt.Sprintf("installed %s names no EL stream, so no vendor fix can be compared against it", comp.Version)
	}
	var same []string
	for _, fix := range fixes {
		if value.RPMReleaseMajor(fix) == major {
			same = append(same, fix)
		}
	}
	if len(same) == 0 {
		return fmt.Sprintf("no el%s fix on record for %s (%d fix bound(s) known for other EL streams)", major, pkg, len(fixes))
	}
	reason := fmt.Sprintf("installed %s is below every el%s fix for %s: %s", comp.Version, major, pkg, listBounds(same))
	switch series := otherStreamSeries(comp.Version, same); {
	case len(series) > 0:
		reason += fmt.Sprintf("; those fixes are module builds of another series (%s, installed %s) — likely another module stream, which a plain update inside the installed stream never reaches",
			strings.Join(series, ", "), upstreamSeries(comp.Version))
	case !value.IsRPMModuleStream(comp.Version) && allModuleBuilds(same):
		// The base-repository shape (measured 2026-10-27: RHEL 8's base perl 5.26 against
		// fixes that exist only as perl:5.30 / perl:5.32 stream rebuilds). The install names
		// no stream at all, so no series compare is possible — but every bound does, and that
		// is the fact the operator needs: enabling the stream, not updating, reaches the fix.
		reason += "; those fixes are module-stream builds and the installed package is not (base repository) — likely a fix published only for a module stream, which a plain update never reaches"
	}
	return reason
}

// allModuleBuilds reports whether every bound is a module-stream rebuild.
func allModuleBuilds(bounds []string) bool {
	for _, b := range bounds {
		if !value.IsRPMModuleStream(b) {
			return false
		}
	}
	return len(bounds) > 0
}

// listBounds renders at most three bounds and counts the rest, so a card with thirteen el8
// rebuilds does not turn the premise into a wall.
func listBounds(bounds []string) string {
	const show = 3
	if len(bounds) <= show {
		return strings.Join(bounds, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(bounds[:show], ", "), len(bounds)-show)
}

// otherStreamSeries returns the distinct upstream series of the given same-major fixes when the
// install AND every fix are module-stream builds and NONE shares the install's series — the
// shape of "the fix lives in another stream". Any plain (non-modular) build on either side, or
// one fix in the install's own series, returns nil: then the install is simply behind.
func otherStreamSeries(installed string, fixes []string) []string {
	if !value.IsRPMModuleStream(installed) {
		return nil
	}
	mine := upstreamSeries(installed)
	if mine == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, fix := range fixes {
		if !value.IsRPMModuleStream(fix) {
			return nil
		}
		s := upstreamSeries(fix)
		if s == "" || s == mine {
			return nil
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// upstreamSeries is the first two dot-segments of an rpm build's upstream version — the part a
// RHEL module stream is named by ("8.0.46-1.module+el8.10.0+…" -> "8.0", "2.5.9-116.module+…" ->
// "2.5"). A single-segment version is its own series ("15-1.module+el8…" -> "15").
func upstreamSeries(v string) string {
	up := rpmUpstreamVersion(v)
	parts := strings.SplitN(up, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return up
}

// joinReasons prefixes an open verdict's premise with the fan-out guard's flag (KN-SANITY-1)
// when both apply: the guard says "look twice", the premise says what was compared.
func joinReasons(flag, premise string) string {
	switch {
	case flag == "":
		return premise
	case premise == "":
		return flag
	default:
		return flag + "; " + premise
	}
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
		owner.Version = value.RPMInstalledVersion(owner.Ecosystem, owner.Version, owner.PURL)
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
		sib.Version = value.RPMInstalledVersion(sib.Ecosystem, sib.Version, sib.PURL)
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
