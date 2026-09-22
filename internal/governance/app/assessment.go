package app

import (
	"context"
	"strings"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// FaultlineKnowledge is what Knowledge knows about a CVE, read over its read API and mapped
// into Governance's own view type — no cross-context import (Book III §3.5).
type FaultlineKnowledge struct {
	FaultlineID string
	CVE         string
	// Summary is the source's short account of WHAT the CVE is — carried so a human judging a
	// proposal (and the AI grounding on this same projection) can see the nature of the flaw,
	// not only its numbers. Descriptive; nothing decides on it.
	Summary        string
	Severity       string
	CVSSScore      float64
	EPSS           float64
	KEV            bool
	ExploitPublic  bool
	AffectedRanges []string
	// CarrierProducts are the products the card's sources say CARRY the flaw
	// (EDR-CORRELATION-01 D4), read from Knowledge unchanged. Governance classifies nothing —
	// Knowledge already matched this Finding's components against exactly this list, and the
	// result is each component's claim class. They are carried so an unresolved attribution can
	// NAME the carrier it could not place (EDR-ATTRIBUTION-01 D10); empty means no source named
	// one at all.
	CarrierProducts []string
	// Applicabilities are the vendor VEX statements the card holds, with the scope the VENDOR
	// stated. Themis's determination about whether each covers this release is computed per
	// Finding (see VendorStatement) and never written back onto these (EDR-VEX-02 D1).
	Applicabilities []Applicability
	// FixedVersions holds the fixes that apply to THIS Finding's components — selected, not
	// the card's flat union. See selectFixes.
	FixedVersions []string
	// Fixes is the same selection with its package attribution intact, so a consumer can say
	// "upgrade python3-ply (source python-ply) to X" rather than emit a bare version string.
	Fixes []FixedVersion
	// UnattributedFixes counts fixes the card holds that could NOT be tied to this Finding's
	// components. It is reported rather than silently dropped: "we hold 94 fix versions and
	// none is attributable to your component" is a materially different statement from "no fix
	// has been published", and a consumer must be able to tell them apart.
	UnattributedFixes int
	// RangeTrust is the trust class of the sources that contributed the ranges
	// (EDR-TRUST-01 T2/T3), carried so a consumer knows what the range evidence is worth.
	RangeTrust value.TrustClass
}

// FixedVersion is a published fix version together with the package — and, when the source said,
// the canonical ecosystem — it was published for. Ecosystem "" means "not stated" and never
// excludes (only positive evidence of mismatch does — EDR-VEX-01 D8).
type FixedVersion struct {
	Package   string
	Version   string
	Ecosystem string
}

// FaultlineKnowledgeReader reads a Faultline's enrichment from Knowledge's read API. It is a
// read-only seam (T10): Governance never touches Knowledge's tables.
type FaultlineKnowledgeReader interface {
	GetFaultline(ctx context.Context, faultlineID string) (FaultlineKnowledge, error)
}

// FindingAssessment is a **Domain Projection** (EDR-TRUST-01 T10): everything needed to
// assess one Finding — the release-scoped concern itself, plus what is known about the CVE
// it rests on.
//
// It is named for the **business view it represents**, not for any consumer. A dashboard
// rendering a finding-detail page wants exactly this, and so does a report, and so does the
// AI Runtime. Naming it after a capability (`recommend_position_context`) would have
// guaranteed it was never reused, and would have let AI become a driver of the domain model
// rather than one consumer of it.
//
// It is assembled **only** from Governance's own aggregate plus Knowledge's read API — never
// a cross-context import, never a foreign table. That is the same discipline `ReleasePosture`
// already follows: own findings + a Knowledge-derived score (by event) + a Registry-derived
// multiplier (one read-API call per release, fail-safe when unreachable).
type FindingAssessment struct {
	Finding   domain.Finding
	Knowledge FaultlineKnowledge
	// VendorStatements are the card's vendor VEX statements with Themis's per-release
	// applicability determination beside each (EDR-VEX-02 D2). Present so a statement that was
	// BLOCKED still reaches the reviewer: a non-applicable statement raises no Proposal, and
	// without this it would disappear from the drawer instead of being visibly inapplicable.
	VendorStatements []VendorStatement
	// Attribution states BOTH SIDES of the carrier question for this Finding — what the card
	// says carries the flaw, what is actually installed, and whether Themis could relate the
	// two (EDR-ATTRIBUTION-01 D10/D11/D14).
	Attribution Attribution
}

// Attribution statuses. A small closed set on purpose: D13 defers any richer taxonomy until the
// population is measured, and an enum invented ahead of that measurement is the mistake R4 names.
const (
	// AttributionAttributed — at least one installed component acts as a carrier. The ordinary
	// case, and the one where a remediation plan and the AI's grounding have a subject.
	AttributionAttributed = "attributed"
	// AttributionUnresolved — components are recorded and EVERY one is scope-class, so nothing
	// installed is evidenced to carry the flaw. This is the Attribution Gap (D1): an
	// OBSERVATION about the evidence, never a verdict that the release is unaffected.
	AttributionUnresolved = "unresolved"
	// AttributionNoComponents — the Finding lists no components at all. Distinct from a gap,
	// which requires something installed to have gone unattributed.
	AttributionNoComponents = "no_components"
)

// Attribution is the carrier question, answered at READ TIME from facts both sides already
// hold: the card's carrier products (Knowledge) and this Finding's matched components with
// their claim classes (Governance). It is a PROJECTION and stores nothing — D3 settled that,
// and copying a derived fact onto the aggregate is the generation-stamp trap this repo has hit
// twice. `VendorStatements` beside it is the same shape for the same reason.
//
// Its value is that it states BOTH SIDES. "Attribution gap" as a bare label leaves a reviewer to
// infer from claim classes what Themis could not relate; naming the carrier it could not place
// ("carrier: http_server · installed: httpd") turns the same fact into something a human can act
// on — and makes visible that the two names are a vocabulary problem, not an absence of risk.
type Attribution struct {
	// Status is one of the three constants above.
	Status string
	// Carriers are the products the card says carry the flaw, verbatim from Knowledge. Empty
	// means NO source named one — a materially different gap from "named, none matched", and
	// the split D13's measurement needs.
	Carriers []string
	// Components are the installed components this Finding matched, by name. The other side.
	Components []string
	// UnresolvedBecause states, in plain language, why the two sides could not be related —
	// per-Finding DATA, and empty unless Status is AttributionUnresolved.
	//
	// D11: only the facts that VARY belong here. What evidence would RESOLVE the gap is
	// identical on every one of the 227 measured instances, so it is documentation
	// (EDR-ATTRIBUTION-01), not a field — a value that never varies carries no information, and
	// persisting invariant prose into a projection turns it into a CMS.
	UnresolvedBecause []string
}

// attributionFor derives the projection. Governance re-derives NO classification here: it reads
// the claim classes Knowledge already decided (D3's equivalence — "every component is
// scope-class" is exactly the gap) and pairs them with the carriers the card named.
func attributionFor(comps []domain.MatchedComponent, carriers []string) Attribution {
	a := Attribution{Carriers: carriers}
	if len(comps) == 0 {
		a.Status = AttributionNoComponents
		return a
	}
	a.Components = make([]string, 0, len(comps))
	attributed := false
	for _, c := range comps {
		a.Components = append(a.Components, c.Name)
		if c.ActsAsCarrier() {
			attributed = true // unknown counts as carrier — absence of evidence never hides risk
		}
	}
	if attributed {
		a.Status = AttributionAttributed
		return a
	}
	a.Status = AttributionUnresolved
	if len(carriers) == 0 {
		// The uncounted half of the gap: `vm-verify` reports the population as "carrier named,
		// none matched", which cannot be true of a card that named none. Stating it separately
		// is what lets the two be counted apart (D13's measurement).
		a.UnresolvedBecause = []string{
			"no source named a product that carries this flaw, so there was nothing to match against",
		}
		return a
	}
	a.UnresolvedBecause = []string{
		"the card names carrier product(s) " + strings.Join(carriers, ", "),
		"the installed component(s) here are " + strings.Join(a.Components, ", "),
		"no deterministic identity relationship between the two is established",
	}
	return a
}

// GetFindingAssessment builds the projection for one Finding.
//
// The Knowledge read is **best-effort**: an unreachable Knowledge degrades to the Finding
// alone rather than failing the whole projection, mirroring `ReleasePosture`'s fail-safe
// blast-radius read. A consumer that needs the enrichment can see it is absent; one that
// does not is unaffected. Failing outright would make a Knowledge outage look like a missing
// Finding.
func (s *ReadService) GetFindingAssessment(ctx context.Context, id domain.FindingID) (FindingAssessment, error) {
	f, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return FindingAssessment{}, err
	}
	out := FindingAssessment{Finding: f}
	if s.knowledge == nil {
		return out, nil // no Knowledge seam wired (single-context dev)
	}
	if k, kerr := s.knowledge.GetFaultline(ctx, f.FaultlineID()); kerr == nil {
		// ACTIVE components only — this is a read projection, and a withdrawn twin must not
		// appear in it, pull in a fix version, or count toward the carrier question
		// (KN-SCAN-4(b); measured 2026-09-22 as `httpd, httpd` for one installed component).
		active := f.ActiveComponents()
		out.Knowledge = selectFixes(k, active)
		out.VendorStatements = vendorStatements(&f, releaseScopeFor(ctx, s.repo, &f), k.Applicabilities)
		out.Attribution = attributionFor(active, k.CarrierProducts)
	}
	return out, nil
}

// VendorStatement is one vendor VEX statement as EVIDENCE, beside Themis's separate
// determination about whether it covers this release (EDR-VEX-02 D1/D2).
//
// The three concepts stay in three fields and never collapse: `Status` and `Justification` are
// the vendor's, verbatim; `ScopeFamily`/`ScopeMajor` are the scope the VENDOR stated; and
// `Applicability` is Themis's conclusion. Nothing here rewrites the vendor's words.
type VendorStatement struct {
	Package       string
	Status        string
	Justification string
	ScopeFamily   string
	ScopeMajor    string
	// Applicability is `applicable` / `not_applicable` / `unknown` (D3). Only `applicable` can
	// have become a Proposal; the other two are shown so a reviewer can see that Red Hat DID
	// speak about this package and why it did not clear the Finding — the audit trail this whole
	// arc exists for. `unknown` is epistemic uncertainty, never product mismatch (D4).
	Applicability string
}

// vendorStatements pairs each statement the card holds with Themis's determination for THIS
// Finding. It exists so a blocked statement stays visible: a statement whose scope does not cover
// the release raises no Proposal, so without this it would vanish from the drawer entirely —
// which would recreate the invisibility D2 forbids.
func vendorStatements(f *domain.Finding, release value.ProductScope, apps []Applicability) []VendorStatement {
	if len(apps) == 0 {
		return nil
	}
	out := make([]VendorStatement, 0, len(apps))
	for _, a := range apps {
		out = append(out, VendorStatement{
			Package: a.Package, Status: a.Status, Justification: a.Justification,
			ScopeFamily: a.Scope.Family, ScopeMajor: a.Scope.Major,
			Applicability: string(applicabilityOf(release, a)),
		})
	}
	return out
}

// selectFixes narrows a card's fix versions to the ones published for THIS Finding's components
// (EDR-TRUST-01 T9 — Selection), and is the correctness half of AI-GROUND-1.
//
// A Faultline card is enterprise-wide: one card per CVE, carrying every package that CVE touches.
// CVE-2007-4559's card holds 94 fix versions across Cython, PyYAML, numpy and dozens more. A
// Finding is component-scoped, so handing it the whole union does not merely add noise — it
// invites a false conclusion. Measured on a live model: given the union, a recommendation
// reasoned that `python3-ply 3.9-9.el8` was affected because it sorted below
// `0:0.1.7-16.module+el8.9.0`, a version belonging to an entirely different package, and returned
// that at confidence 0.99.
//
// Matching runs over MatchedComponent.FixKeys() — source package, then namespace:name, then bare
// name — because one component has several names across naming authorities.
//
// When nothing matches, the fix list is left EMPTY and the count is reported instead. That is a
// deliberate choice to say less: an empty list with "94 unattributable" is honest and leads a
// consumer (or a model) to `insufficient`, whereas the union leads it to a confident wrong answer.
// Fewer facts beat wrong ones when the output is a security decision.
// selectFixesFor narrows a fix list to the entries published for the given components, over
// MatchedComponent.FixKeys() — the source package, then namespace:name, then the bare name.
//
// Shared by the read-time projection and the enrichment-time materialization, because two
// implementations of "which fix is mine?" would eventually disagree, and the disagreement would
// show up as a dashboard and a plan recommending different versions for the same component.
//
// The name match alone is not enough (KN-FIX-3, measured: a Rocky rpm `perl` Finding was offered
// an Alpine apk version, an EL7 build, and its real fix side by side). A fix must also survive
// two positive-evidence checks against the component it name-matched (fixAppliesTo); anything
// excluded joins the UnattributedFixes count rather than silently vanishing.
func selectFixesFor(fixes []FixedVersion, comps []domain.MatchedComponent) []FixedVersion {
	if len(fixes) == 0 {
		return nil
	}
	out := make([]FixedVersion, 0, len(fixes))
	for _, f := range fixes {
		for _, c := range comps {
			// A CLEARED occurrence needs nothing (EDR-VERDICT-01 D8): its files already carry
			// the fix, so letting it pull "its" fix into the Finding's list would tell an
			// operator to upgrade something that is done — and once every carrier is cleared,
			// an empty list is the honest answer. Open occurrences select exactly as before.
			if !c.VerdictIsOpen() {
				continue
			}
			if fixAppliesTo(f, c) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// fixAppliesTo reports whether one published fix is honestly attributable to one component.
// Every check excludes only on POSITIVE evidence of mismatch and fails open on absence
// (EDR-VEX-01 D8) — the same direction as ClaimUnknown → carrier:
//
//  1. the fix's package must be one of the component's names (FixKeys);
//  2. a KNOWN fix ecosystem must equal the component's canonical ecosystem — an apk bound is
//     not a fix for an rpm, however exactly the names match;
//  3. an rpm fix whose `.elN` major is known must share the installed build's — the EL7 backport
//     is not what an EL8 host upgrades to. Display/grounding honesty only: the fixed-VERDICT
//     (value.RPMFixedByStream) always enforced this and is untouched.
func fixAppliesTo(f FixedVersion, c domain.MatchedComponent) bool {
	nameOK := false
	for _, key := range c.FixKeys() {
		if strings.EqualFold(key, f.Package) {
			nameOK = true
			break
		}
	}
	if !nameOK {
		return false
	}
	fixEco := value.CanonicalEcosystem(f.Ecosystem)
	if fixEco != "" {
		if compEco := value.CanonicalEcosystem(c.Ecosystem); compEco != "" && compEco != fixEco {
			return false
		}
		if fixEco == "rpm" {
			fixMajor, instMajor := value.RPMReleaseMajor(f.Version), value.RPMReleaseMajor(c.Version)
			if fixMajor != "" && instMajor != "" && fixMajor != instMajor {
				return false
			}
		}
	}
	return true
}

func selectFixes(k FaultlineKnowledge, comps []domain.MatchedComponent) FaultlineKnowledge {
	if len(k.Fixes) == 0 {
		// The card carries no attributed fixes at all (an older card, or sources that cannot
		// attribute — NVD keys on CPE, scanners report bare versions). Report the union's size
		// rather than passing the union on.
		k.UnattributedFixes = len(k.FixedVersions)
		k.FixedVersions = nil
		return k
	}
	mine := selectFixesFor(k.Fixes, comps)
	versions := make([]string, 0, len(mine))
	for _, f := range mine {
		versions = append(versions, f.Version)
	}
	k.UnattributedFixes = len(k.Fixes) - len(mine)
	k.Fixes, k.FixedVersions = mine, versions
	return k
}
