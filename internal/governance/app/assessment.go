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
	FaultlineID    string
	CVE            string
	Severity       string
	CVSSScore      float64
	EPSS           float64
	KEV            bool
	ExploitPublic  bool
	AffectedRanges []string
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
		out.Knowledge = selectFixes(k, f.Components())
	}
	return out, nil
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
