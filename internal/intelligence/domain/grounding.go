package domain

import "fmt"

// FindingView is Intelligence's read-only view of a Governance Finding (D5) — the
// grounding subject of a position recommendation. It is a value mirror decoded from
// Governance's read API (FindingView JSON), never Governance's aggregate
// (Intelligence owns no truth, D1; no cross-context import).
type FindingView struct {
	ID          string
	ReleaseID   string
	FaultlineID string
	CVE         string
	Stage       string
	Components  []string // component purls
	// ClaimClasses aligns with Components: `carrier`, `scope`, or "" = unknown per component
	// (EDR-CORRELATION-01 D3). Carried for AI-204-2's thinness diagnosis — unknown is treated
	// as carrier everywhere, so only an explicit all-`scope` set reads as thin.
	ClaimClasses []string
}

// GroundingThinness names the deterministic reason a Decision capability's grounding cannot
// support a stance, when the backend already knows it BEFORE any model runs (AI-204-2).
// Returns "" when the grounding is not deterministically thin. Telemetry-only by decision:
// the 204 header stays opaque (AI-204-1's invariant); this string lands in Outcome.Detail so
// a decline's journal line carries its why — and so the eval loop (G-AI-2c) can tell "model
// can't reason" from "grounding had nothing to reason about".
func GroundingThinness(a FindingAssessment) string {
	f := a.Finding
	// All matched components explicitly scope-class ⇒ zero carriers: nothing in the grounding
	// says any component CARRIES the flaw (the CVE-2026-42496 case — 37 components, all from a
	// module-stream rebuild set). Unknown ("") counts as carrier, per EDR-CORRELATION-01.
	if n := len(f.Components); n > 0 && n == len(f.ClaimClasses) {
		scope := 0
		for _, c := range f.ClaimClasses {
			if c == "scope" {
				scope++
			}
		}
		if scope == n {
			return fmt.Sprintf("grounding: %d component(s), all scope-class (zero carriers) — no evidence any component carries the flaw", n)
		}
	}
	// No version evidence at all: nothing to run a range verdict on and no fix to reason from.
	if len(a.Knowledge.AffectedRanges) == 0 && len(a.Knowledge.FixedVersions) == 0 && a.Knowledge.UnattributedFixes == 0 {
		return "grounding: no affected ranges and no fix versions on record — nothing for a version verdict to stand on"
	}
	return ""
}

// FaultlineView is Intelligence's read-only view of a Knowledge Faultline's
// enrichment (D5, decoded from Knowledge's FaultlineView/EnterpriseView JSON) — the
// core risk signal grounding a recommendation.
type FaultlineView struct {
	ID  string
	CVE string
	// Summary is Knowledge's reconciled short account of WHAT the CVE is — already bounded at
	// ingestion, so it cannot blow the prompt budget (the AI-CTX-1 class). Grounding
	// Verification does not anchor to it; it informs the model the way it informs a human.
	Summary       string
	Severity      string
	CVSSScore     float64
	EPSS          float64
	KEV           bool
	ExploitPublic bool
	// FixedVersions are the fixes published for THIS finding's components, already SELECTED by
	// Governance (EDR-TRUST-01 T9). They are NOT the card's cross-package union: given the union
	// a model reasoned that python3-ply 3.9 was affected because it sorted below another
	// package's 0:0.1.7-16, at confidence 0.99 (AI-GROUND-1).
	FixedVersions []string
	// UnattributedFixes counts fixes the card holds that could not be tied to this component.
	// Surfaced to the model so an empty fix list is not read as "no fix exists" — the honest
	// reading is "a fix may exist but we cannot say which", which argues for `insufficient`.
	UnattributedFixes int
	AffectedRanges    []string
}

// FixAvailable reports whether the Faultline has any known fixed version.
func (f FaultlineView) FixAvailable() bool { return len(f.FixedVersions) > 0 }

// PrecedentPosition is one of our own past Enterprise Positions pulled into grounding as
// labeled context. Δ2 pulls precedent on the SAME CVE from other releases (exact match,
// Score 0); Δ3a's Knowledge Engine additionally retrieves SEMANTICALLY similar past decisions
// — possibly a DIFFERENT CVE on the same component or bug-class — each with a cosine Score in
// [0,1] (Book IV Ch 8, RC-1). It is context, not instruction: the AI only reads it and the
// human still decides ("Gathering Is Not Knowing"). Ranking is delta-aware (G-AI-3): the
// PrecedentService weights each precedent by how much the release it was decided on overlaps
// the release under judgment, and both consumers see the same weight.
type PrecedentPosition struct {
	ReleaseID string
	Stance    string
	Rationale string
	SourceCVE string  // CVE of the precedent decision (may differ from the subject — Δ3a semantic precedent)
	Component string  // representative component of the precedent decision (label)
	Score     float64 // cosine similarity in [0,1] for a Δ3a retrieved precedent; 0 for a Δ2 exact-CVE precedent
	// ReleaseOverlap is the posture overlap between the precedent's release and the subject's
	// (G-AI-3): |persisting| / (|fixed|+|new|+|persisting|) from the deterministic comparison
	// read (EDR-GOVERNANCE-01 D16). 1.0 = the releases share their whole open surface; 0 =
	// nothing in common. Meaningful only when OverlapKnown — an unreadable or empty comparison
	// leaves the precedent unweighted rather than penalized.
	ReleaseOverlap float64
	OverlapKnown   bool
}

// DeltaWeight is the G-AI-3 down-weight: how much of a precedent's retrieval score survives
// the release-to-release delta. An identical release keeps everything (1.0); a completely
// disjoint one keeps half (0.5) — down-weighted, NEVER dropped, because the precedent stays
// clearly labeled and the model/human weigh it themselves. Unknown overlap weighs 1.0.
func (p PrecedentPosition) DeltaWeight() float64 {
	if !p.OverlapKnown {
		return 1.0
	}
	return 0.5 + 0.5*p.ReleaseOverlap
}

// RankScore is the ordering key the PrecedentService sorts by (G-AI-3): the cosine similarity
// scaled by the delta weight for a semantic precedent; the delta weight alone for an exact-CVE
// precedent (whose Score is 0 by construction, not "no similarity").
func (p PrecedentPosition) RankScore() float64 {
	if p.Score > 0 {
		return p.Score * p.DeltaWeight()
	}
	return p.DeltaWeight()
}

// AssembledContext is the **Capability Context** (EDR-TRUST-01 T10): the shape a capability
// reasons over, derived in memory from the received Domain Projection and never persisted.
//
// It is a **view, not a source**. Shaping may reduce (filter, sort, group, summarise) but may
// introduce nothing the projection did not contain (rule 2), every element stays traceable to
// it (rule 3), and Grounding Verification anchors to the projection rather than to this
// (rule 4) — which is why Grounds delegates instead of re-implementing.
//
// Precedents are the one addition, and deliberately NOT citable evidence: they are
// supplementary reasoning context retrieved from the runtime's own semantic index, so they
// are excluded from Grounds by construction.
type AssembledContext struct {
	Projection FindingAssessment
	// Release is the authoritative projection when the subject is a Release (T9/T10). Exactly
	// one of Projection / Release / Comparison is populated, decided by the capability's
	// Selection Type and declared Needs.
	Release ReleasePosture
	// Comparison is the authoritative projection when the capability declared
	// NeedReleaseComparison (AI-CMP-1): Governance's cross-release diff, received verbatim.
	Comparison ReleaseComparison
	Precedents []PrecedentPosition
}

// Finding returns the subject Finding from the authoritative projection.
func (c AssembledContext) Finding() FindingView { return c.Projection.Finding }

// Faultline returns the CVE knowledge from the authoritative projection.
func (c AssembledContext) Faultline() FaultlineView { return c.Projection.Knowledge }

// Grounds delegates to the authoritative projection (T10 rule 4). A shaped view can never
// widen what counts as grounded — that is the whole point of anchoring to authority.
func (c AssembledContext) Grounds(ref string) bool {
	if c.Comparison.CandidateID != "" {
		return c.Comparison.Grounds(ref)
	}
	if c.Release.ReleaseID != "" {
		return c.Release.Grounds(ref)
	}
	return c.Projection.Grounds(ref)
}
