package domain

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
// human still decides ("Gathering Is Not Knowing"). Ranking by release-to-release delta stays
// deferred (G-AI-3).
type PrecedentPosition struct {
	ReleaseID string
	Stance    string
	Rationale string
	SourceCVE string  // CVE of the precedent decision (may differ from the subject — Δ3a semantic precedent)
	Component string  // representative component of the precedent decision (label)
	Score     float64 // cosine similarity in [0,1] for a Δ3a retrieved precedent; 0 for a Δ2 exact-CVE precedent
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
	// one of Projection / Release is populated, decided by the capability's Selection Type.
	Release    ReleasePosture
	Precedents []PrecedentPosition
}

// Finding returns the subject Finding from the authoritative projection.
func (c AssembledContext) Finding() FindingView { return c.Projection.Finding }

// Faultline returns the CVE knowledge from the authoritative projection.
func (c AssembledContext) Faultline() FaultlineView { return c.Projection.Knowledge }

// Grounds delegates to the authoritative projection (T10 rule 4). A shaped view can never
// widen what counts as grounded — that is the whole point of anchoring to authority.
func (c AssembledContext) Grounds(ref string) bool {
	if c.Release.ReleaseID != "" {
		return c.Release.Grounds(ref)
	}
	return c.Projection.Grounds(ref)
}
