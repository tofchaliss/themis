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
	ID             string
	CVE            string
	Severity       string
	CVSSScore      float64
	EPSS           float64
	KEV            bool
	ExploitPublic  bool
	FixedVersions  []string
	AffectedRanges []string
}

// FixAvailable reports whether the Faultline has any known fixed version.
func (f FaultlineView) FixAvailable() bool { return len(f.FixedVersions) > 0 }

// AssembledContext is the deterministic output of Context Construction (D5): exactly
// the grounding a capability declared it needs, assembled via read-API Knowledge
// Providers. It is the anti-hallucination ground truth — stage-2 validation checks
// (via Grounds) that every cited evidence ref exists here.
type AssembledContext struct {
	Finding   FindingView
	Faultline FaultlineView
}

// Grounds reports whether a non-empty evidence citation ref refers to something in
// the assembled context (D7 anti-hallucination). Δ1 grounds the subject Finding, its
// Faultline, their CVE aliases, and the Finding's component purls.
func (c AssembledContext) Grounds(ref string) bool {
	if ref == "" {
		return false
	}
	switch ref {
	case c.Finding.ID, c.Finding.FaultlineID, c.Finding.CVE, c.Faultline.ID, c.Faultline.CVE:
		return true
	}
	for _, purl := range c.Finding.Components {
		if purl == ref {
			return true
		}
	}
	return false
}
