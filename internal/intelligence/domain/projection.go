package domain

// FindingAssessment is the **Domain Projection** the runtime receives (EDR-TRUST-01 T10):
// everything needed to assess one Finding, produced by the context that owns the Finding
// Selection Type and named for the business view it represents.
//
// It is **authoritative** — an owning context vouches for it — which is what lets Grounding
// Verification anchor here. The runtime does not compose it, does not know how it was built,
// and issues no follow-up reads to complete it.
type FindingAssessment struct {
	Finding   FindingView
	Knowledge FaultlineView
}

// Grounds reports whether a non-empty evidence citation refers to something in the
// **authoritative projection** (T8/T10 rule 4).
//
// It deliberately lives on the projection rather than on the shaped context. A runtime that
// validated against its own transformed view would be checking the model against something
// it produced itself — a buggy or over-eager transformation would be *confirmed* rather than
// caught. Anchoring here makes that impossible by construction rather than by convention.
func (p FindingAssessment) Grounds(ref string) bool {
	if ref == "" {
		return false
	}
	switch ref {
	case p.Finding.ID, p.Finding.FaultlineID, p.Finding.CVE, p.Knowledge.ID, p.Knowledge.CVE:
		return true
	}
	for _, purl := range p.Finding.Components {
		if purl == ref {
			return true
		}
	}
	return false
}
