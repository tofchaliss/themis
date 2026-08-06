package app

import (
	"context"

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
	FixedVersions  []string
	// RangeTrust is the trust class of the sources that contributed the ranges
	// (EDR-TRUST-01 T2/T3), carried so a consumer knows what the range evidence is worth.
	RangeTrust value.TrustClass
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
		out.Knowledge = k
	}
	return out, nil
}
