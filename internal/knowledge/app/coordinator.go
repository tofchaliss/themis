package app

import "context"

// EvidenceRegistered is the inbound fact the coordinator reacts to, carried from
// Evidence's EvidenceRegistered event by the event-consumer adapter.
type EvidenceRegistered struct {
	EvidenceID string
	ReleaseID  string
	Kind       string
}

// Coordinator sequences the new-SBOM → correlate flow (BCK-0044) by calling app
// services only; it owns no aggregates and enforces no business rules.
type Coordinator struct {
	correlate *CorrelationService
}

// NewCoordinator wires the coordinator over the correlation service.
func NewCoordinator(c *CorrelationService) *Coordinator { return &Coordinator{correlate: c} }

// OnEvidenceRegistered runs correlation for a newly registered SBOM. Non-SBOM evidence
// (VEX / scanner reports) folds in via its own ACLs, not correlation, so it is ignored
// here.
func (c *Coordinator) OnEvidenceRegistered(ctx context.Context, e EvidenceRegistered) error {
	if e.Kind != "sbom" {
		return nil
	}
	_, err := c.correlate.Correlate(ctx, e.ReleaseID, e.EvidenceID)
	return err
}
