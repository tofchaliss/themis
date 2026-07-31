package app

import "context"

// EvidenceRegistered is the inbound fact the coordinator reacts to, carried from
// Evidence's EvidenceRegistered event by the event-consumer adapter.
type EvidenceRegistered struct {
	EvidenceID string
	ReleaseID  string
	Kind       string
}

// Coordinator sequences the inbound-evidence flows (BCK-0044) by calling app services only;
// it owns no aggregates and enforces no business rules. An SBOM drives correlation; an
// uploaded VEX drives applicability folding (EDR-VEX-01 D2).
type Coordinator struct {
	correlate *CorrelationService
	vex       *VEXApplicabilityService
}

// NewCoordinator wires the coordinator over the correlation and VEX-applicability services.
func NewCoordinator(c *CorrelationService, vex *VEXApplicabilityService) *Coordinator {
	return &Coordinator{correlate: c, vex: vex}
}

// OnEvidenceRegistered dispatches by kind: an SBOM correlates its inventory; an uploaded VEX
// folds its applicability statements onto the cards (D2). Other kinds (e.g. scanner reports)
// are ignored here — they fold in via their own paths.
func (c *Coordinator) OnEvidenceRegistered(ctx context.Context, e EvidenceRegistered) error {
	switch e.Kind {
	case "sbom":
		_, err := c.correlate.Correlate(ctx, e.ReleaseID, e.EvidenceID)
		return err
	case "vex":
		return c.vex.Apply(ctx, e.EvidenceID)
	default:
		return nil
	}
}
