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

// PrepareEvidenceRegistered runs the inbound event's READ phase (inventory/document reads +
// discovery) OUTSIDE any transaction and returns an apply func that performs only the writes,
// to be run inside the inbox transaction. Splitting read from write keeps that transaction
// short so it never pins the cluster xmin and stalls the bus reader's gap-free watermark
// (EDR-EVENTBUS-01 D7). Dispatch is by kind: an SBOM correlates its inventory; an uploaded VEX
// folds its applicability statements (D2). A kind handled elsewhere (e.g. scanner reports)
// returns a nil apply — the inbox treats that as a no-op.
func (c *Coordinator) PrepareEvidenceRegistered(ctx context.Context, e EvidenceRegistered) (func(context.Context) error, error) {
	switch e.Kind {
	case "sbom":
		plan, err := c.correlate.PlanCorrelation(ctx, e.ReleaseID, e.EvidenceID)
		if err != nil {
			return nil, err
		}
		return func(txCtx context.Context) error {
			_, err := c.correlate.ApplyCorrelation(txCtx, plan)
			return err
		}, nil
	case "vex":
		plan, err := c.vex.PlanVEX(ctx, e.EvidenceID)
		if err != nil {
			return nil, err
		}
		return func(txCtx context.Context) error {
			return c.vex.ApplyVEX(txCtx, plan)
		}, nil
	default:
		return nil, nil
	}
}

// OnEvidenceRegistered runs both phases back-to-back on the given context. It is the direct
// (non-inbox) entry point; the event path calls PrepareEvidenceRegistered so discovery I/O
// stays outside the transaction. Other kinds are ignored — they fold in via their own paths.
func (c *Coordinator) OnEvidenceRegistered(ctx context.Context, e EvidenceRegistered) error {
	apply, err := c.PrepareEvidenceRegistered(ctx, e)
	if err != nil {
		return err
	}
	if apply == nil {
		return nil
	}
	return apply(ctx)
}
