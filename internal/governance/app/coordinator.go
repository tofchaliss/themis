package app

import (
	"context"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The inbound-seam contract (D5/D6). Governance re-declares the facts it consumes from
// Knowledge rather than importing Knowledge's packages (no cross-context imports); the
// inbound adapter translates the wire event into these.

// InboundComponentMatched is Knowledge's ComponentMatched fact: a Release component matched
// a Faultline (D5).
type InboundComponentMatched struct {
	FaultlineID string
	CVE         string
	ReleaseID   string
	Components  []domain.MatchedComponent
}

// InboundFaultlineEnriched is Knowledge's FaultlineEnriched fact: a Faultline's enterprise
// view changed (D6). It carries the coarse headline Governance re-evaluates against.
type InboundFaultlineEnriched struct {
	FaultlineID   string
	CVE           string
	Severity      string
	KEV           bool
	ExploitPublic bool
}

// InboundFaultlineSuperseded is Knowledge's FaultlineSuperseded fact: the CVE was withdrawn
// or rejected upstream (D6 — maps to a Not-Affected proposal).
type InboundFaultlineSuperseded struct {
	FaultlineID string
	CVE         string
}

// Coordinator sequences the inbound Knowledge seam by calling the app services only
// (BCK-0044). It owns no state and enforces no rules — it translates a completed Knowledge
// fact into the matching Governance use case and lets the service govern it (D5/D6).
type Coordinator struct {
	svc *FindingService
}

// NewCoordinator wires the coordinator over the Finding service.
func NewCoordinator(svc *FindingService) *Coordinator { return &Coordinator{svc: svc} }

// OnComponentMatched opens-or-updates the (Release, Faultline) Finding for a match (D5).
func (c *Coordinator) OnComponentMatched(ctx context.Context, m InboundComponentMatched) error {
	_, err := c.svc.OpenOrUpdateFinding(ctx, m.ReleaseID, m.FaultlineID, m.CVE, m.Components)
	return err
}

// OnFaultlineEnriched re-evaluates the affected Findings — raising a system proposal +
// flagging for review, never auto-deciding (D6).
func (c *Coordinator) OnFaultlineEnriched(ctx context.Context, e InboundFaultlineEnriched) error {
	return c.svc.ReactToEnrichment(ctx, EnrichmentSignal{
		FaultlineID:  e.FaultlineID,
		KEV:          e.KEV,
		HighSeverity: isHighSeverity(e.Severity),
	})
}

// OnFaultlineSuperseded re-evaluates the affected Findings for a withdrawn/rejected CVE
// (D6): a system Not-Affected proposal per Finding (auto-accepted only by a policy).
func (c *Coordinator) OnFaultlineSuperseded(ctx context.Context, s InboundFaultlineSuperseded) error {
	return c.svc.ReactToEnrichment(ctx, EnrichmentSignal{FaultlineID: s.FaultlineID, Withdrawn: true})
}

// isHighSeverity reports whether a coarse severity headline warrants a re-prioritize
// proposal (D6). The absolute high/critical bands stand in for "severity increased" until
// a richer enrichment signal (prior-vs-new) is carried across the seam.
func isHighSeverity(severity string) bool {
	return severity == "high" || severity == "critical"
}
