package app

import (
	"context"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
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
	Score       int // CVE-intrinsic base priority 0–100 (C6) of the card at match time; stamped onto the Finding at open so it is not stranded at 0 on an already-enriched card (BUG-3).
}

// InboundFaultlineEnriched is Knowledge's FaultlineEnriched fact: a Faultline's enterprise
// view changed (D6). It carries the coarse headline Governance re-evaluates against, plus the
// reconciled vendor VEX statements (EDR-VEX-01 D5) it may suppress a Finding with.
type InboundFaultlineEnriched struct {
	FaultlineID     string
	CVE             string
	Severity        string
	KEV             bool
	ExploitPublic   bool
	Score           int // CVE-intrinsic base priority 0–100 (C6); Governance scales it by the blast multiplier (C2).
	Applicabilities []Applicability
	// Per-field-group trust from Knowledge's reconciled view (EDR-TRUST-01 T2/T3). Unset
	// on a payload predating the field; value.MaxTrust reads unset as Inferred, so a
	// consumer that folds one in without checking degrades conservatively.
	HeadlineTrust value.TrustClass
	RangeTrust    value.TrustClass
	SignalTrust   value.TrustClass
	// EPSS is the reconciled exploitation probability, used to detect drift against a suppressing
	// decision's premise (GOV-14b).
	EPSS float64
	// AffectedRanges is Knowledge's reconciled, backport-aware range (D3).
	AffectedRanges []string
}

// InboundFaultlineSuperseded is Knowledge's FaultlineSuperseded fact: the CVE was withdrawn
// or rejected upstream (D6 — maps to a Not-Affected proposal).
type InboundFaultlineSuperseded struct {
	FaultlineID string
	CVE         string
	// Trust is the class Knowledge assigned to the source that reported the withdrawal
	// (TRUST-4). Empty on a payload predating the field — see evidenceTrustFor.
	Trust value.TrustClass
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
	_, err := c.svc.OpenOrUpdateFinding(ctx, m.ReleaseID, m.FaultlineID, m.CVE, m.Score, m.Components)
	return err
}

// OnFaultlineEnriched re-evaluates the affected Findings — raising a system proposal +
// flagging for review, never auto-deciding (D6).
func (c *Coordinator) OnFaultlineEnriched(ctx context.Context, e InboundFaultlineEnriched) error {
	return c.svc.ReactToEnrichment(ctx, EnrichmentSignal{
		FaultlineID:     e.FaultlineID,
		KEV:             e.KEV,
		HighSeverity:    isHighSeverity(e.Severity),
		Score:           e.Score,
		Applicabilities: e.Applicabilities,
		HeadlineTrust:   e.HeadlineTrust,
		RangeTrust:      e.RangeTrust,
		SignalTrust:     e.SignalTrust,
		AffectedRanges:  e.AffectedRanges,
		Signals:         domain.ExploitSignals{KEV: e.KEV, ExploitPublic: e.ExploitPublic, EPSS: e.EPSS},
	})
}

// OnFaultlineSuperseded re-evaluates the affected Findings for a withdrawn/rejected CVE
// (D6): a system Not-Affected proposal per Finding (auto-accepted only by a policy).
// The withdrawal path carries **no** trust class yet: knowledge.faultline_superseded.v1 does
// not include one. A withdrawal is reproducible (re-fetch and the CVE is still rejected), so
// it is genuinely Observed — but unset reads as Inferred under value.MaxTrust, and the
// constitutional bar (T4) would then block a policy auto-accept that works today. Group 4
// must classify this path explicitly before it consumes trust. Tracked as TRUST-4.
func (c *Coordinator) OnFaultlineSuperseded(ctx context.Context, s InboundFaultlineSuperseded) error {
	return c.svc.ReactToEnrichment(ctx, EnrichmentSignal{
		FaultlineID: s.FaultlineID, Withdrawn: true, WithdrawnTrust: s.Trust,
	})
}

// isHighSeverity reports whether a coarse severity headline warrants a re-prioritize
// proposal (D6). The absolute high/critical bands stand in for "severity increased" until
// a richer enrichment signal (prior-vs-new) is carried across the seam.
func isHighSeverity(severity string) bool {
	return severity == "high" || severity == "critical"
}
