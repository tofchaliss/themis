package app

import (
	"context"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// The inbound-seam contract (D5/D6). Governance re-declares the facts it consumes from
// Knowledge rather than importing Knowledge's packages (no cross-context imports); the
// inbound adapter translates the wire event into these.

// OpenFindingInput is the birth-path input for a Finding. It is a struct rather than a
// parameter list because the list had reached three strings, an int and two slices, where
// transposing `cve` and `band` would compile and be wrong.
type OpenFindingInput struct {
	ReleaseID   string
	FaultlineID string
	CVE         string
	Components  []domain.MatchedComponent
	// BaseScore, Band and Fixes are the card's facts AT MATCH TIME, stamped onto the Finding as
	// it is born so it never depends on a later enrichment event that may never arrive
	// (BUG-3 / BUG-3b). Zero/empty means the card had none yet, and the field is left alone.
	BaseScore int
	Band      string
	Fixes     []FixedVersion
}

// InboundComponentMatched is Knowledge's ComponentMatched fact: a Release component matched
// a Faultline (D5).
type InboundComponentMatched struct {
	FaultlineID string
	CVE         string
	ReleaseID   string
	Components  []domain.MatchedComponent
	Score       int // CVE-intrinsic base priority 0–100 (C6) of the card at match time; stamped onto the Finding at open so it is not stranded at 0 on an already-enriched card (BUG-3).
	// Band and Fixes of the card at match time, stamped at open for the same reason as Score
	// (BUG-3b). Without them a Finding opened after its card's LAST enrichment carries neither
	// forever, because the enrichment handler stamps only Findings that already exist.
	Band  string
	Fixes []FixedVersion
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
	// Priority is Knowledge's exploitability band, materialized onto the posture (DASH-2).
	Priority string
	// Fixes are the package-attributed fix versions; Governance selects the ones matching each
	// Finding's components and stamps them (PLAN-3).
	Fixes []FixedVersion
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
	_, err := c.svc.OpenOrUpdateFinding(ctx, OpenFindingInput{
		ReleaseID: m.ReleaseID, FaultlineID: m.FaultlineID, CVE: m.CVE,
		BaseScore: m.Score, Band: m.Band, Fixes: m.Fixes, Components: m.Components,
	})
	return err
}

// InboundComponentVerdictChanged is one existing occurrence whose verdict state changed on a
// Knowledge re-judgement (EDR-VERDICT-01 D5/D6). The component carries the NEW state.
type InboundComponentVerdictChanged struct {
	FaultlineID string
	ReleaseID   string
	Component   domain.MatchedComponent
}

// OnComponentVerdictChanged mirrors a re-judged occurrence verdict onto the Finding's
// component row (D5). Governance never re-derives the verdict and never decides anything
// here — queue membership and priority re-derive from the mirrored state at read time (D7),
// and human decisions stay Positions. A change for a Finding that does not exist (the match
// predates Governance, or arrived out of order) is a no-op, not an error: the ComponentMatched
// that creates it carries the same verdict.
func (c *Coordinator) OnComponentVerdictChanged(ctx context.Context, m InboundComponentVerdictChanged) error {
	return c.svc.MirrorComponentVerdict(ctx, m.ReleaseID, m.FaultlineID, m.Component)
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
		Band:            e.Priority,
		Fixes:           e.Fixes,
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
