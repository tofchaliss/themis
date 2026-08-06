package domain

import (
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Knowledge events are completed business facts published on an actual Faultline state
// change — never on the mere arrival of a Proposal (D8; DOM-0033). Payloads are thin
// (mirroring Evidence D6): consumers fetch detail via the read API.

// FaultlineCreated announces that a new card exists.
type FaultlineCreated struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// FaultlineEnriched announces that the enterprise view changed. It carries a coarse
// headline (severity + exploit signals) so Governance can re-evaluate (EDR-GOVERNANCE-01
// D6) without fetching the whole card.
type FaultlineEnriched struct {
	FaultlineID   FaultlineID
	CVE           string
	Severity      value.Severity
	KEV           bool
	ExploitPublic bool
	// Score is the CVE-intrinsic composite priority (0–100), snapshotted so Governance can
	// apply its release-scoped blast multiplier without refetching the card (C6 → C2).
	Score int
	// Applicabilities carries the reconciled vendor VEX statements (EDR-VEX-01 D5) so Governance
	// can raise a system not_affected Proposal on the affected Findings without fetching the card.
	// Optional/additive (omitempty): a card with no vendor statement keeps the frozen v1 wire
	// byte-identical (EVENTBUS D9 — additive, non-breaking).
	Applicabilities []Applicability `json:"Applicabilities,omitempty"`
	// AffectedRanges is the reconciled, backport-aware affected range (D3), carried so
	// Governance can re-evaluate an EXISTING Finding against it (EDR-TRUST-01 T5) — the case
	// correlation's own range gate cannot reach, because that gate only runs at match time,
	// so a Finding born before the range was known is never revisited.
	AffectedRanges []string `json:"AffectedRanges,omitempty"`
	// Trust classes for the reconciled view's field-groups (EDR-TRUST-01 T2/T3), so
	// Governance can apply the constitutional check (T4) and derive reservations (T12)
	// without refetching the card.
	//
	// These must ride the wire rather than being re-derived downstream: re-derivation
	// would require Governance to hold a **second copy** of the source→class policy, and
	// two copies of a trust policy will eventually disagree. Knowledge owns the table, so
	// Knowledge ships the verdict.
	//
	// Additive and optional (omitempty), like Score and Applicabilities before them: a
	// payload from before this change stays byte-identical, and an older consumer ignores
	// them (EVENTBUS D9 — additive, non-breaking, no schema version bump).
	HeadlineTrust value.TrustClass `json:"HeadlineTrust,omitempty"`
	RangeTrust    value.TrustClass `json:"RangeTrust,omitempty"`
	SignalTrust   value.TrustClass `json:"SignalTrust,omitempty"`
	OccurredAt    time.Time
}

// FaultlineMatured announces the card reached the Mature stage.
type FaultlineMatured struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// FaultlineSuperseded announces the card reached the terminal Superseded stage.
type FaultlineSuperseded struct {
	FaultlineID FaultlineID
	CVE         string
	OccurredAt  time.Time
}

// MatchedComponent is one release component that matched a card during correlation.
type MatchedComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
}

// ComponentMatched is the correlation output (D3/D8): a release's component matches a
// card. Governance consumes it to create a Finding (EDR-GOVERNANCE-01 D5). It is a
// Proposal, not truth, and never mutates the card.
type ComponentMatched struct {
	FaultlineID FaultlineID
	CVE         string
	ReleaseID   string
	Components  []MatchedComponent
	// Score is the card's CVE-intrinsic composite score (0–100) at match time (C6). Carried so
	// Governance can stamp base_score at finding-open — otherwise a Finding born on an
	// already-enriched card is stranded at 0 until the next enrichment event (BUG-3).
	Score      int
	OccurredAt time.Time
}

// NewFaultlineCreated builds the event for a newly created card.
func NewFaultlineCreated(f Faultline, at time.Time) FaultlineCreated {
	return FaultlineCreated{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewFaultlineEnriched builds the view-change event, snapshotting the current headline and the
// reconciled vendor applicability statements (D5).
func NewFaultlineEnriched(f Faultline, at time.Time) FaultlineEnriched {
	v := f.View()
	return FaultlineEnriched{
		FaultlineID:     f.ID(),
		CVE:             f.CVE().String(),
		Severity:        v.Severity,
		KEV:             v.KEV,
		ExploitPublic:   v.ExploitPublic,
		Score:           v.Score(),
		Applicabilities: append([]Applicability(nil), v.Applicabilities...),
		AffectedRanges:  append([]string(nil), v.AffectedRanges...),
		HeadlineTrust:   v.HeadlineTrust,
		RangeTrust:      v.RangeTrust,
		SignalTrust:     v.SignalTrust,
		OccurredAt:      at.UTC(),
	}
}

// NewFaultlineMatured builds the Mature-stage event.
func NewFaultlineMatured(f Faultline, at time.Time) FaultlineMatured {
	return FaultlineMatured{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewFaultlineSuperseded builds the Superseded-stage event.
func NewFaultlineSuperseded(f Faultline, at time.Time) FaultlineSuperseded {
	return FaultlineSuperseded{FaultlineID: f.ID(), CVE: f.CVE().String(), OccurredAt: at.UTC()}
}

// NewComponentMatched builds the correlation event for a release's matched components.
func NewComponentMatched(f Faultline, releaseID string, components []MatchedComponent, at time.Time) ComponentMatched {
	return ComponentMatched{
		FaultlineID: f.ID(),
		CVE:         f.CVE().String(),
		ReleaseID:   releaseID,
		Components:  append([]MatchedComponent(nil), components...),
		Score:       f.View().Score(),
		OccurredAt:  at.UTC(),
	}
}
