package domain

import (
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// ProposalID is a Governance Proposal's own opaque identity, unique within a Finding.
type ProposalID string

// ProposalStatus is a Governance Proposal's lifecycle state: Proposed → Accepted /
// Rejected (D4). Evaluation is the act of accepting or rejecting; the status resolves
// exactly once and is then retained as history (never re-opened).
type ProposalStatus string

const (
	StatusProposed ProposalStatus = "proposed"
	StatusAccepted ProposalStatus = "accepted"
	StatusRejected ProposalStatus = "rejected"
)

// GovernanceProposal is a first-class proposed decision about a Finding (D4), from any
// source — knowledge evolution, a human analyst, a policy, or AI. No proposal is
// authoritative (CON-0002): it proposes a stance + rationale and is evaluated into an
// accept/reject. Its identity, proposer, stance, and raised time are immutable; only the
// status (and the decider that set it) transition once, on evaluation.
type GovernanceProposal struct {
	id        ProposalID
	proposer  Actor
	stance    Stance
	rationale string
	raisedAt  time.Time
	status    ProposalStatus
	decidedBy Actor
	decidedAt time.Time
	// evidenceTrust is the trust class of the evidence this proposal rests on
	// (EDR-TRUST-01 T2/T3) — a property of the evidence, never of the proposer (T1).
	// It is what the constitutional check reads; the proposer is recorded only for
	// explainability and authority, not for trust.
	evidenceTrust value.TrustClass
}

// NewGovernanceProposal builds a freshly proposed decision (status Proposed). The
// proposer is recorded but grants no authority — deciding is a separate, governed step
// (D11).
func NewGovernanceProposal(
	id ProposalID, proposer Actor, stance Stance, rationale string, raisedAt time.Time, evidenceTrust value.TrustClass,
) (GovernanceProposal, error) {
	if strings.TrimSpace(string(id)) == "" {
		return GovernanceProposal{}, errEmptyProposalID
	}
	if err := validActor(proposer); err != nil {
		return GovernanceProposal{}, err
	}
	if !stance.Valid() {
		return GovernanceProposal{}, errInvalidStance
	}
	if raisedAt.IsZero() {
		return GovernanceProposal{}, errZeroTime
	}
	return GovernanceProposal{
		id:            id,
		proposer:      proposer,
		stance:        stance,
		rationale:     rationale,
		raisedAt:      raisedAt.UTC(),
		status:        StatusProposed,
		evidenceTrust: evidenceTrust,
	}, nil
}

// ReconstituteProposal rebuilds a Governance Proposal from persisted state (store
// adapter). Persistence is trusted; no re-validation is performed.
func ReconstituteProposal(
	id ProposalID, proposer Actor, stance Stance, rationale string, raisedAt time.Time,
	status ProposalStatus, decidedBy Actor, decidedAt time.Time, evidenceTrust value.TrustClass,
) GovernanceProposal {
	return GovernanceProposal{
		id:            id,
		proposer:      proposer,
		stance:        stance,
		rationale:     rationale,
		raisedAt:      raisedAt.UTC(),
		status:        status,
		decidedBy:     decidedBy,
		decidedAt:     decidedAt.UTC(),
		evidenceTrust: evidenceTrust,
	}
}

// ID returns the proposal's identity (unique within its Finding).
func (p GovernanceProposal) ID() ProposalID { return p.id }

// Proposer returns who raised the proposal (human / AI / policy / system).
func (p GovernanceProposal) Proposer() Actor { return p.proposer }

// Stance returns the proposed decision value.
func (p GovernanceProposal) Stance() Stance { return p.stance }

// Rationale returns the proposed justification.
func (p GovernanceProposal) Rationale() string { return p.rationale }

// RaisedAt returns when the proposal was raised.
func (p GovernanceProposal) RaisedAt() time.Time { return p.raisedAt }

// Status returns the proposal's lifecycle status.
func (p GovernanceProposal) Status() ProposalStatus { return p.status }

// DecidedBy returns the actor that accepted/rejected the proposal (zero until decided).
func (p GovernanceProposal) DecidedBy() Actor { return p.decidedBy }

// DecidedAt returns when the proposal was decided (zero until decided).
func (p GovernanceProposal) DecidedAt() time.Time { return p.decidedAt }

// EvidenceTrust returns the trust class of the evidence this proposal rests on. An unset
// class is deliberately NOT normalized here: value.MaxTrust reads unset as Inferred, so a
// proposal raised without stating its evidence is barred from automatic acceptance rather
// than silently treated as trusted.
func (p GovernanceProposal) EvidenceTrust() value.TrustClass { return p.evidenceTrust }

// IsOpen reports whether the proposal is still awaiting a decision.
func (p GovernanceProposal) IsOpen() bool { return p.status == StatusProposed }

// decide resolves an open proposal to accepted/rejected, recording the decider and time.
// It is unexported: only the Finding aggregate drives the decision, in one transaction
// with the resulting Position/lifecycle change (D9).
func (p *GovernanceProposal) decide(status ProposalStatus, by Actor, at time.Time) {
	p.status = status
	p.decidedBy = by
	p.decidedAt = at.UTC()
}
