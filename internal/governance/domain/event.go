package domain

import "time"

// Governance events are completed business facts (DOM-0033 / D8), published after persist
// via the shared outbox. Payloads are thin: consumers fetch detail via the read API.
//
// Two audiences (D8):
//   - PositionEstablished / PositionRevised are the ONLY events Communication consumes
//     (DOM-0025) — thin: Finding id, Release, Faultline/CVE, Position version, stance.
//   - Finding-lifecycle events (Opened/Resolved/Reopened/Archived) and proposal events
//     (Raised/Accepted/Rejected) are Governance-internal (metrics / audit / workflow).

// FindingOpened announces that a new Finding exists (from a component match — D5).
type FindingOpened struct {
	FindingID   FindingID
	ReleaseID   string
	FaultlineID string
	CVE         string
	OccurredAt  time.Time
}

// FindingResolved announces the Finding's concern was closed.
type FindingResolved struct {
	FindingID  FindingID
	OccurredAt time.Time
}

// FindingReopened announces the Finding re-entered investigation (the governed reopen path).
type FindingReopened struct {
	FindingID  FindingID
	OccurredAt time.Time
}

// FindingArchived announces the Finding reached the terminal Archived stage.
type FindingArchived struct {
	FindingID  FindingID
	OccurredAt time.Time
}

// ProposalRaised announces a Governance Proposal was recorded against a Finding.
type ProposalRaised struct {
	FindingID    FindingID
	ProposalID   ProposalID
	Stance       Stance
	ProposerKind ActorKind
	OccurredAt   time.Time
}

// ProposalAccepted announces a Proposal was accepted, establishing a Position version.
type ProposalAccepted struct {
	FindingID       FindingID
	ProposalID      ProposalID
	PositionVersion int
	OccurredAt      time.Time
}

// ProposalRejected announces a Proposal was rejected (retained as history).
type ProposalRejected struct {
	FindingID  FindingID
	ProposalID ProposalID
	OccurredAt time.Time
}

// PositionEstablished is the first Enterprise Position for a Finding (version 1) — a
// completed fact Communication consumes (DOM-0025).
type PositionEstablished struct {
	FindingID   FindingID
	ReleaseID   string
	FaultlineID string
	CVE         string
	Version     int
	Stance      Stance
	OccurredAt  time.Time
}

// PositionRevised is a subsequent Enterprise Position version (2+) — a completed fact
// Communication consumes (DOM-0025). Same thin shape as PositionEstablished.
type PositionRevised struct {
	FindingID   FindingID
	ReleaseID   string
	FaultlineID string
	CVE         string
	Version     int
	Stance      Stance
	OccurredAt  time.Time
}

// NewFindingOpened builds the event for a newly opened Finding.
func NewFindingOpened(f Finding, at time.Time) FindingOpened {
	return FindingOpened{
		FindingID:   f.ID(),
		ReleaseID:   f.ReleaseID(),
		FaultlineID: f.FaultlineID(),
		CVE:         f.CVE(),
		OccurredAt:  at.UTC(),
	}
}

// NewFindingResolved builds the Resolved event.
func NewFindingResolved(f Finding, at time.Time) FindingResolved {
	return FindingResolved{FindingID: f.ID(), OccurredAt: at.UTC()}
}

// NewFindingReopened builds the Reopened event.
func NewFindingReopened(f Finding, at time.Time) FindingReopened {
	return FindingReopened{FindingID: f.ID(), OccurredAt: at.UTC()}
}

// NewFindingArchived builds the Archived event.
func NewFindingArchived(f Finding, at time.Time) FindingArchived {
	return FindingArchived{FindingID: f.ID(), OccurredAt: at.UTC()}
}

// NewProposalRaised builds the event for a raised Governance Proposal.
func NewProposalRaised(f Finding, p GovernanceProposal, at time.Time) ProposalRaised {
	return ProposalRaised{
		FindingID:    f.ID(),
		ProposalID:   p.ID(),
		Stance:       p.Stance(),
		ProposerKind: p.Proposer().Kind,
		OccurredAt:   at.UTC(),
	}
}

// NewProposalAccepted builds the event for an accepted proposal + its new Position version.
func NewProposalAccepted(f Finding, proposalID ProposalID, pos Position, at time.Time) ProposalAccepted {
	return ProposalAccepted{
		FindingID:       f.ID(),
		ProposalID:      proposalID,
		PositionVersion: pos.Version(),
		OccurredAt:      at.UTC(),
	}
}

// NewProposalRejected builds the event for a rejected proposal.
func NewProposalRejected(f Finding, proposalID ProposalID, at time.Time) ProposalRejected {
	return ProposalRejected{FindingID: f.ID(), ProposalID: proposalID, OccurredAt: at.UTC()}
}

// NewPositionEvent builds the correct outbound Position event for a newly established
// version: PositionEstablished for v1, PositionRevised for v2+. It returns exactly one of
// the two (the other is nil) so the app relays a single Communication-facing fact per
// accepted decision (D8).
func NewPositionEvent(f Finding, pos Position, at time.Time) (*PositionEstablished, *PositionRevised) {
	if pos.Version() <= 1 {
		e := PositionEstablished{
			FindingID:   f.ID(),
			ReleaseID:   f.ReleaseID(),
			FaultlineID: f.FaultlineID(),
			CVE:         f.CVE(),
			Version:     pos.Version(),
			Stance:      pos.Stance(),
			OccurredAt:  at.UTC(),
		}
		return &e, nil
	}
	e := PositionRevised{
		FindingID:   f.ID(),
		ReleaseID:   f.ReleaseID(),
		FaultlineID: f.FaultlineID(),
		CVE:         f.CVE(),
		Version:     pos.Version(),
		Stance:      pos.Stance(),
		OccurredAt:  at.UTC(),
	}
	return nil, &e
}
