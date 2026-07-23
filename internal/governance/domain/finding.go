package domain

import (
	"strings"
	"time"
)

// FindingID is the Finding's own opaque, stable identity (D1) — never the CVE, never the
// Faultline id, never a composite string.
type FindingID string

// Finding is Governance's release-scoped record of how one Faultline affects one Release
// (D1): its own identity, keyed by the (Release, Faultline) pair; the matched components
// as content; an explicit investigation lifecycle (D7); append-only Governance Proposals
// (D4) and append-only immutable Enterprise Position versions (D3); and a materialized
// "current position" (the latest version). It is one aggregate and one consistency
// boundary (D9), guarded by an optimistic version. State changes only through its domain
// operations — never a direct field edit. It references the Faultline by immutable id and
// never owns knowledge (D1/DOM-0026).
type Finding struct {
	id          FindingID
	releaseID   string
	faultlineID string
	cve         string // carried alias for thin events / reads (D8); the id is authoritative
	components  []MatchedComponent
	stage       Stage
	proposals   []GovernanceProposal
	positions   []Position
	version     int
}

// NewFinding opens a Finding for a (Release, Faultline) pair at stage Identified with no
// components, proposals, or Position (D5: "found, not yet decided"). The CVE is a carried
// alias for downstream events; the (Release, Faultline) pair is the identity.
func NewFinding(id FindingID, releaseID, faultlineID, cve string) (Finding, error) {
	if strings.TrimSpace(string(id)) == "" {
		return Finding{}, errEmptyFindingID
	}
	if strings.TrimSpace(releaseID) == "" {
		return Finding{}, errEmptyReleaseID
	}
	if strings.TrimSpace(faultlineID) == "" {
		return Finding{}, errEmptyFaultlineID
	}
	return Finding{
		id:          id,
		releaseID:   releaseID,
		faultlineID: faultlineID,
		cve:         cve,
		stage:       StageIdentified,
	}, nil
}

// ReconstituteFinding rebuilds a Finding from persisted state (store adapter). Persistence
// is trusted; no re-validation is performed.
func ReconstituteFinding(id FindingID, releaseID, faultlineID, cve string, components []MatchedComponent, stage Stage, proposals []GovernanceProposal, positions []Position, version int) Finding {
	return Finding{
		id:          id,
		releaseID:   releaseID,
		faultlineID: faultlineID,
		cve:         cve,
		components:  append([]MatchedComponent(nil), components...),
		stage:       stage,
		proposals:   append([]GovernanceProposal(nil), proposals...),
		positions:   append([]Position(nil), positions...),
		version:     version,
	}
}

// AbsorbComponent idempotently records a matched component as content (D5): a component
// whose PURL is already present is a no-op (re-scans and event re-delivery converge on
// one Finding), otherwise it is appended and the version bumped. It reports whether the
// component was newly added.
func (f *Finding) AbsorbComponent(c MatchedComponent) (bool, error) {
	if err := validComponent(c); err != nil {
		return false, err
	}
	for _, existing := range f.components {
		if existing.PURL == c.PURL {
			return false, nil
		}
	}
	f.components = append(f.components, c)
	f.version++
	return true, nil
}

// RaiseProposal records a first-class Governance Proposal against the Finding (D4) and
// flags it for review by moving to Under Investigation — the reopen path (D7) when the
// Finding was Monitoring/Resolved. Raising is the single proposer entry (human / AI /
// policy / knowledge-evolution); it never decides. A Finding is Archived-terminal: no
// proposal may be raised against a retired release.
func (f *Finding) RaiseProposal(p GovernanceProposal) error {
	if strings.TrimSpace(string(p.id)) == "" {
		return errEmptyProposalID
	}
	if !p.IsOpen() {
		return ErrProposalNotOpen
	}
	if f.stage == StageArchived {
		return ErrIllegalTransition
	}
	if _, exists := f.indexOfProposal(p.id); exists {
		return ErrDuplicateProposal
	}
	f.proposals = append(f.proposals, p)
	// Any active stage flags for review / reopens to Under Investigation (all non-Archived
	// stages can legally reach it — see the transition table).
	f.stage = StageUnderInvestigation
	f.version++
	return nil
}

// AcceptProposal is the governed decision (D4/D9): it accepts an open proposal, establishes
// a new immutable Enterprise Position version from its stance, advances the lifecycle to
// Position Established on the first decision (a later revision never resets the stage —
// D7), and bumps the version — all on the one aggregate, in one transaction at the store.
// The deciding actor is recorded (CON-0003); the app enforces the authority line (D11).
func (f *Finding) AcceptProposal(id ProposalID, by Actor, at time.Time) (Position, error) {
	if err := validActor(by); err != nil {
		return Position{}, err
	}
	if at.IsZero() {
		return Position{}, errZeroTime
	}
	if f.stage == StageArchived {
		return Position{}, ErrIllegalTransition
	}
	idx, ok := f.indexOfProposal(id)
	if !ok {
		return Position{}, ErrProposalNotFound
	}
	if !f.proposals[idx].IsOpen() {
		return Position{}, ErrProposalNotOpen
	}
	f.proposals[idx].decide(StatusAccepted, by, at)
	pos := Position{
		version:       len(f.positions) + 1,
		stance:        f.proposals[idx].stance,
		rationale:     f.proposals[idx].rationale,
		actor:         by,
		inputs:        PositionInputs{AcceptedProposalID: id, FaultlineRef: f.faultlineID},
		establishedAt: at.UTC(),
	}
	f.positions = append(f.positions, pos)
	if f.stage == StageIdentified || f.stage == StageUnderInvestigation {
		f.stage = StagePositionEstablished
	}
	f.version++
	return pos, nil
}

// RejectProposal evaluates an open proposal to Rejected, retaining it as history (D4). It
// establishes no Position and does not change the lifecycle stage (investigation stays
// open). The deciding actor is recorded.
func (f *Finding) RejectProposal(id ProposalID, by Actor, at time.Time) error {
	if err := validActor(by); err != nil {
		return err
	}
	if at.IsZero() {
		return errZeroTime
	}
	if f.stage == StageArchived {
		return ErrIllegalTransition
	}
	idx, ok := f.indexOfProposal(id)
	if !ok {
		return ErrProposalNotFound
	}
	if !f.proposals[idx].IsOpen() {
		return ErrProposalNotOpen
	}
	f.proposals[idx].decide(StatusRejected, by, at)
	f.version++
	return nil
}

// MarkMonitoring moves a Position-Established Finding to Monitoring (position set, watching
// for change — D7). Only legal from Position Established (or a no-op if already Monitoring).
func (f *Finding) MarkMonitoring() error {
	if f.stage != StagePositionEstablished && f.stage != StageMonitoring {
		return ErrIllegalTransition
	}
	_, err := f.transition(StageMonitoring)
	return err
}

// Resolve closes the concern (fixed / mitigated / not-affected — D7). Reopenable. Illegal
// only from Archived.
func (f *Finding) Resolve() error {
	_, err := f.transition(StageResolved)
	return err
}

// Reopen takes the governed reopen path (D7) — Monitoring/Resolved → Under Investigation —
// when new knowledge raises a proposal. Illegal from any other stage.
func (f *Finding) Reopen() error {
	if f.stage != StageMonitoring && f.stage != StageResolved {
		return ErrIllegalTransition
	}
	_, err := f.transition(StageUnderInvestigation)
	return err
}

// Archive moves the Finding to the terminal Archived stage (release retired — D7).
func (f *Finding) Archive() error {
	_, err := f.transition(StageArchived)
	return err
}

// transition applies a governed lifecycle move (D7): it rejects an illegal transition,
// treats a move to the current stage as a no-op, and otherwise advances the stage and
// bumps the version. It reports whether the stage actually changed.
func (f *Finding) transition(target Stage) (bool, error) {
	if !f.stage.canTransitionTo(target) {
		return false, ErrIllegalTransition
	}
	if target == f.stage {
		return false, nil
	}
	f.stage = target
	f.version++
	return true, nil
}

func (f *Finding) indexOfProposal(id ProposalID) (int, bool) {
	for i := range f.proposals {
		if f.proposals[i].id == id {
			return i, true
		}
	}
	return 0, false
}

// ID returns the Finding's stable identity.
func (f Finding) ID() FindingID { return f.id }

// ReleaseID returns the Release this Finding is scoped to (half of the business key).
func (f Finding) ReleaseID() string { return f.releaseID }

// FaultlineID returns the immutable id of the referenced global Faultline (the other half
// of the business key).
func (f Finding) FaultlineID() string { return f.faultlineID }

// CVE returns the carried CVE alias (for thin events / reads); the ids are authoritative.
func (f Finding) CVE() string { return f.cve }

// Components returns a copy of the matched components (content, not identity).
func (f Finding) Components() []MatchedComponent {
	return append([]MatchedComponent(nil), f.components...)
}

// Stage returns the current investigation lifecycle stage.
func (f Finding) Stage() Stage { return f.stage }

// Proposals returns a copy of the append-only Governance Proposals (accepted, rejected,
// and open) — full decision history for explainability (CON-0003).
func (f Finding) Proposals() []GovernanceProposal {
	return append([]GovernanceProposal(nil), f.proposals...)
}

// Positions returns a copy of the append-only immutable Enterprise Position versions,
// oldest first (the last is the current position).
func (f Finding) Positions() []Position {
	return append([]Position(nil), f.positions...)
}

// CurrentPosition returns the latest (current) Enterprise Position and whether one exists;
// a Finding may legitimately have none yet ("found, not yet decided" — D2).
func (f Finding) CurrentPosition() (Position, bool) {
	if len(f.positions) == 0 {
		return Position{}, false
	}
	return f.positions[len(f.positions)-1], true
}

// Version returns the optimistic-concurrency version stamp.
func (f Finding) Version() int { return f.version }
