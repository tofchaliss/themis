package domain

import (
	"github.com/themis-project/themis/internal/kernel/value"
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
	// signals is the CURRENT exploitability picture for this Finding's CVE, refreshed from each
	// enrichment. It is denormalized onto the Finding for the same reason base_score is: a
	// decision needs it at the moment it is taken, and reaching across to Knowledge then would
	// make the record of WHY depend on a live read succeeding.
	signals   ExploitSignals
	stage     Stage
	proposals []GovernanceProposal
	positions []Position
	version   int
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
func ReconstituteFinding(id FindingID, releaseID, faultlineID, cve string, components []MatchedComponent, stage Stage, proposals []GovernanceProposal, positions []Position, version int, signals ...ExploitSignals) Finding {
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
		// Variadic so every existing caller is untouched: a Finding rebuilt without signals reads
		// as "nothing known", which is the CONSERVATIVE direction — any positive signal later
		// looks like drift and re-surfaces the Finding, and a redundant review costs attention
		// where a missed one costs a breach.
		signals: firstSignal(signals),
	}
}

func firstSignal(s []ExploitSignals) ExploitSignals {
	if len(s) == 0 {
		return ExploitSignals{}
	}
	return s[0]
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
		version:   len(f.positions) + 1,
		stance:    f.proposals[idx].stance,
		rationale: f.proposals[idx].rationale,
		actor:     by,
		// Snapshot the exploitability picture the decision is being taken WITH (GOV-14b). Taken
		// from the Finding rather than passed in, so the human triage path records it exactly as
		// the policy path does — a decision's premise must not depend on who took it.
		inputs:        PositionInputs{AcceptedProposalID: id, FaultlineRef: f.faultlineID, DecidedWith: f.signals},
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

// CoversPackage reports whether a vendor VEX statement about `pkg` applies to this Finding —
// i.e. one of its matched components IS that package (EDR-VEX-01 D4). A VEX product id is
// matched against a component's full PURL, its bare name, or the PURL without the `@version`
// suffix (the common vendor form, e.g. "pkg:rpm/openssl" for "pkg:rpm/openssl@1.0.2"). Empty
// `pkg` never matches. The match is intentionally conservative: a broader/looser heuristic
// could suppress the wrong Finding, and suppression is a governed, human-overridable step.
func (f Finding) CoversPackage(pkg string) bool {
	pkg = strings.TrimSpace(pkg)
	if pkg == "" {
		return false
	}
	for _, c := range f.components {
		if c.PURL == pkg || c.Name == pkg || strings.HasPrefix(c.PURL, pkg+"@") {
			return true
		}
	}
	return false
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

// Vouches reports whether a cited evidence reference resolves against what THIS Finding
// actually is — the Business Verification check (EDR-TRUST-01 T8).
//
// It is computed from Governance's own aggregate, deliberately: the AI Runtime's Grounding
// Verification proves the model reasoned only from the context it was handed, but that
// context was supplied to it. Only the context owner can say whether the claim is consistent
// with the system of record. That is what makes a stale or forged projection **useless**
// rather than merely unlikely to be accepted.
func (f Finding) Vouches(ref string) bool {
	if ref == "" {
		return false
	}
	switch ref {
	case string(f.id), f.faultlineID, f.cve:
		return true
	}
	for _, c := range f.components {
		if c.PURL == ref {
			return true
		}
	}
	return false
}

// Reservation is a recorded caveat that a decision rested on evidence weaker than Observed
// — for example an acceptance leaning on a vendor's Asserted `not_affected` (EDR-TRUST-01
// T12). It names the class and who supplied the evidence, so "how sound was that call?"
// has an answer months later.
//
// A reservation is a property of **evidence**, never of the decision, so it is **derived
// from the Position's immutable inputs and never persisted as state**. There is no
// "accepted with warning" lifecycle status: the Position's state records what Governance
// decided; the reservation explains what that decision rested on.
type Reservation struct {
	EvidenceTrust value.TrustClass // class of the evidence the accepted proposal rested on
	Proposer      Actor            // who supplied that evidence
}

// CurrentReservation returns the reservation on the Finding's current Position, if any.
// ok=false means either no Position yet, or one resting on Observed evidence — nothing to
// caveat.
//
// It cannot drift, because it is recomputed from the accepted proposal rather than stored
// alongside it. And it lifts by itself: when better evidence later establishes a NEW
// Position version, that version simply carries no reservation — no migration, no backfill,
// and the history shows the caveat disappearing.
func (f Finding) CurrentReservation() (Reservation, bool) {
	pos, ok := f.CurrentPosition()
	if !ok {
		return Reservation{}, false
	}
	for _, p := range f.proposals {
		if p.ID() != pos.Inputs().AcceptedProposalID {
			continue
		}
		// MaxTrust normalizes an unset class to Inferred, so a Position whose evidence was
		// never stated is reserved rather than silently treated as trusted.
		class := value.MaxTrust(p.EvidenceTrust())
		if class == value.TrustObserved {
			return Reservation{}, false
		}
		return Reservation{EvidenceTrust: class, Proposer: p.Proposer()}, true
	}
	// A Position whose accepted proposal is not present (e.g. a partial projection) cannot
	// be vouched for — reserve it rather than imply it was well-evidenced.
	return Reservation{EvidenceTrust: value.TrustInferred}, true
}

// Signals returns the current exploitability picture recorded on this Finding (GOV-14b).
func (f Finding) Signals() ExploitSignals { return f.signals }

// RefreshSignals records the current exploitability picture. It is denormalized read-state, not a
// decision: it bumps no version and emits nothing, exactly like the base score beside it. What
// makes it matter is that AcceptProposal snapshots it, so every Position records the premise it
// was taken on.
func (f *Finding) RefreshSignals(s ExploitSignals) { f.signals = s }
