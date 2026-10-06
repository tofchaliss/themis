package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// Harness integration (EDR-HARNESS-01): Themis commissions governed
// work against a Finding BEFORE it runs, the AI runtime executes under
// that commission and produces a reconstructable record, and a human
// raises a Proposal whose evidence is that execution. Governance
// equality-checks the execution against the commission at proposal
// time and never reads the runtime's record itself (D-I-1, D-C-5).

var (
	ErrCommissionNotFound      = errors.New("governance: commission not found")
	ErrCommissionWithdrawn     = errors.New("governance: commission withdrawn")
	ErrCommissionMismatch      = errors.New("governance: execution does not correspond to the commission")
	ErrCommissionActor         = errors.New("governance: only an authenticated human may commission or withdraw")
	ErrCommissionMalformed     = errors.New("governance: malformed commission")
	ErrDuplicateCommission     = errors.New("governance: duplicate commission id")
	ErrHarnessEvidenceInvalid  = errors.New("governance: harness execution evidence is malformed")
	ErrHarnessEvidenceTrust    = errors.New("governance: submitted trust class is not the class the evidence derives")
	ErrHarnessEvidenceNoCommit = errors.New("governance: execution cites no commission")
)

var (
	shaHex    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	nameAtVer = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}@[1-9][0-9]*$`)
)

// CommissionID is the Themis-minted identity of a commission (UUID v4
// from the kernel id generator; the SHAPE is the generator's property,
// like every other Themis id — the domain requires presence, not form).
// The runtime records it in its CREATED event; existence-before-
// reference is the ordering proof (D-C-2).
type CommissionID string

// MethodIdentity is the governed method commissioned: the runtime's
// skill name@version and the catalog composition hash. Opaque to
// Themis — recorded and equality-checked, never interpreted (D-C-2).
type MethodIdentity struct {
	Skill       string // name@version
	Composition string // sha256 hex
}

// DeploymentIdentity is the governed deployment commissioned: the
// runtime's anchor name@version and artifact hash. Opaque likewise.
type DeploymentIdentity struct {
	Anchor   string // name@version
	Artifact string // sha256 hex
}

// CommissionPremise is the Finding state observed when the commission
// was created — descriptive, never a lock (D-C-2).
type CommissionPremise struct {
	Stage           Stage
	PositionVersion int
}

// CommissionState is open → withdrawn, forward-only (D-C-3).
type CommissionState string

const (
	CommissionStateOpen      CommissionState = "open"
	CommissionStateWithdrawn CommissionState = "withdrawn"
)

// Commission is an immutable, pre-execution Governance authority record
// (D-C-1, D-C-2): reusable across executions, never consumed (D-C-3).
type Commission struct {
	id             CommissionID
	method         MethodIdentity
	deployment     DeploymentIdentity
	commissionedBy Actor
	premise        CommissionPremise
	rationale      string
	raisedAt       time.Time

	state              CommissionState
	withdrawnBy        Actor
	withdrawnAt        time.Time
	withdrawalRational string
}

func (c Commission) ID() CommissionID               { return c.id }
func (c Commission) Method() MethodIdentity         { return c.method }
func (c Commission) Deployment() DeploymentIdentity { return c.deployment }
func (c Commission) CommissionedBy() Actor          { return c.commissionedBy }
func (c Commission) Premise() CommissionPremise     { return c.premise }
func (c Commission) Rationale() string              { return c.rationale }
func (c Commission) RaisedAt() time.Time            { return c.raisedAt }
func (c Commission) State() CommissionState         { return c.state }
func (c Commission) WithdrawnBy() Actor             { return c.withdrawnBy }
func (c Commission) WithdrawnAt() time.Time         { return c.withdrawnAt }
func (c Commission) WithdrawalRationale() string    { return c.withdrawalRational }
func (c Commission) IsOpen() bool                   { return c.state == CommissionStateOpen }

func validMethod(m MethodIdentity) error {
	if !nameAtVer.MatchString(m.Skill) || !shaHex.MatchString(m.Composition) {
		return ErrCommissionMalformed
	}
	return nil
}

func validDeployment(d DeploymentIdentity) error {
	if !nameAtVer.MatchString(d.Anchor) || !shaHex.MatchString(d.Artifact) {
		return ErrCommissionMalformed
	}
	return nil
}

// NewCommission builds an open commission. Only a human actor may
// commission (D-C-6): AI, policy, and system actors would be automation
// authorizing the very work whose output it later influences.
func NewCommission(id CommissionID, method MethodIdentity, deployment DeploymentIdentity, by Actor, premise CommissionPremise, rationale string, at time.Time) (Commission, error) {
	if strings.TrimSpace(string(id)) == "" {
		return Commission{}, ErrCommissionMalformed
	}
	if err := validMethod(method); err != nil {
		return Commission{}, err
	}
	if err := validDeployment(deployment); err != nil {
		return Commission{}, err
	}
	if err := validActor(by); err != nil {
		return Commission{}, err
	}
	if by.Kind != ActorHuman {
		return Commission{}, ErrCommissionActor
	}
	if at.IsZero() {
		return Commission{}, errZeroTime
	}
	return Commission{
		id: id, method: method, deployment: deployment, commissionedBy: by,
		premise: premise, rationale: rationale, raisedAt: at.UTC(), state: CommissionStateOpen,
	}, nil
}

// ReconstituteCommission rebuilds a commission from persisted state.
func ReconstituteCommission(id CommissionID, method MethodIdentity, deployment DeploymentIdentity, by Actor, premise CommissionPremise, rationale string, at time.Time, state CommissionState, withdrawnBy Actor, withdrawnAt time.Time, withdrawalRationale string) Commission {
	return Commission{
		id: id, method: method, deployment: deployment, commissionedBy: by, premise: premise,
		rationale: rationale, raisedAt: at.UTC(), state: state, withdrawnBy: withdrawnBy,
		withdrawnAt: withdrawnAt.UTC(), withdrawalRational: withdrawalRationale,
	}
}

// --- Finding aggregate operations ------------------------------------

func (f *Finding) indexOfCommission(id CommissionID) (int, bool) {
	for i, c := range f.commissions {
		if c.id == id {
			return i, true
		}
	}
	return 0, false
}

// Commissions returns the append-only commission history.
func (f *Finding) Commissions() []Commission {
	return append([]Commission(nil), f.commissions...)
}

// Commission records authority to perform governed work against this
// Finding (D-C-1). Allowed at every non-terminal stage; it changes NO
// investigation stage (D-C-4). The premise is captured here from the
// Finding as observed.
func (f *Finding) Commission(id CommissionID, method MethodIdentity, deployment DeploymentIdentity, by Actor, rationale string, at time.Time) (Commission, error) {
	if f.stage == StageArchived {
		return Commission{}, ErrIllegalTransition
	}
	if _, exists := f.indexOfCommission(id); exists {
		return Commission{}, ErrDuplicateCommission
	}
	premise := CommissionPremise{Stage: f.stage, PositionVersion: len(f.positions)}
	c, err := NewCommission(id, method, deployment, by, premise, rationale, at)
	if err != nil {
		return Commission{}, err
	}
	f.commissions = append(f.commissions, c)
	f.version++
	return c, nil
}

// WithdrawCommission is the one forward-only transition (D-C-3): a
// Governance fact with its own witness, by any authenticated human,
// never the original commissioner only (D-C-6). Historical executions
// under it are untouched; future proposals citing it are refused.
func (f *Finding) WithdrawCommission(id CommissionID, by Actor, rationale string, at time.Time) error {
	if err := validActor(by); err != nil {
		return err
	}
	if by.Kind != ActorHuman {
		return ErrCommissionActor
	}
	if at.IsZero() {
		return errZeroTime
	}
	idx, ok := f.indexOfCommission(id)
	if !ok {
		return ErrCommissionNotFound
	}
	if !f.commissions[idx].IsOpen() {
		return ErrCommissionWithdrawn
	}
	f.commissions[idx].state = CommissionStateWithdrawn
	f.commissions[idx].withdrawnBy = by
	f.commissions[idx].withdrawnAt = at.UTC()
	f.commissions[idx].withdrawalRational = rationale
	f.version++
	return nil
}

// ReconstituteCommissions sets the persisted commission history on a
// reconstituted Finding (store adapter only).
func ReconstituteCommissions(f *Finding, cs []Commission) {
	f.commissions = append([]Commission(nil), cs...)
}

// --- Harness execution evidence ---------------------------------------

// HarnessDelegations references the runtime's l8-delegation witnesses
// by sequence number only (D-L-1): never copied, never interpreted.
type HarnessDelegations struct {
	Count int
	Seqs  []int64
}

// HarnessExecution is the `harness-execution/v1` evidence a proposal
// rests on (D-I-5): the execution tuple and every identity Themis
// derived from the runtime record through its own intake. Immutable
// once the proposal is raised; the Position later cites it by
// reference. Governance validates its SHAPE and its correspondence to
// the commission; it never re-resolves the runtime record.
type HarnessExecution struct {
	CommissionID CommissionID

	AnchorHash    string // sha256 hex of the anchor bytes
	Anchor        string // name@version
	AnchorState   string // lifecycle state at intake (active | withdrawn)
	TaskID        string
	ArtifactSeq   int64  // artifact-bound seq (the tuple's third element)
	ArtifactID    string // L6 object id sha256:<hex>
	VerifiedPath  string // member of the egress manifest the PASS was about
	VerifiedHash  string // sha256 hex of that member
	Skill         string // name@version, as recorded
	Composition   string // sha256 hex, as recorded
	Contract      string // verification contract name@version
	ContractHash  string
	ContractState string // registry state at intake
	Reconstructed string // reconstruction verdict: consistent-pass
	Witness       string // production witness: l5-witnessed | l6-record-only
	Constitution  string // the record's L6 constitution hash
	HarnessModule string // module@pseudo-version the intake was built against
	Delegations   HarnessDelegations

	// BusinessRefs are the identifiers the proposal claims the Finding
	// vouches for — taken from the RECORDED Finding bytes the execution
	// read (dependency PURL, CVE), never from model output (D-I-5).
	BusinessRefs []string
}

// Validate checks the closed shape. It is deliberately strict: a
// proposal that cites an incomplete execution cannot be raised.
func (e HarnessExecution) Validate() error {
	switch {
	case strings.TrimSpace(string(e.CommissionID)) == "":
		return ErrHarnessEvidenceNoCommit
	case !shaHex.MatchString(e.AnchorHash) || !nameAtVer.MatchString(e.Anchor):
		return ErrHarnessEvidenceInvalid
	case e.AnchorState != "active" && e.AnchorState != "withdrawn":
		return ErrHarnessEvidenceInvalid
	case strings.TrimSpace(e.TaskID) == "" || e.ArtifactSeq < 1:
		return ErrHarnessEvidenceInvalid
	case !strings.HasPrefix(e.ArtifactID, "sha256:") || !shaHex.MatchString(strings.TrimPrefix(e.ArtifactID, "sha256:")):
		return ErrHarnessEvidenceInvalid
	case e.VerifiedPath == "" || !shaHex.MatchString(e.VerifiedHash):
		return ErrHarnessEvidenceInvalid
	case !nameAtVer.MatchString(e.Skill) || !shaHex.MatchString(e.Composition):
		return ErrHarnessEvidenceInvalid
	case !nameAtVer.MatchString(e.Contract) || !shaHex.MatchString(e.ContractHash):
		return ErrHarnessEvidenceInvalid
	case e.ContractState != "active" && e.ContractState != "withdrawn":
		return ErrHarnessEvidenceInvalid
	case e.Reconstructed != "consistent-pass":
		return ErrHarnessEvidenceInvalid
	case e.Witness != "l5-witnessed":
		// D-W-5 / D-L-2: only a five-link, L5-witnessed execution is
		// Position-eligible; an l6-record-only record is inspectable
		// history, never proposal evidence.
		return ErrHarnessEvidenceInvalid
	case !shaHex.MatchString(e.Constitution) || strings.TrimSpace(e.HarnessModule) == "":
		return ErrHarnessEvidenceInvalid
	case e.Delegations.Count != len(e.Delegations.Seqs):
		return ErrHarnessEvidenceInvalid
	case len(e.BusinessRefs) == 0:
		return ErrHarnessEvidenceInvalid
	}
	return nil
}

// DerivedTrust is the deterministic trust classification of a harness
// execution (D-I-5 tightening): the artifact is model-authored, and an
// L10 PASS establishes admissibility, not authorship — so the evidence
// class is Inferred, always. Neither the CLI nor the API may choose it;
// Governance validates the submitted class against this derivation.
func (e HarnessExecution) DerivedTrust() value.TrustClass { return value.TrustInferred }

// Corresponds checks the execution against the commission it cites in
// causal order, first failure named (D-C-5 §4): open → method →
// deployment. The caller has already established the commission exists
// on this Finding.
func (e HarnessExecution) Corresponds(c Commission) error {
	if !c.IsOpen() {
		return ErrCommissionWithdrawn
	}
	if c.method.Skill != e.Skill || c.method.Composition != e.Composition {
		return ErrCommissionMismatch
	}
	if c.deployment.Anchor != e.Anchor || c.deployment.Artifact != e.AnchorHash {
		return ErrCommissionMismatch
	}
	return nil
}

// --- Proposal evidence binding -----------------------------------------

// HarnessEvidence returns the harness execution a proposal rests on,
// or nil for proposals from other sources.
func (p GovernanceProposal) HarnessEvidence() *HarnessExecution {
	if p.harness == nil {
		return nil
	}
	cp := *p.harness
	cp.Delegations.Seqs = append([]int64(nil), cp.Delegations.Seqs...)
	cp.BusinessRefs = append([]string(nil), cp.BusinessRefs...)
	return &cp
}

// NewHarnessProposal builds a proposal whose evidence basis is a
// harness execution: a HUMAN proposer (D-I-5 — the harness is never
// the proposer), the trust class DERIVED from the evidence, and the
// commission id carried on the proposal.
func NewHarnessProposal(id ProposalID, proposer Actor, stance Stance, rationale string, raisedAt time.Time, ev HarnessExecution) (GovernanceProposal, error) {
	if proposer.Kind != ActorHuman {
		return GovernanceProposal{}, errInvalidActorKind
	}
	if err := ev.Validate(); err != nil {
		return GovernanceProposal{}, err
	}
	p, err := NewGovernanceProposal(id, proposer, stance, rationale, raisedAt, ev.DerivedTrust())
	if err != nil {
		return GovernanceProposal{}, err
	}
	cp := ev
	p.harness = &cp
	return p, nil
}

// ReconstituteProposalHarness attaches persisted harness evidence to a
// reconstituted proposal (store adapter only).
func ReconstituteProposalHarness(p *GovernanceProposal, ev *HarnessExecution) {
	p.harness = ev
}

// --- Thin events (D-C-4) --------------------------------------------------

// FindingCommissioned announces a commission was recorded (Governance-
// internal; Communication does not consume it).
type FindingCommissioned struct {
	FindingID    FindingID
	CommissionID CommissionID
	Skill        string
	Anchor       string
	OccurredAt   time.Time
}

// CommissionWithdrawn announces a commission was withdrawn.
type CommissionWithdrawn struct {
	FindingID    FindingID
	CommissionID CommissionID
	OccurredAt   time.Time
}

func NewFindingCommissioned(f Finding, c Commission, at time.Time) FindingCommissioned {
	return FindingCommissioned{FindingID: f.ID(), CommissionID: c.ID(), Skill: c.method.Skill, Anchor: c.deployment.Anchor, OccurredAt: at.UTC()}
}

func NewCommissionWithdrawn(f Finding, id CommissionID, at time.Time) CommissionWithdrawn {
	return CommissionWithdrawn{FindingID: f.ID(), CommissionID: id, OccurredAt: at.UTC()}
}
