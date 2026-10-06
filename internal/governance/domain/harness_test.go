package domain

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

const (
	cid1 = "c0a8e3d6-5b1e-4f5a-9d3e-2b4c6a8e0f12"
	hA   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hB   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hC   = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var (
	human  = Actor{Kind: ActorHuman, ID: "key:k1"}
	aiKind = Actor{Kind: ActorAI, ID: "cap"}
	method = MethodIdentity{Skill: "remediate-dependency@4", Composition: hA}
	deploy = DeploymentIdentity{Anchor: "rsys@6", Artifact: hB}
	t0     = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
)

func goodEvidence() HarnessExecution {
	return HarnessExecution{
		CommissionID: cid1, AnchorHash: hB, Anchor: "rsys@6", AnchorState: "active", TaskID: "fx-1", ArtifactSeq: 31,
		ArtifactID: "sha256:" + hC, VerifiedPath: "report.json", VerifiedHash: hC, Skill: "remediate-dependency@4", Composition: hA,
		Contract: "report-valid@2", ContractHash: hA, ContractState: "active", Reconstructed: "consistent-pass", Witness: "l5-witnessed",
		Constitution: hA, HarnessModule: "github.com/tofchaliss/themis-ai-runtime/src/harness@v0.0.0-x", BusinessRefs: []string{"CVE-2024-1000"},
	}
}

// D-C-1/2/4/6 on the aggregate: a human commissions at any non-terminal
// stage; the premise is observed, not caused; no stage moves; AI cannot.
func TestFindingCommissionIsAuthorityNotStage(t *testing.T) {
	f, _ := NewFinding("f-1", "r-1", "fl-1", "CVE-2024-1000")
	c, err := f.Commission(cid1, method, deploy, human, "remediate", t0)
	if err != nil {
		t.Fatal(err)
	}
	if f.Stage() != StageIdentified || c.Premise().Stage != StageIdentified || c.Premise().PositionVersion != 0 || !c.IsOpen() {
		t.Fatalf("stage %s premise %+v open %v", f.Stage(), c.Premise(), c.IsOpen())
	}
	if _, err := f.Commission(cid1, method, deploy, human, "again", t0); !errors.Is(err, ErrDuplicateCommission) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := f.Commission("d1e2f3a4-0000-4000-8000-000000000001", method, deploy, aiKind, "x", t0); !errors.Is(err, ErrCommissionActor) {
		t.Fatalf("ai commissioner: %v", err)
	}
	if _, err := f.Commission("", method, deploy, human, "x", t0); !errors.Is(err, ErrCommissionMalformed) {
		t.Fatalf("empty id: %v", err)
	}
	if _, err := f.Commission("d1e2f3a4-0000-4000-8000-000000000003", MethodIdentity{Skill: "Bad Name", Composition: hA}, deploy, human, "x", t0); !errors.Is(err, ErrCommissionMalformed) {
		t.Fatalf("malformed method: %v", err)
	}
	// Withdrawal: forward-only, any human, never AI; a second withdrawal refuses.
	if err := f.WithdrawCommission(cid1, aiKind, "x", t0); !errors.Is(err, ErrCommissionActor) {
		t.Fatalf("ai withdraw: %v", err)
	}
	other := Actor{Kind: ActorHuman, ID: "key:k2"}
	if err := f.WithdrawCommission(cid1, other, "premise moved", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := f.WithdrawCommission(cid1, other, "again", t0); !errors.Is(err, ErrCommissionWithdrawn) {
		t.Fatalf("second withdrawal: %v", err)
	}
	cs := f.Commissions()
	if len(cs) != 1 || cs[0].State() != CommissionStateWithdrawn || cs[0].WithdrawnBy() != other || cs[0].WithdrawalRationale() != "premise moved" {
		t.Fatalf("%+v", cs)
	}
	// Archived refuses commissioning.
	_ = f.Resolve()
	_ = f.Archive()
	if _, err := f.Commission("d1e2f3a4-0000-4000-8000-000000000002", method, deploy, human, "x", t0); !errors.Is(err, ErrIllegalTransition) {
		t.Fatalf("archived: %v", err)
	}
}

// D-I-5 / D-W-5 / D-L-2 shape rules and the derived trust.
func TestHarnessEvidenceShapeAndTrust(t *testing.T) {
	ev := goodEvidence()
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	if ev.DerivedTrust() != value.TrustInferred {
		t.Fatal("harness evidence derives inferred, always")
	}
	mut := func(name string, f func(*HarnessExecution), want error) {
		t.Helper()
		e := goodEvidence()
		f(&e)
		if err := e.Validate(); !errors.Is(err, want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	mut("no commission", func(e *HarnessExecution) { e.CommissionID = "" }, ErrHarnessEvidenceNoCommit)
	mut("l6-only witness is not position-eligible", func(e *HarnessExecution) { e.Witness = "l6-record-only" }, ErrHarnessEvidenceInvalid)
	mut("inconsistent reconstruction", func(e *HarnessExecution) { e.Reconstructed = "inconsistent" }, ErrHarnessEvidenceInvalid)
	mut("bad object id", func(e *HarnessExecution) { e.ArtifactID = hC }, ErrHarnessEvidenceInvalid)
	mut("delegation count mismatch", func(e *HarnessExecution) { e.Delegations.Count = 1 }, ErrHarnessEvidenceInvalid)
	mut("no business refs", func(e *HarnessExecution) { e.BusinessRefs = nil }, ErrHarnessEvidenceInvalid)
	mut("anchor state", func(e *HarnessExecution) { e.AnchorState = "unknown" }, ErrHarnessEvidenceInvalid)
}

// D-C-5 §4: correspondence in causal order, first failure named.
func TestHarnessEvidenceCorrespondsToCommission(t *testing.T) {
	c, _ := NewCommission(cid1, method, deploy, human, CommissionPremise{}, "r", t0)
	ev := goodEvidence()
	if err := ev.Corresponds(c); err != nil {
		t.Fatal(err)
	}
	other := ev
	other.Skill = "remediate-dependency@3"
	if err := other.Corresponds(c); !errors.Is(err, ErrCommissionMismatch) {
		t.Fatalf("method: %v", err)
	}
	other = ev
	other.AnchorHash = hC
	if err := other.Corresponds(c); !errors.Is(err, ErrCommissionMismatch) {
		t.Fatalf("deployment: %v", err)
	}
	wd := c
	wd.state = CommissionStateWithdrawn
	if err := ev.Corresponds(wd); !errors.Is(err, ErrCommissionWithdrawn) {
		t.Fatalf("withdrawn: %v", err)
	}
	// The proposal built on it is human, inferred, and carries the evidence.
	p, err := NewHarnessProposal("p-1", human, StanceMitigated, "fixed", t0, ev)
	if err != nil {
		t.Fatal(err)
	}
	if p.EvidenceTrust() != value.TrustInferred || p.HarnessEvidence() == nil || p.HarnessEvidence().CommissionID != cid1 {
		t.Fatalf("%+v", p)
	}
	if _, err := NewHarnessProposal("p-2", aiKind, StanceMitigated, "x", t0, ev); err == nil {
		t.Fatal("the harness/AI is never the proposer")
	}
	if !strings.HasPrefix(string(p.HarnessEvidence().ArtifactID), "sha256:") {
		t.Fatal("artifact id shape")
	}
}

// Persistence round-trips and the remaining named refusals: every field
// the store adapter reconstitutes reads back unchanged; every guard in
// NewCommission and WithdrawCommission refuses by its own error.
func TestCommissionReconstituteAndGuards(t *testing.T) {
	t1 := t0.Add(2 * time.Hour)
	lead := Actor{Kind: ActorHuman, ID: "key:lead"}
	c := ReconstituteCommission(cid1, method, deploy, human, CommissionPremise{Stage: StageUnderInvestigation, PositionVersion: 2}, "why", t0, CommissionStateWithdrawn, lead, t1, "moved")
	if c.ID() != cid1 || c.Method() != method || c.Deployment() != deploy || c.CommissionedBy() != human || c.Rationale() != "why" || !c.RaisedAt().Equal(t0) {
		t.Fatalf("%+v", c)
	}
	if c.IsOpen() || c.WithdrawnBy() != lead || !c.WithdrawnAt().Equal(t1) || c.WithdrawalRationale() != "moved" || c.Premise().PositionVersion != 2 {
		t.Fatalf("%+v", c)
	}
	f, _ := NewFinding("f-1", "r-1", "fl-1", "CVE-2024-1000")
	ReconstituteCommissions(&f, []Commission{c})
	if cs := f.Commissions(); len(cs) != 1 || cs[0].ID() != cid1 || cs[0].State() != CommissionStateWithdrawn {
		t.Fatalf("%+v", cs)
	}
	// NewCommission guards, each by name.
	if _, err := NewCommission(cid1, method, DeploymentIdentity{Anchor: "rsys@6", Artifact: "nothex"}, human, CommissionPremise{}, "", t0); !errors.Is(err, ErrCommissionMalformed) {
		t.Fatalf("deployment: %v", err)
	}
	if _, err := NewCommission(cid1, method, deploy, Actor{Kind: ActorHuman, ID: " "}, CommissionPremise{}, "", t0); !errors.Is(err, errEmptyActorID) {
		t.Fatalf("blank actor: %v", err)
	}
	if _, err := NewCommission(cid1, method, deploy, human, CommissionPremise{}, "", time.Time{}); !errors.Is(err, errZeroTime) {
		t.Fatalf("zero time: %v", err)
	}
	// WithdrawCommission guards.
	if err := f.WithdrawCommission(cid1, Actor{Kind: "robot", ID: "x"}, "", t0); !errors.Is(err, errInvalidActorKind) {
		t.Fatalf("invalid kind: %v", err)
	}
	if err := f.WithdrawCommission(cid1, human, "", time.Time{}); !errors.Is(err, errZeroTime) {
		t.Fatalf("zero time: %v", err)
	}
	if err := f.WithdrawCommission("d1e2f3a4-0000-4000-8000-00000000ffff", human, "", t0); !errors.Is(err, ErrCommissionNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	// Thin events carry the identities and nothing else.
	ev := NewFindingCommissioned(f, c, t0)
	if ev.FindingID != f.ID() || ev.CommissionID != cid1 || ev.Skill != method.Skill || ev.Anchor != deploy.Anchor || !ev.OccurredAt.Equal(t0) {
		t.Fatalf("%+v", ev)
	}
	wd := NewCommissionWithdrawn(f, cid1, t1)
	if wd.FindingID != f.ID() || wd.CommissionID != cid1 || !wd.OccurredAt.Equal(t1) {
		t.Fatalf("%+v", wd)
	}
}

// The remaining evidence shape rules, one mutation each.
func TestHarnessEvidenceShapeRemainingRules(t *testing.T) {
	mut := func(name string, f func(*HarnessExecution)) {
		t.Helper()
		e := goodEvidence()
		f(&e)
		if err := e.Validate(); !errors.Is(err, ErrHarnessEvidenceInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	mut("anchor hash", func(e *HarnessExecution) { e.AnchorHash = "x" })
	mut("anchor name", func(e *HarnessExecution) { e.Anchor = "RSYS" })
	mut("task id", func(e *HarnessExecution) { e.TaskID = " " })
	mut("artifact seq", func(e *HarnessExecution) { e.ArtifactSeq = 0 })
	mut("verified path", func(e *HarnessExecution) { e.VerifiedPath = "" })
	mut("verified hash", func(e *HarnessExecution) { e.VerifiedHash = "x" })
	mut("skill", func(e *HarnessExecution) { e.Skill = "no-version" })
	mut("composition", func(e *HarnessExecution) { e.Composition = "x" })
	mut("contract", func(e *HarnessExecution) { e.Contract = "no-version" })
	mut("contract hash", func(e *HarnessExecution) { e.ContractHash = "x" })
	mut("contract state", func(e *HarnessExecution) { e.ContractState = "revoked" })
	mut("constitution", func(e *HarnessExecution) { e.Constitution = "x" })
	mut("module", func(e *HarnessExecution) { e.HarnessModule = "" })
}

// Proposal evidence binding: a plain proposal carries no harness
// evidence; the reconstituted attachment reads back as a defensive copy;
// NewHarnessProposal refuses malformed evidence and a malformed proposal.
func TestHarnessProposalBinding(t *testing.T) {
	plain, err := NewGovernanceProposal("p-0", human, StanceMitigated, "", t0, value.TrustAsserted)
	if err != nil {
		t.Fatal(err)
	}
	if plain.HarnessEvidence() != nil {
		t.Fatal("a plain proposal has no harness evidence")
	}
	ev := goodEvidence()
	ev.Delegations = HarnessDelegations{Count: 1, Seqs: []int64{7}}
	ReconstituteProposalHarness(&plain, &ev)
	got := plain.HarnessEvidence()
	if got == nil || got.CommissionID != cid1 || len(got.Delegations.Seqs) != 1 {
		t.Fatalf("%+v", got)
	}
	got.Delegations.Seqs[0] = 9
	got.BusinessRefs[0] = "tampered"
	if ev.Delegations.Seqs[0] != 7 || ev.BusinessRefs[0] != "CVE-2024-1000" {
		t.Fatal("HarnessEvidence must return a copy")
	}
	bad := goodEvidence()
	bad.Witness = "l6-record-only"
	if _, err := NewHarnessProposal("p-1", human, StanceMitigated, "", t0, bad); !errors.Is(err, ErrHarnessEvidenceInvalid) {
		t.Fatalf("malformed evidence: %v", err)
	}
	if _, err := NewHarnessProposal("", human, StanceMitigated, "", t0, goodEvidence()); !errors.Is(err, errEmptyProposalID) {
		t.Fatalf("empty id: %v", err)
	}
}
