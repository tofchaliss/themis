package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

const (
	hxA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hxB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hxC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func harnessWorld(t *testing.T) (*app.FindingService, *fakeRepo, domain.FindingID) {
	t.Helper()
	repo := newRepo()
	f, _ := domain.NewFinding("f-1", "r-1", "fl-1", "CVE-2024-1000")
	_, _ = f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:golang/demo/vulnerable-dep@v1", Name: "vulnerable-dep", Version: "v1", Ecosystem: "golang"})
	repo.seed(f)
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	return svc, repo, f.ID()
}

func evidenceFor(cid domain.CommissionID) domain.HarnessExecution {
	return domain.HarnessExecution{
		CommissionID: cid, AnchorHash: hxB, Anchor: "rsys@6", AnchorState: "active", TaskID: "fx-1", ArtifactSeq: 31,
		ArtifactID: "sha256:" + hxC, VerifiedPath: "report.json", VerifiedHash: hxC, Skill: "remediate-dependency@4", Composition: hxA,
		Contract: "report-valid@2", ContractHash: hxA, ContractState: "active", Reconstructed: "consistent-pass", Witness: "l5-witnessed",
		Constitution: hxA, HarnessModule: "harness@v0", BusinessRefs: []string{"CVE-2024-1000", "pkg:golang/demo/vulnerable-dep@v1"},
	}
}

// The whole Row 4 contract through the service: commission → (execution)
// → proposal with correspondence and Business Verification → the
// commissioner may be the proposer; the trust class is derived, never
// chosen; a withdrawn commission refuses a later proposal but the
// earlier one stands.
func TestHarnessCommissionAndProposal(t *testing.T) {
	svc, repo, fid := harnessWorld(t)
	ctx := context.Background()
	human := domain.Actor{Kind: domain.ActorHuman, ID: "key:operator"}
	cid, err := svc.Commission(ctx, fid, domain.MethodIdentity{Skill: "remediate-dependency@4", Composition: hxA}, domain.DeploymentIdentity{Anchor: "rsys@6", Artifact: hxB}, human, "remediate the dep")
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.lastNotes) != 1 || repo.lastNotes[0].EventType != app.EventFindingCommissioned {
		t.Fatalf("commission event: %+v", repo.lastNotes)
	}
	f, _ := repo.GetByID(ctx, fid)
	if f.Stage() != domain.StageIdentified {
		t.Fatal("commissioning must not move the stage (D-C-4)")
	}
	// AI cannot commission.
	if _, err := svc.Commission(ctx, fid, domain.MethodIdentity{Skill: "x@1", Composition: hxA}, domain.DeploymentIdentity{Anchor: "rsys@6", Artifact: hxB}, domain.Actor{Kind: domain.ActorAI, ID: "cap"}, ""); !errors.Is(err, domain.ErrCommissionActor) {
		t.Fatalf("ai commission: %v", err)
	}
	// Proposal on the execution: commissioner = proposer is allowed.
	pid, err := svc.RaiseHarnessProposal(ctx, fid, human, domain.StanceMitigated, "bumped to v2", evidenceFor(cid), value.TrustInferred)
	if err != nil {
		t.Fatal(err)
	}
	f, _ = repo.GetByID(ctx, fid)
	if len(f.Proposals()) != 1 || f.Proposals()[0].ID() != pid || f.Proposals()[0].EvidenceTrust() != value.TrustInferred || f.Proposals()[0].HarnessEvidence() == nil {
		t.Fatalf("%+v", f.Proposals())
	}
	if f.Stage() != domain.StageUnderInvestigation {
		t.Fatal("the PROPOSAL moves the stage, as today")
	}
	// Refusals, each named.
	refuse := func(name string, ev domain.HarnessExecution, trust value.TrustClass, want error) {
		t.Helper()
		if _, err := svc.RaiseHarnessProposal(ctx, fid, human, domain.StanceMitigated, "x", ev, trust); !errors.Is(err, want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	refuse("asserted trust for harness evidence", evidenceFor(cid), value.TrustAsserted, domain.ErrHarnessEvidenceTrust)
	refuse("unknown commission", evidenceFor("d1e2f3a4-0000-4000-8000-000000000009"), value.TrustInferred, domain.ErrCommissionNotFound)
	ev := evidenceFor(cid)
	ev.Skill = "remediate-dependency@3"
	refuse("method mismatch", ev, value.TrustInferred, domain.ErrCommissionMismatch)
	ev = evidenceFor(cid)
	ev.Anchor, ev.AnchorHash = "rsys@7", hxC
	refuse("deployment mismatch", ev, value.TrustInferred, domain.ErrCommissionMismatch)
	ev = evidenceFor(cid)
	ev.BusinessRefs = []string{"CVE-2024-9999"}
	refuse("ref not vouched by the finding", ev, value.TrustInferred, app.ErrBusinessVerification)
	ev = evidenceFor(cid)
	ev.Witness = "l6-record-only"
	refuse("historical record", ev, value.TrustInferred, domain.ErrHarnessEvidenceInvalid)
	// Withdraw: the earlier proposal stands; a new one refuses.
	if err := svc.WithdrawCommission(ctx, fid, cid, domain.Actor{Kind: domain.ActorHuman, ID: "key:lead"}, "premise moved"); err != nil {
		t.Fatal(err)
	}
	refuse("withdrawn commission", evidenceFor(cid), value.TrustInferred, domain.ErrCommissionWithdrawn)
	f, _ = repo.GetByID(ctx, fid)
	if len(f.Proposals()) != 1 || !strings.EqualFold(string(f.Proposals()[0].Status()), "proposed") {
		t.Fatalf("history rewritten: %+v", f.Proposals())
	}
	if err := svc.WithdrawCommission(ctx, fid, cid, human, "again"); !errors.Is(err, domain.ErrCommissionWithdrawn) {
		t.Fatalf("second withdrawal: %v", err)
	}
}

// The two refusals that surface only inside the aggregate mutation: a
// non-human proposer (the harness is never the proposer, D-I-5) and a
// Finding that can no longer take a proposal.
func TestHarnessProposalAggregateRefusals(t *testing.T) {
	svc, repo, fid := harnessWorld(t)
	ctx := context.Background()
	human := domain.Actor{Kind: domain.ActorHuman, ID: "key:operator"}
	cid, err := svc.Commission(ctx, fid, domain.MethodIdentity{Skill: "remediate-dependency@4", Composition: hxA}, domain.DeploymentIdentity{Anchor: "rsys@6", Artifact: hxB}, human, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RaiseHarnessProposal(ctx, fid, domain.Actor{Kind: domain.ActorAI, ID: "cap"}, domain.StanceMitigated, "x", evidenceFor(cid), value.TrustInferred); err == nil {
		t.Fatal("an AI proposer must be refused")
	}
	f, _ := repo.GetByID(ctx, fid)
	if err := f.Resolve(); err != nil {
		t.Fatal(err)
	}
	if err := f.Archive(); err != nil {
		t.Fatal(err)
	}
	repo.seed(f)
	if _, err := svc.RaiseHarnessProposal(ctx, fid, human, domain.StanceMitigated, "x", evidenceFor(cid), value.TrustInferred); !errors.Is(err, domain.ErrIllegalTransition) {
		t.Fatalf("archived finding: %v", err)
	}
}
