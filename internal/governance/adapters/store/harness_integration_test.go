//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// EDR-HARNESS-01: a commission and a harness-evidence proposal round-trip
// through migration 000014 — the commission with its withdrawal
// witness, the proposal with its immutable evidence and commission id.
func TestHarnessCommissionAndEvidenceRoundTrip(t *testing.T) {
	pool := newPool(t)
	s := store.New(pool)
	ctx := context.Background()
	f, err := domain.NewFinding("fnd-h1", "rel-1", "fl-1", "CVE-2024-1000")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:golang/demo/dep@v1", Name: "dep", Version: "v1", Ecosystem: "golang"})
	if err := s.Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}
	const h = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	human := domain.Actor{Kind: domain.ActorHuman, ID: "key:k1"}
	t0 := time.Unix(1_700_000_000, 0).UTC()
	prev := f.Version()
	c, err := f.Commission("c-1", domain.MethodIdentity{Skill: "remediate-dependency@4", Composition: h}, domain.DeploymentIdentity{Anchor: "rsys@6", Artifact: h}, human, "remediate", t0)
	if err != nil {
		t.Fatal(err)
	}
	ev := domain.HarnessExecution{
		CommissionID: c.ID(), AnchorHash: h, Anchor: "rsys@6", AnchorState: "active", TaskID: "fx-1", ArtifactSeq: 31,
		ArtifactID: "sha256:" + h, VerifiedPath: "report.json", VerifiedHash: h, Skill: "remediate-dependency@4", Composition: h,
		Contract: "report-valid@2", ContractHash: h, ContractState: "active", Reconstructed: "consistent-pass", Witness: "l5-witnessed",
		Constitution: h, HarnessModule: "harness@v0", Delegations: domain.HarnessDelegations{Count: 1, Seqs: []int64{17}}, BusinessRefs: []string{"CVE-2024-1000"},
	}
	p, err := domain.NewHarnessProposal("p-h1", human, domain.StanceMitigated, "bumped", t0, ev)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatal(err)
	}
	if err := f.WithdrawCommission(c.ID(), domain.Actor{Kind: domain.ActorHuman, ID: "key:k2"}, "premise moved", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, f, false, prev, nil); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetByID(ctx, f.ID())
	if err != nil {
		t.Fatal(err)
	}
	cs := got.Commissions()
	if len(cs) != 1 || cs[0].ID() != "c-1" || cs[0].State() != domain.CommissionStateWithdrawn || cs[0].WithdrawnBy().ID != "key:k2" || cs[0].WithdrawalRationale() != "premise moved" || cs[0].Premise().Stage != domain.StageIdentified {
		t.Fatalf("commissions: %+v", cs)
	}
	ps := got.Proposals()
	if len(ps) != 1 || ps[0].EvidenceTrust() != value.TrustInferred || ps[0].HarnessEvidence() == nil {
		t.Fatalf("proposals: %+v", ps)
	}
	rt := ps[0].HarnessEvidence()
	if rt.CommissionID != "c-1" || rt.VerifiedPath != "report.json" || rt.Witness != "l5-witnessed" || rt.Delegations.Count != 1 || len(rt.Delegations.Seqs) != 1 || rt.Delegations.Seqs[0] != 17 || len(rt.BusinessRefs) != 1 {
		t.Fatalf("evidence round-trip: %+v", rt)
	}
}
