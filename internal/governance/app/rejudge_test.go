package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// The KN-GO-2 scenario, in miniature. Three undecided Findings on one card whose range says
// "fixed in 1.17.12": one carries the stdlib at go1.27.1 (provably out of range once KN-GO-1
// reads the prefix), one carries it at go1.17.5 (in range, must stay open), and one is already
// decided (must never be touched). A fourth Finding sits on a card with no ranges (skipped).
type fixedLister struct {
	ids []string
	err error
}

func (l fixedLister) UndecidedFaultlines(context.Context) ([]string, error) { return l.ids, l.err }

type knowledgeByID map[string]app.FaultlineKnowledge

func (k knowledgeByID) GetFaultline(_ context.Context, id string) (app.FaultlineKnowledge, error) {
	v, ok := k[id]
	if !ok {
		return app.FaultlineKnowledge{}, errors.New("knowledge: unreachable")
	}
	return v, nil
}

func withStdlib(t *testing.T, f domain.Finding, version string) domain.Finding {
	t.Helper()
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:golang/stdlib@1.27.1", Name: "stdlib", Version: version, Ecosystem: "golang",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	return f
}

func TestRangeRejudge_RaisesOnlyWhereProvablyOutOfRange(t *testing.T) {
	repo := newRepo()
	repo.seed(withStdlib(t, identified(t, "fnd-out", "rel-1", "fl-go", "CVE-2022-30632"), "go1.27.1"))
	repo.seed(withStdlib(t, identified(t, "fnd-in", "rel-2", "fl-go", "CVE-2022-30632"), "go1.17.5"))
	repo.seed(withStdlib(t, identified(t, "fnd-noranges", "rel-1", "fl-bare", "CVE-2026-1"), "go1.27.1"))

	svc := writeSvc(repo, domain.AutoAcceptObservedNotAffectedPolicy())
	kn := knowledgeByID{
		"fl-go":   {FaultlineID: "fl-go", AffectedRanges: []string{"<1.17.12", ">=1.18.0-0,<1.18.4"}, RangeTrust: value.TrustObserved},
		"fl-bare": {FaultlineID: "fl-bare"},
	}
	pass := app.NewRangeRejudge(svc, fixedLister{ids: []string{"fl-go", "fl-bare", "fl-unreadable"}}, kn)

	res, err := pass.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Faultlines != 3 || res.Raised != 1 || res.Skipped != 2 {
		t.Fatalf("result = %+v, want 3 faultlines, 1 raised, 2 skipped (no ranges + unreadable)", res)
	}

	out := repo.byID["fnd-out"]
	if len(out.Proposals()) != 1 || out.Proposals()[0].Proposer().Kind != domain.ActorSystem {
		t.Fatalf("out-of-range finding proposals = %+v, want one system proposal", out.Proposals())
	}
	if pos, ok := out.CurrentPosition(); !ok || pos.Stance() != domain.StanceNotAffected {
		t.Fatalf("out-of-range finding on Observed evidence should be policy-auto-accepted, got %+v ok=%v", pos, ok)
	}
	if in := repo.byID["fnd-in"]; len(in.Proposals()) != 0 {
		t.Fatalf("in-range finding must stay untouched, got proposals %+v", in.Proposals())
	}
	if bare := repo.byID["fnd-noranges"]; len(bare.Proposals()) != 0 {
		t.Fatalf("finding on a card with no ranges must stay untouched, got %+v", bare.Proposals())
	}
}

// A second pass raises nothing: the proposal id is deterministic per Finding, so the operator
// who leaves the switch set across two restarts does no harm.
func TestRangeRejudge_IsIdempotent(t *testing.T) {
	repo := newRepo()
	repo.seed(withStdlib(t, identified(t, "fnd-out", "rel-1", "fl-go", "CVE-2022-30632"), "go1.27.1"))
	// A policy that accepts nothing, so the proposal stays open and a repeat would be a duplicate.
	svc := writeSvc(repo)
	kn := knowledgeByID{"fl-go": {FaultlineID: "fl-go", AffectedRanges: []string{"<1.17.12"}, RangeTrust: value.TrustObserved}}
	pass := app.NewRangeRejudge(svc, fixedLister{ids: []string{"fl-go"}}, kn)

	first, err := pass.Run(context.Background())
	if err != nil || first.Raised != 1 {
		t.Fatalf("first pass = %+v, %v; want 1 raised", first, err)
	}
	second, err := pass.Run(context.Background())
	if err != nil || second.Raised != 0 {
		t.Fatalf("second pass = %+v, %v; want 0 raised", second, err)
	}
	if got := repo.byID["fnd-out"]; len(got.Proposals()) != 1 {
		t.Fatalf("proposals after two passes = %d, want exactly 1", len(got.Proposals()))
	}
}

// Weaker-than-Observed evidence raises the proposal but the constitutional bar and the policy
// leave it for a human — the pass never widens what an enrichment could do.
func TestRangeRejudge_AssertedEvidenceWaitsForAHuman(t *testing.T) {
	repo := newRepo()
	repo.seed(withStdlib(t, identified(t, "fnd-out", "rel-1", "fl-go", "CVE-2022-30632"), "go1.27.1"))
	svc := writeSvc(repo, domain.AutoAcceptObservedNotAffectedPolicy())
	kn := knowledgeByID{"fl-go": {FaultlineID: "fl-go", AffectedRanges: []string{"<1.17.12"}, RangeTrust: value.TrustAsserted}}

	if _, err := app.NewRangeRejudge(svc, fixedLister{ids: []string{"fl-go"}}, kn).Run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := repo.byID["fnd-out"]
	if len(got.Proposals()) != 1 {
		t.Fatalf("proposals = %d, want 1", len(got.Proposals()))
	}
	if _, ok := got.CurrentPosition(); ok {
		t.Fatal("Asserted evidence must not be auto-accepted by the Observed policy")
	}
}

func TestRangeRejudge_ListerFailureIsFatal(t *testing.T) {
	svc := writeSvc(newRepo())
	_, err := app.NewRangeRejudge(svc, fixedLister{err: errors.New("db down")}, knowledgeByID{}).Run(context.Background())
	if err == nil {
		t.Fatal("expected the lister error to surface")
	}
}

// A write failure is fatal — it means the service is unhealthy — and a cancelled context stops
// the pass between Faultlines; both surface as errors with the partial counts intact.
func TestRangeRejudge_WriteFailureAndCancellationAreFatal(t *testing.T) {
	repo := newRepo()
	repo.seed(withStdlib(t, identified(t, "fnd-out", "rel-1", "fl-go", "CVE-2022-30632"), "go1.27.1"))
	repo.saveErr = errors.New("db down")
	kn := knowledgeByID{"fl-go": {FaultlineID: "fl-go", AffectedRanges: []string{"<1.17.12"}, RangeTrust: value.TrustObserved}}
	if _, err := app.NewRangeRejudge(writeSvc(repo), fixedLister{ids: []string{"fl-go"}}, kn).Run(context.Background()); err == nil {
		t.Fatal("a write failure must abort the pass")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := app.NewRangeRejudge(writeSvc(newRepo()), fixedLister{ids: []string{"fl-go"}}, kn).Run(ctx)
	if err == nil || res.Raised != 0 {
		t.Fatalf("cancelled context: err=%v res=%+v, want an error and nothing raised", err, res)
	}
}

func TestRejudgeVersionRange_NoRangesIsANoop(t *testing.T) {
	n, err := writeSvc(newRepo()).RejudgeVersionRange(context.Background(), "fl-go", nil, value.TrustObserved)
	if err != nil || n != 0 {
		t.Fatalf("no ranges: n=%d err=%v, want 0, nil", n, err)
	}
}
