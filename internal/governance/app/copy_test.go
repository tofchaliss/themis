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

// Decision copy (EDR-SYNC-01 revision 2). The estate is scopeOwners(): product P1 with projects
// A (rel-a1, rel-a2) and B (rel-b1); product OTHER with project C (rel-c1).

func copyTo(ids ...domain.FindingID) domain.AcceptanceTerms {
	return domain.AcceptanceTerms{CopyTo: ids}
}

// copyEstate seeds the source (undecided unless terms are given) and its siblings.
func copyEstate(t *testing.T, terms *domain.AcceptanceTerms) *fakeRepo {
	t.Helper()
	repo := newRepo()
	src := withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier")
	if terms != nil {
		src = decidedScoped(t, src, "p", domain.StanceNotAffected, "built without the codec", t0, *terms)
	}
	repo.seed(src)
	repo.seed(withPURL(t, identified(t, "a2", "rel-a2", "fl-1", "CVE-2026-1"), tiff39, "carrier"))
	repo.seed(decidedBy(t, withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "q", human, human, domain.StanceAffected, "we ship it", t0))
	repo.seed(withPURL(t, identified(t, "b1-other-pkg", "rel-b1", "fl-1", "CVE-2026-1"), httpd, "carrier"))
	repo.seed(withPURL(t, identified(t, "c1", "rel-c1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	repo.seed(withPURL(t, identified(t, "other-cve", "rel-b1", "fl-2", "CVE-2026-2"), tiff38, "carrier"))
	return repo
}

func copyPass(repo *fakeRepo, q *scopeQueue, owners *ownersByRelease) *app.ScopePropagation {
	return app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners)
}

// The pick list: every other Finding of the CVE in the product, decided or not, with its level
// and the decision it carries; never another product, never another CVE, never the source.
func TestCopyCandidates(t *testing.T) {
	ctx := context.Background()
	repo := copyEstate(t, nil)
	got, err := copyPass(repo, newScopeQueue(repo), scopeOwners()).CopyCandidates(ctx, "src")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("candidates = %+v", got)
	}
	a2, b1, other := got[0], got[1], got[2]
	if a2.FindingID != "a2" || a2.Level != domain.LevelComponent || a2.Decided || !a2.Copyable() || a2.ProjectID != "A" || a2.ReleaseID != "rel-a2" {
		t.Errorf("a2 = %+v", a2)
	}
	if b1.FindingID != "b1" || b1.Level != domain.LevelArtifact || !b1.Decided || b1.Stance != domain.StanceAffected ||
		b1.DecidedBy != human || !b1.DecidedAt.Equal(t0) || !b1.Copyable() || b1.ProductID != "P1" {
		t.Errorf("b1 = %+v", b1)
	}
	if other.FindingID != "b1-other-pkg" || other.Level != domain.LevelVulnerability || other.Copyable() {
		t.Errorf("other package = %+v", other)
	}
}

// Every failure of the pick list is an error, never a shorter list.
func TestCopyCandidates_Failures(t *testing.T) {
	ctx := context.Background()
	run := func(repo *fakeRepo, owners *ownersByRelease) error {
		_, err := copyPass(repo, newScopeQueue(repo), owners).CopyCandidates(ctx, "src")
		return err
	}
	repo := copyEstate(t, nil)
	if _, err := copyPass(repo, newScopeQueue(repo), scopeOwners()).CopyCandidates(ctx, "ghost"); err == nil {
		t.Error("unknown source accepted")
	}
	owners := scopeOwners()
	owners.fail = map[string]bool{"rel-a1": true}
	if run(copyEstate(t, nil), owners) == nil {
		t.Error("Registry outage on the source swallowed")
	}
	owners = scopeOwners()
	owners.fail = map[string]bool{"rel-b1": true}
	if run(copyEstate(t, nil), owners) == nil {
		t.Error("Registry outage on a sibling swallowed")
	}
	repo = copyEstate(t, nil)
	repo.byFaultlineErr = errors.New("db down")
	if run(repo, scopeOwners()) == nil {
		t.Error("unlistable Faultline swallowed")
	}
	repo = copyEstate(t, nil)
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n == 1 {
			repo.getByIDErr = errors.New("db down")
		}
		return f
	}
	if run(repo, scopeOwners()) == nil {
		t.Error("unreadable sibling swallowed")
	}
}

// A pick is judged whole: a copyable sibling passes; another product's Finding, a Finding of
// another component, the source itself and an unknown id each refuse the request. No pick
// asks Registry nothing.
func TestCheckCopyTargets(t *testing.T) {
	ctx := context.Background()
	repo := copyEstate(t, nil)
	owners := scopeOwners()
	sp := copyPass(repo, newScopeQueue(repo), owners)
	if err := sp.CheckCopyTargets(ctx, "src", nil); err != nil || owners.calls != 0 {
		t.Fatalf("empty pick = %v, registry calls %d", err, owners.calls)
	}
	if err := sp.CheckCopyTargets(ctx, "src", []domain.FindingID{"a2", "b1"}); err != nil {
		t.Fatalf("valid pick refused: %v", err)
	}
	for _, bad := range []domain.FindingID{"c1", "b1-other-pkg", "src", "other-cve", "ghost"} {
		err := sp.CheckCopyTargets(ctx, "src", []domain.FindingID{"a2", bad})
		if !errors.Is(err, app.ErrCopyTargetInvalid) || !strings.Contains(err.Error(), string(bad)) {
			t.Errorf("pick %s = %v, want ErrCopyTargetInvalid naming it", bad, err)
		}
	}
	owners.fail = map[string]bool{"rel-a1": true}
	if err := sp.CheckCopyTargets(ctx, "src", []domain.FindingID{"a2"}); err == nil || errors.Is(err, app.ErrCopyTargetInvalid) {
		t.Errorf("Registry outage = %v, want its own error", err)
	}
}

// The sweep makes the copies once: the undecided target gets the Position, the decided target
// gets a NEW version (its own decision stays in the history), both in the person's name and
// naming the source; a copy is not a source; a second pass and a re-apply do nothing.
func TestSweep_CopiesADecision(t *testing.T) {
	ctx := context.Background()
	terms := copyTo("a2", "b1")
	repo := copyEstate(t, &terms)
	q := newScopeQueue(repo)
	sp := copyPass(repo, q, scopeOwners())

	res, err := sp.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res.Copies != 1 || res.Copied != 2 || res.Decisions != 0 || res.Applied != 0 {
		t.Fatalf("result = %+v, want 1 decision copied to 2", res)
	}
	a2, ok := repo.byID["a2"].CurrentPosition()
	if !ok || a2.Version() != 1 || a2.Stance() != domain.StanceNotAffected || a2.Actor() != human ||
		a2.Inputs().PropagatedFrom != (domain.PropagationSource{FindingID: "src", Version: 1}) ||
		a2.Inputs().AcceptedProposalID != domain.CopiedProposalID("a2", "src", 1) || a2.Scope() != domain.ScopeRelease {
		t.Fatalf("a2 = %+v %v", a2, ok)
	}
	if want := "built without the codec — copied from alpha 1.0 (Finding src), Position v1, component level"; a2.Rationale() != want {
		t.Errorf("a2 rationale = %q", a2.Rationale())
	}
	if a2.IsCopySource() || a2.IsScopedSource() {
		t.Error("a copy is a source")
	}
	b1 := repo.byID["b1"]
	cur, _ := b1.CurrentPosition()
	if len(b1.Positions()) != 2 || cur.Version() != 2 || cur.Stance() != domain.StanceNotAffected ||
		b1.Positions()[0].Stance() != domain.StanceAffected || b1.Positions()[0].Rationale() != "we ship it" {
		t.Fatalf("b1 positions = %+v", b1.Positions())
	}
	if !strings.HasSuffix(cur.Rationale(), "artifact level") {
		t.Errorf("b1 rationale = %q", cur.Rationale())
	}
	for _, id := range []domain.FindingID{"b1-other-pkg", "c1", "other-cve"} {
		if _, decided := repo.byID[id].CurrentPosition(); decided {
			t.Errorf("%s was decided", id)
		}
	}
	if len(repo.byID["src"].Positions()) != 1 {
		t.Error("the source was touched")
	}
	again, err := sp.Sweep(ctx)
	if err != nil || again.Copies != 0 || again.Copied != 0 {
		t.Fatalf("second sweep = %+v %v", again, err)
	}
	if n, err := sp.ApplyCopy(ctx, app.ScopedPosition{FindingID: "src", Version: 1}); err != nil || n != 0 {
		t.Fatalf("re-apply = %d %v, want nothing (already copied)", n, err)
	}
	if len(repo.byID["b1"].Positions()) != 2 {
		t.Error("a retry copied twice")
	}
}

// Nothing is copied from a decision that is no longer current, from one without targets, or to
// a target that stopped carrying the component since the pick.
func TestApplyCopy_Skips(t *testing.T) {
	ctx := context.Background()
	terms := copyTo("a2")
	repo := copyEstate(t, &terms)
	src := decidedBy(t, repo.byID["src"], "p2", human, human, domain.StanceAffected, "changed my mind", t0)
	repo.seed(src)
	sp := copyPass(repo, newScopeQueue(repo), scopeOwners())
	if n, err := sp.ApplyCopy(ctx, app.ScopedPosition{FindingID: "src", Version: 1}); err != nil || n != 0 {
		t.Fatalf("stale version copied: %d %v", n, err)
	}
	if n, err := sp.ApplyCopy(ctx, app.ScopedPosition{FindingID: "src", Version: 2}); err != nil || n != 0 {
		t.Fatalf("a decision without targets copied: %d %v", n, err)
	}
	if n, err := sp.ApplyCopy(ctx, app.ScopedPosition{FindingID: "b1-other-pkg", Version: 1}); err != nil || n != 0 {
		t.Fatalf("an undecided Finding copied: %d %v", n, err)
	}
	if _, err := sp.ApplyCopy(ctx, app.ScopedPosition{FindingID: "ghost", Version: 1}); err == nil {
		t.Fatal("unknown source accepted")
	}
	if _, decided := repo.byID["a2"].CurrentPosition(); decided {
		t.Error("a2 was decided")
	}
	// the picked target carries another package by the time the copy runs
	terms = copyTo("b1-other-pkg")
	repo = copyEstate(t, &terms)
	if n, err := copyPass(repo, newScopeQueue(repo), scopeOwners()).ApplyCopy(ctx, app.ScopedPosition{FindingID: "src", Version: 1}); err != nil || n != 0 {
		t.Fatalf("copied to another component: %d %v", n, err)
	}
	if _, decided := repo.byID["b1-other-pkg"].CurrentPosition(); decided {
		t.Error("a different component was decided")
	}
}

// Failures leave the decision pending: the list, the Registry, the write, the mark, a cancelled
// context; and the copies of one decision stop at the first failure.
func TestSweep_CopyFailuresLeaveTheRowPending(t *testing.T) {
	ctx := context.Background()
	seed := func() (*fakeRepo, *scopeQueue, *ownersByRelease) {
		terms := copyTo("a2", "b1")
		repo := copyEstate(t, &terms)
		return repo, newScopeQueue(repo), scopeOwners()
	}
	repo, q, owners := seed()
	q.copyListErr = errors.New("db down")
	if _, err := copyPass(repo, q, owners).Sweep(ctx); err == nil {
		t.Fatal("list failure swallowed")
	}
	repo, q, owners = seed()
	owners.fail = map[string]bool{"rel-a1": true}
	sp := copyPass(repo, q, owners)
	if _, err := sp.Sweep(ctx); err == nil || len(q.copied) != 0 {
		t.Fatalf("Registry outage: err=%v marked=%v", err, q.copied)
	}
	owners.fail = nil
	repo.saveErr = errors.New("db down")
	if res, err := sp.Sweep(ctx); err == nil || res.Copied != 0 || len(q.copied) != 0 {
		t.Fatalf("write failure: %+v err=%v marked=%v", res, err, q.copied)
	}
	repo.saveErr = nil
	q.copyMarkErr = errors.New("db down")
	if res, err := sp.Sweep(ctx); err == nil || res.Copied != 2 || res.Copies != 0 {
		t.Fatalf("mark failure: %+v %v", res, err)
	}
	q.copyMarkErr = nil
	if res, err := sp.Sweep(ctx); err != nil || res.Copies != 1 || res.Copied != 0 || len(q.copied) != 1 {
		t.Fatalf("recovery: %+v %v marked=%v (the copies were made before the mark failed)", res, err, q.copied)
	}
	// cancelled before the first decision, and before the first target
	repo, q, owners = seed()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	sp = copyPass(repo, q, owners)
	if _, err := sp.Sweep(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sweep = %v", err)
	}
	if n, err := sp.ApplyCopy(cancelled, app.ScopedPosition{FindingID: "src", Version: 1}); !errors.Is(err, context.Canceled) || n != 0 {
		t.Fatalf("cancelled copy = %d %v", n, err)
	}
}

// The narrow branches of one copy: a target the domain refuses, the pair already on the
// target, terms the domain refuses, and a source with no valid actor.
func TestApplyCopiedPosition_Refusals(t *testing.T) {
	ctx := context.Background()
	seed := func() *fakeRepo {
		terms := copyTo("a2")
		return copyEstate(t, &terms)
	}
	run := func(repo *fakeRepo) (int, error) {
		return copyPass(repo, newScopeQueue(repo), scopeOwners()).ApplyCopy(ctx, app.ScopedPosition{FindingID: "src", Version: 1})
	}
	// an archived target cannot take a proposal
	repo := seed()
	tgt := repo.byID["a2"]
	_ = tgt.Resolve()
	_ = tgt.Archive()
	repo.seed(tgt)
	if _, err := run(repo); err == nil {
		t.Error("refused proposal swallowed")
	}
	// the pair already on the target: nothing twice
	repo = seed()
	tgt = repo.byID["a2"]
	p, _ := domain.NewGovernanceProposal(domain.CopiedProposalID("a2", "src", 1), human, domain.StanceNotAffected, "", t0, value.TrustAsserted)
	_ = tgt.RaiseProposal(p)
	_ = tgt.RejectProposal(p.ID(), human, t0)
	repo.seed(tgt)
	if n, err := run(repo); err != nil || n != 0 {
		t.Errorf("duplicate pair = %d %v", n, err)
	}
	// an accepted risk with no owner (only a reconstituted row can carry it): the accept fails
	repo = seed()
	repo.seed(domain.ReconstituteFinding("src", "rel-a1", "fl-1", "CVE-2026-1", repo.byID["src"].Components(), domain.StagePositionEstablished, nil,
		[]domain.Position{domain.ReconstitutePosition(1, domain.StanceAcceptedRisk, "", human, domain.PositionInputs{CopyTo: []domain.FindingID{"a2"}}, t0)}, 3))
	if _, err := run(repo); !errors.Is(err, domain.ErrOwnerRequired) {
		t.Errorf("ownerless acceptance = %v, want ErrOwnerRequired", err)
	}
	// a source whose Position names no valid actor makes a proposal the domain refuses
	repo = seed()
	repo.seed(domain.ReconstituteFinding("src", "rel-a1", "fl-1", "CVE-2026-1", repo.byID["src"].Components(), domain.StagePositionEstablished, nil,
		[]domain.Position{domain.ReconstitutePosition(1, domain.StanceNotAffected, "", domain.Actor{}, domain.PositionInputs{CopyTo: []domain.FindingID{"a2"}}, t0)}, 3))
	if _, err := run(repo); err == nil {
		t.Error("invalid proposer swallowed")
	}
}
