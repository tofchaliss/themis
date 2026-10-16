package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// --- fakes -----------------------------------------------------------------------------

// projectByRelease is the Registry identity seam as roll-forward needs it: release → project,
// with a per-release outage and a per-release blank answer.
type projectByRelease struct {
	projects map[string]string
	fail     map[string]bool
	calls    int
}

func (p *projectByRelease) ProductAndProjectOfRelease(_ context.Context, releaseID string) (string, string, error) {
	p.calls++
	if p.fail[releaseID] {
		return "", "", errors.New("registry: connection refused")
	}
	return "prod", p.projects[releaseID], nil
}

// undecidedByRelease answers UndecidedFindingsByRelease from the fake repo.
type undecidedByRelease struct {
	repo *fakeRepo
	err  error
}

func (u undecidedByRelease) UndecidedFindingsByRelease(_ context.Context, rel string) ([]domain.FindingID, error) {
	if u.err != nil {
		return nil, u.err
	}
	var out []domain.FindingID
	for _, id := range u.repo.order {
		f := u.repo.byID[id]
		if _, decided := f.CurrentPosition(); f.ReleaseID() == rel && !decided {
			out = append(out, id)
		}
	}
	return out, nil
}

// undecidedFaultlines lists every Faultline with an undecided Finding in the fake repo.
type undecidedFaultlines struct {
	repo *fakeRepo
	err  error
}

func (u undecidedFaultlines) UndecidedFaultlines(context.Context) ([]string, error) {
	if u.err != nil {
		return nil, u.err
	}
	seen := map[string]bool{}
	var out []string
	for _, id := range u.repo.order {
		f := u.repo.byID[id]
		if _, decided := f.CurrentPosition(); !decided && !seen[f.FaultlineID()] {
			seen[f.FaultlineID()] = true
			out = append(out, f.FaultlineID())
		}
	}
	return out, nil
}

func withPURL(t *testing.T, f domain.Finding, purl, class string) domain.Finding {
	t.Helper()
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: purl, Name: "x", Version: "1", ClaimClass: class}); err != nil {
		t.Fatal(err)
	}
	return f
}

// decidedBy raises `pid` from `proposer` and has `decider` accept it at `at`.
func decidedBy(t *testing.T, f domain.Finding, pid domain.ProposalID, proposer, decider domain.Actor, stance domain.Stance, rationale string, at time.Time) domain.Finding {
	t.Helper()
	p, err := domain.NewGovernanceProposal(pid, proposer, stance, rationale, at, value.TrustAsserted)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposal(pid, decider, at); err != nil {
		t.Fatal(err)
	}
	return f
}

const (
	tiff38 = "pkg:rpm/rocky/libtiff@4.0.9-38.el8_10"
	tiff39 = "pkg:rpm/rocky/libtiff@4.0.9-39.el8_10"
	httpd  = "pkg:rpm/rocky/httpd@2.4.37-65"
)

var t0 = fixedClock{}.Now()

// --- the pass ----------------------------------------------------------------------------

// The VAMS behaviour, deterministic: the previous release of the project decided this CVE on
// the same package; the new release gets that decision as a PROPOSAL on Inferred evidence —
// a person accepts it, the Observed-only policy cannot.
func TestRollForward_ProposesSiblingJudgementInSameProject(t *testing.T) {
	repo := newRepo()
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-old", "rel-old", "fl-1", "CVE-2026-1"), tiff38, "carrier"),
		"p-h", human, human, domain.StanceNotAffected, "built without the codec", t0.Add(-time.Hour)))
	repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff39, "carrier"))

	svc := writeSvc(repo, domain.AutoAcceptObservedNotAffectedPolicy())
	ids := &projectByRelease{projects: map[string]string{"rel-old": "prj-A", "rel-new": "prj-A"}}
	rf := app.NewRollForward(svc, undecidedByRelease{repo: repo}, ids)

	res, err := rf.ForRelease(context.Background(), "rel-new", "prj-A")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Considered != 1 || res.Raised != 1 || res.NoPrecedent != 0 {
		t.Fatalf("result = %+v, want one proposal raised", res)
	}
	f := repo.byID["fnd-new"]
	ps := f.Proposals()
	if len(ps) != 1 || ps[0].ID() != "rollforward:fnd-new:fnd-old" || ps[0].Stance() != domain.StanceNotAffected {
		t.Fatalf("proposals = %+v, want one roll-forward not_affected", ps)
	}
	if ps[0].Proposer().Kind != domain.ActorSystem || ps[0].EvidenceTrust() != value.TrustInferred || !ps[0].IsOpen() {
		t.Fatalf("proposal = system %v trust %v open %v; want system, Inferred, open for a human", ps[0].Proposer(), ps[0].EvidenceTrust(), ps[0].IsOpen())
	}
	if _, decided := f.CurrentPosition(); decided {
		t.Fatal("a roll-forward proposal must never become a Position on its own")
	}
	for _, want := range []string{"component level", "release rel-old", "Position v1", "decided by human", "not_affected", "built without the codec"} {
		if !strings.Contains(ps[0].Rationale(), want) {
			t.Errorf("rationale %q lacks %q", ps[0].Rationale(), want)
		}
	}
	// Idempotent: the same pair raises nothing new.
	again, err := rf.ForRelease(context.Background(), "rel-new", "prj-A")
	if err != nil || again.Raised != 0 || again.NoPrecedent != 1 || len(repo.byID["fnd-new"].Proposals()) != 1 {
		t.Fatalf("second run = %+v err=%v proposals=%d; want nothing new", again, err, len(repo.byID["fnd-new"].Proposals()))
	}
}

// What is NOT carried: another project's decision, a rule's verdict, a different package, a
// scope-only target (the CVE-2026-33006 fixture), a sibling in the same release.
func TestRollForward_DoesNotProposeAcrossProjectsRulesOrPackages(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "version-range"}
	repo := newRepo()
	// other project, same package, human judgement
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-other", "rel-other", "fl-1", "CVE-2026-1"), tiff38, ""), "p1", human, human, domain.StanceNotAffected, "", t0))
	// same project, but a human confirming a system proposal (a rule's verdict)
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-rule", "rel-rule", "fl-1", "CVE-2026-1"), tiff38, ""), "range:x", system, human, domain.StanceNotAffected, "", t0))
	// same project, judgement, different package
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-curl", "rel-curl", "fl-1", "CVE-2026-1"), "pkg:rpm/rocky/curl@1", ""), "p2", human, human, domain.StanceAffected, "", t0))
	// targets
	repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff39, ""))
	repo.seed(withPURL(t, identified(t, "fnd-scope", "rel-new", "fl-2", "CVE-2026-33006"), httpd, domain.ClaimScope))
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-fixture-src", "rel-fx", "fl-2", "CVE-2026-33006"), httpd, ""), "p3", human, human, domain.StanceNotAffected, "", t0))

	svc := writeSvc(repo)
	ids := &projectByRelease{projects: map[string]string{"rel-other": "prj-B", "rel-rule": "prj-A", "rel-curl": "prj-A", "rel-new": "prj-A", "rel-fx": "prj-A"}}
	res, err := app.NewRollForward(svc, undecidedByRelease{repo: repo}, ids).ForRelease(context.Background(), "rel-new", "prj-A")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Considered != 2 || res.Raised != 0 || res.NoPrecedent != 2 {
		t.Fatalf("result = %+v, want two considered and nothing raised", res)
	}
	for _, id := range []domain.FindingID{"fnd-new", "fnd-scope"} {
		if n := len(repo.byID[id].Proposals()); n != 0 {
			t.Errorf("%s got %d proposals, want none", id, n)
		}
	}
	// The project hop ran only for siblings that qualified on every other count: fnd-rule and
	// fnd-curl never cost a Registry call (fnd-rule is a rule's verdict, fnd-curl another package).
	if ids.calls != 1 {
		t.Fatalf("registry calls = %d, want 1 (only the human-judged same-package sibling)", ids.calls)
	}
}

// Among several judged siblings in the project the latest decision wins; artifact level is
// reported when the builds match purl for purl.
func TestRollForward_LatestJudgementWinsAndArtifactLevelNamed(t *testing.T) {
	repo := newRepo()
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-a", "rel-a", "fl-1", "CVE-2026-1"), tiff38, ""), "pa", human, human, domain.StanceNotAffected, "old view", t0.Add(-2*time.Hour)))
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-b", "rel-b", "fl-1", "CVE-2026-1"), tiff38, ""), "pb", ai, human, domain.StanceAffected, "new view", t0.Add(-time.Hour)))
	repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff38, ""))
	ids := &projectByRelease{projects: map[string]string{"rel-a": "prj-A", "rel-b": "prj-A", "rel-new": "prj-A"}}
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(context.Background(), "rel-new", "prj-A"); err != nil {
		t.Fatal(err)
	}
	ps := repo.byID["fnd-new"].Proposals()
	if len(ps) != 1 || ps[0].ID() != "rollforward:fnd-new:fnd-b" || ps[0].Stance() != domain.StanceAffected || !strings.Contains(ps[0].Rationale(), "artifact level") {
		t.Fatalf("proposals = %+v, want the later fnd-b decision at artifact level", ps)
	}
}

func TestRollForward_FailuresDeferRatherThanGuess(t *testing.T) {
	ctx := context.Background()
	seedPair := func() (*fakeRepo, *projectByRelease) {
		repo := newRepo()
		repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-old", "rel-old", "fl-1", "CVE-2026-1"), tiff38, ""), "p", human, human, domain.StanceNotAffected, "", t0))
		repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff38, ""))
		return repo, &projectByRelease{projects: map[string]string{"rel-old": "prj-A", "rel-new": "prj-A"}}
	}
	// blank project
	repo, ids := seedPair()
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(ctx, "rel-new", " "); !errors.Is(err, app.ErrUnresolvedReleaseIdentity) {
		t.Fatalf("blank project: err = %v", err)
	}
	// lister failure
	repo, ids = seedPair()
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo, err: errors.New("db")}, ids).ForRelease(ctx, "rel-new", "prj-A"); err == nil {
		t.Fatal("lister failure must surface")
	}
	// Registry down while placing the sibling
	repo, ids = seedPair()
	ids.fail = map[string]bool{"rel-old": true}
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(ctx, "rel-new", "prj-A"); err == nil {
		t.Fatal("a Registry failure must surface so the worker defers")
	}
	// Registry answers blank for the sibling
	repo, ids = seedPair()
	ids.projects["rel-old"] = ""
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(ctx, "rel-new", "prj-A"); !errors.Is(err, app.ErrUnresolvedReleaseIdentity) {
		t.Fatalf("blank sibling project: err = %v", err)
	}
	// repo read failures
	repo, ids = seedPair()
	repo.getByIDErr = errors.New("db")
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(ctx, "rel-new", "prj-A"); err == nil {
		t.Fatal("GetByID failure must surface")
	}
	repo, ids = seedPair()
	repo.byFaultlineErr = errors.New("db")
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(ctx, "rel-new", "prj-A"); err == nil {
		t.Fatal("FindingsByFaultline failure must surface")
	}
	// save failure
	repo, ids = seedPair()
	repo.saveErr = errors.New("db")
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(ctx, "rel-new", "prj-A"); err == nil {
		t.Fatal("save failure must surface")
	}
	// cancelled context
	repo, ids = seedPair()
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).ForRelease(cctx, "rel-new", "prj-A"); err == nil {
		t.Fatal("cancellation must stop the pass")
	}
}

// Direct entry: a Finding decided since it was listed is left alone; a sibling in the SAME
// release is not a precedent.
func TestRollForwardFinding_SkipsDecidedTargetAndSameRelease(t *testing.T) {
	repo := newRepo()
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-done", "rel-x", "fl-1", "CVE-2026-1"), tiff38, ""), "p", human, human, domain.StanceNotAffected, "", t0))
	repo.seed(withPURL(t, identified(t, "fnd-twin", "rel-x", "fl-1", "CVE-2026-1"), tiff38, ""))
	svc := writeSvc(repo)
	noLookup := func(context.Context, string) (string, error) { return "prj-A", nil }
	if raised, err := svc.RollForwardFinding(context.Background(), "fnd-done", "prj-A", noLookup); err != nil || raised {
		t.Fatalf("decided target: raised=%v err=%v", raised, err)
	}
	if raised, err := svc.RollForwardFinding(context.Background(), "fnd-twin", "prj-A", noLookup); err != nil || raised {
		t.Fatalf("same-release sibling must not be precedent: raised=%v err=%v", raised, err)
	}
}

// The one-time sweep: every undecided Finding, its own project resolved first, one Registry call
// per release; failures surface.
func TestRollForward_Sweep(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-old", "rel-old", "fl-1", "CVE-2026-1"), tiff38, ""), "p", human, human, domain.StanceNotAffected, "", t0))
	repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff39, ""))
	repo.seed(withPURL(t, identified(t, "fnd-new2", "rel-new", "fl-9", "CVE-2026-9"), tiff39, ""))
	ids := &projectByRelease{projects: map[string]string{"rel-old": "prj-A", "rel-new": "prj-A"}}
	rf := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids)
	res, err := rf.Sweep(ctx, undecidedFaultlines{repo: repo})
	if err != nil || res.Considered != 2 || res.Raised != 1 || res.NoPrecedent != 1 {
		t.Fatalf("sweep = %+v err=%v, want 2 considered, 1 raised", res, err)
	}
	if ids.calls != 2 {
		t.Fatalf("registry calls = %d, want one per release", ids.calls)
	}
	if _, err := rf.Sweep(ctx, undecidedFaultlines{err: errors.New("db")}); err == nil {
		t.Fatal("lister failure must surface")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := rf.Sweep(cctx, undecidedFaultlines{repo: repo}); err == nil {
		t.Fatal("cancellation must stop the sweep")
	}
	ids.fail = map[string]bool{"rel-new": true}
	if _, err := app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids).Sweep(ctx, undecidedFaultlines{repo: repo}); err == nil {
		t.Fatal("placing the target's own release failing must surface")
	}
	repo.byFaultlineErr = errors.New("db")
	if _, err := rf.Sweep(ctx, undecidedFaultlines{repo: repo}); err == nil {
		t.Fatal("FindingsByFaultline failure must surface")
	}
	repo.byFaultlineErr = nil
	repo.getByIDErr = errors.New("db")
	if _, err := rf.Sweep(ctx, undecidedFaultlines{repo: repo}); err == nil {
		t.Fatal("GetByID failure must surface")
	}
}

// The pass rides the re-judge: with a Registry seam the one-time pass also rolls forward.
func TestRangeRejudge_RunsRollForwardWhenWired(t *testing.T) {
	repo := newRepo()
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-old", "rel-old", "fl-1", "CVE-2026-1"), tiff38, ""), "p", human, human, domain.StanceNotAffected, "", t0))
	repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff38, ""))
	svc := writeSvc(repo)
	ids := &projectByRelease{projects: map[string]string{"rel-old": "prj-A", "rel-new": "prj-A"}}
	pass := app.NewRangeRejudge(svc, undecidedFaultlines{repo: repo}, knowledgeByID{"fl-1": {FaultlineID: "fl-1"}}).
		WithRollForward(app.NewRollForward(svc, undecidedByRelease{repo: repo}, ids))
	res, err := pass.Run(context.Background())
	if err != nil || res.RollForwardRaised != 1 {
		t.Fatalf("result = %+v err=%v, want one roll-forward raised", res, err)
	}
	ids.fail = map[string]bool{"rel-old": true}
	repo.seed(withPURL(t, identified(t, "fnd-new2", "rel-new2", "fl-1", "CVE-2026-1"), tiff38, ""))
	ids.projects["rel-new2"] = "prj-A"
	if _, err := pass.Run(context.Background()); err == nil {
		t.Fatal("a roll-forward failure aborts the pass")
	}
}

// The worker runs roll-forward before publish-and-mark: a failure defers the row (nothing is
// published, the row stays pending) and a later pass completes both.
func TestWorker_RollForwardFailureDefersTheRow(t *testing.T) {
	ctx := context.Background()
	q, worker, identity, _ := evaluationWorker(t, "prod-1", "prj-A")
	record(t, q, "rel-new", "ev-1", domain.CauseNewSBOM)

	repo := newRepo()
	repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-old", "rel-old", "fl-1", "CVE-2026-1"), tiff38, ""), "p", human, human, domain.StanceNotAffected, "", t0))
	repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff38, ""))
	ids := &projectByRelease{projects: map[string]string{"rel-old": "prj-A", "rel-new": "prj-A"}, fail: map[string]bool{"rel-old": true}}
	worker.w.WithRollForward(app.NewRollForward(writeSvc(repo), undecidedByRelease{repo: repo}, ids))
	_ = identity

	worker.Tick(ctx)
	if len(q.publishedEvents()) != 0 || len(q.pending()) != 1 {
		t.Fatalf("after a roll-forward failure: published=%d pending=%d, want 0 and 1", len(q.publishedEvents()), len(q.pending()))
	}
	ids.fail = nil
	worker.clock.advance(2 * app.EvaluationBackoffMax)
	worker.Tick(ctx)
	if len(q.publishedEvents()) != 1 || len(repo.byID["fnd-new"].Proposals()) != 1 {
		t.Fatalf("after recovery: published=%d proposals=%d, want 1 and 1", len(q.publishedEvents()), len(repo.byID["fnd-new"].Proposals()))
	}
}

// The three narrow branches inside the write: a sibling that vanished between listing and
// reading, a target decided between the read and the write (left alone), and a proposal the
// domain refuses (a zero clock makes raisedAt zero).
func TestRollForwardFinding_WriteTimeBranches(t *testing.T) {
	ctx := context.Background()
	lookup := func(context.Context, string) (string, error) { return "prj-A", nil }
	seed := func() *fakeRepo {
		repo := newRepo()
		repo.seed(decidedBy(t, withPURL(t, identified(t, "fnd-old", "rel-old", "fl-1", "CVE-2026-1"), tiff38, ""), "p", human, human, domain.StanceNotAffected, "", t0))
		repo.seed(withPURL(t, identified(t, "fnd-new", "rel-new", "fl-1", "CVE-2026-1"), tiff38, ""))
		return repo
	}
	// sibling listed but unreadable: the store fails on the SECOND read (the sibling's)
	repo := seed()
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n == 1 {
			repo.getByIDErr = errors.New("db down")
		}
		return f
	}
	if _, err := writeSvc(repo).RollForwardFinding(ctx, "fnd-new", "prj-A", lookup); err == nil {
		t.Fatal("an unreadable sibling must surface")
	}
	// decided between the read and the write: the third read (inside mutate) sees a Position
	repo = seed()
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n >= 3 && f.ID() == "fnd-new" {
			return decidedBy(t, f, "p-late", human, human, domain.StanceAffected, "", t0)
		}
		return f
	}
	raised, err := writeSvc(repo).RollForwardFinding(ctx, "fnd-new", "prj-A", lookup)
	if err != nil || raised {
		t.Fatalf("decided under the write: raised=%v err=%v, want nothing raised and no error", raised, err)
	}
	// the domain refuses the proposal
	repo = seed()
	svc := app.NewFindingService(repo, &seqIDs{}, zeroClock{})
	if _, err := svc.RollForwardFinding(ctx, "fnd-new", "prj-A", lookup); err == nil {
		t.Fatal("a refused proposal must surface")
	}
}
