package app_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// --- fakes -----------------------------------------------------------------------------

// ownersByRelease is the Registry identity seam as scope needs it: release → (product, project),
// with a per-release outage and a per-release blank answer.
type ownersByRelease struct {
	owners map[string][2]string
	names  map[string][3]string // optional: product name, project name, version
	fail   map[string]bool
	calls  int
}

func (o *ownersByRelease) ReleaseOwners(_ context.Context, releaseID string) (app.ReleaseOwners, error) {
	o.calls++
	if o.fail[releaseID] {
		return app.ReleaseOwners{}, errors.New("registry: connection refused")
	}
	own, n := o.owners[releaseID], o.names[releaseID]
	return app.ReleaseOwners{ProductID: own[0], ProjectID: own[1], ProductName: n[0], ProjectName: n[1], Version: n[2]}, nil
}

// scopeQueue is the pending-scoped-positions seam in memory: it answers from the repo (a scoped,
// direct, unmarked Position is pending), and records the marks.
type scopeQueue struct {
	repo    *fakeRepo
	marked  map[string]bool
	listErr error
	markErr error
}

func newScopeQueue(repo *fakeRepo) *scopeQueue {
	return &scopeQueue{repo: repo, marked: map[string]bool{}}
}

func (q *scopeQueue) PendingScopedPositions(_ context.Context, limit int) ([]app.ScopedPosition, error) {
	if q.listErr != nil {
		return nil, q.listErr
	}
	var out []app.ScopedPosition
	for _, id := range q.repo.order {
		f := q.repo.byID[id]
		for _, pos := range f.Positions() {
			if pos.IsScopedSource() && !q.marked[string(id)+"/"+itoa(pos.Version())] {
				out = append(out, app.ScopedPosition{FindingID: id, Version: pos.Version()})
			}
		}
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (q *scopeQueue) MarkScopeApplied(_ context.Context, id domain.FindingID, version int) error {
	if q.markErr != nil {
		return q.markErr
	}
	q.marked[string(id)+"/"+itoa(version)] = true
	return nil
}

func itoa(n int) string { return strconv.Itoa(n) }

// decidedScoped raises `pid` from the person and has them accept it with the given terms.
func decidedScoped(t *testing.T, f domain.Finding, pid domain.ProposalID, stance domain.Stance, rationale string, at time.Time, terms domain.AcceptanceTerms) domain.Finding {
	t.Helper()
	p, err := domain.NewGovernanceProposal(pid, human, stance, rationale, at, value.TrustAsserted)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.AcceptProposalWith(pid, human, at, terms); err != nil {
		t.Fatal(err)
	}
	return f
}

// The owner's estate: product MRF with projects A and B, product OTHER with project C.
func scopeOwners() *ownersByRelease {
	return &ownersByRelease{
		owners: map[string][2]string{"rel-a1": {"MRF", "A"}, "rel-a2": {"MRF", "A"}, "rel-b1": {"MRF", "B"}, "rel-c1": {"OTHER", "C"}},
		// Only rel-a1 has names: a rationale from it reads "oamp 1.0", one from the others
		// falls back to the release id.
		names: map[string][3]string{"rel-a1": {"Media", "oamp", "1.0"}},
	}
}

func scopeProduct() domain.AcceptanceTerms { return domain.AcceptanceTerms{Scope: domain.ScopeProduct} }

// --- targets (D2) ----------------------------------------------------------------------

// Who a product-scoped decision on project A reaches: the other release of A and the release
// of B (same package, versions moved → component level); not the other product, not a decided
// target, not a different package, not a scope-only target, not the same release. Project scope
// stops at A. Release scope reaches nobody.
func TestScopePropagation_Targets(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "built without the codec", t0, scopeProduct()))
	repo.seed(withPURL(t, identified(t, "a2", "rel-a2", "fl-1", "CVE-2026-1"), tiff39, "carrier"))
	repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	repo.seed(withPURL(t, identified(t, "c1", "rel-c1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	repo.seed(decidedBy(t, withPURL(t, identified(t, "b1-decided", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "q", human, human, domain.StanceAffected, "", t0))
	repo.seed(withPURL(t, identified(t, "b1-other-pkg", "rel-b1", "fl-1", "CVE-2026-1"), httpd, "carrier"))
	repo.seed(withPURL(t, identified(t, "b1-scope-only", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "scope"))
	repo.seed(withPURL(t, identified(t, "same-release", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	repo.seed(withPURL(t, identified(t, "other-cve", "rel-b1", "fl-2", "CVE-2026-2"), tiff38, "carrier"))

	owners := scopeOwners()
	sp := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, owners)

	got, err := sp.Targets(ctx, "src", domain.ScopeProduct)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].FindingID != "a2" || got[0].Level != domain.LevelComponent || got[0].ProjectID != "A" || got[0].ProjectName != "" ||
		got[1].FindingID != "b1" || got[1].Level != domain.LevelArtifact || got[1].ProductID != "MRF" || got[1].ReleaseID != "rel-b1" {
		t.Fatalf("product targets = %+v", got)
	}
	if owners.calls != 4 { // the source, then one hop per qualifying target (a2, b1, c1) — never the rejected ones
		t.Errorf("registry calls = %d, want 4", owners.calls)
	}
	if got, _ := sp.Targets(ctx, "src", domain.ScopeProject); len(got) != 1 || got[0].FindingID != "a2" {
		t.Errorf("project targets = %+v", got)
	}
	if got, err := sp.Targets(ctx, "src", domain.ScopeRelease); err != nil || got != nil {
		t.Errorf("release targets = %+v %v", got, err)
	}
	// Failures surface, never an empty list.
	if _, err := sp.Targets(ctx, "ghost", domain.ScopeProduct); err == nil {
		t.Error("unknown source accepted")
	}
	owners.fail = map[string]bool{"rel-b1": true}
	if _, err := sp.Targets(ctx, "src", domain.ScopeProduct); err == nil {
		t.Error("a Registry outage on a target must surface")
	}
	owners.fail = map[string]bool{"rel-a1": true}
	if _, err := sp.Targets(ctx, "src", domain.ScopeProduct); err == nil {
		t.Error("a Registry outage on the source must surface")
	}
	owners.fail = nil
	owners.owners["rel-a1"] = [2]string{"", "A"}
	if _, err := sp.Targets(ctx, "src", domain.ScopeProduct); !errors.Is(err, app.ErrUnresolvedReleaseIdentity) {
		t.Errorf("blank owner = %v, want unresolved", err)
	}
	owners.owners["rel-a1"] = [2]string{"MRF", "A"}
	repo.byFaultlineErr = errors.New("db down")
	if _, err := sp.Targets(ctx, "src", domain.ScopeProduct); err == nil {
		t.Error("an unlistable Faultline must surface")
	}
	repo.byFaultlineErr = nil
	repo.onGetByID = func(_ int, f domain.Finding) domain.Finding {
		if f.ID() == "src" {
			repo.getByIDErr = errors.New("db down") // the source reads; the first sibling does not
		}
		return f
	}
	if _, err := sp.Targets(ctx, "src", domain.ScopeProduct); err == nil {
		t.Error("an unreadable sibling must surface")
	}
}

// --- apply and sweep (D3) --------------------------------------------------------------

// The person's decision lands on the target as THEIR Position: same stance, same actor, the
// terms carried, the scope and the source recorded, the rationale naming where it came from,
// the ordinary events. A second sweep finds nothing pending and applies nothing twice.
func TestScopePropagation_SweepAppliesThePersonsDecision(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	terms := domain.AcceptanceTerms{Scope: domain.ScopeProduct, ReviewBy: t0.Add(30 * 24 * time.Hour), Owner: "owner@example.test", Treatment: domain.TreatmentTransfer, Proof: "https://wiki.example.test/r/1"}
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceAcceptedRisk, "compensated by the WAF", t0, terms))
	repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff39, "carrier"))
	repo.seed(withPURL(t, identified(t, "c1", "rel-c1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	q := newScopeQueue(repo)
	sp := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, scopeOwners())

	res, err := sp.Sweep(ctx)
	if err != nil || res.Decisions != 1 || res.Applied != 1 {
		t.Fatalf("sweep = %+v %v, want one decision, one applied", res, err)
	}
	b1 := repo.byID["b1"]
	pos, ok := b1.CurrentPosition()
	if !ok || pos.Stance() != domain.StanceAcceptedRisk || pos.Actor() != human {
		t.Fatalf("target position = %+v %v; want the person's accepted_risk", pos, ok)
	}
	in := pos.Inputs()
	if in.AcceptedProposalID != "scoped:b1:src:v1" || in.Scope != domain.ScopeProduct || in.PropagatedFrom != (domain.PropagationSource{FindingID: "src", Version: 1}) {
		t.Errorf("inputs = %+v", in)
	}
	if !in.ReviewBy.Equal(terms.ReviewBy) || in.Owner != terms.Owner || in.Treatment != terms.Treatment || in.Proof != terms.Proof {
		t.Errorf("terms not carried: %+v", in)
	}
	if !strings.Contains(pos.Rationale(), "compensated by the WAF") || !strings.Contains(pos.Rationale(), "applied by scope product from oamp 1.0 (Finding src)") {
		t.Errorf("rationale = %q", pos.Rationale())
	}
	if ps := b1.Proposals(); len(ps) != 1 || ps[0].Proposer() != human || ps[0].EvidenceTrust() != value.TrustAsserted || ps[0].IsOpen() {
		t.Errorf("proposal = %+v", ps)
	}
	if n := len(repo.lastNotes); n != 3 || repo.lastNotes[0].EventType != app.EventProposalRaised || repo.lastNotes[1].EventType != app.EventProposalAccepted || repo.lastNotes[2].EventType != app.EventPositionEstablished {
		t.Errorf("notes = %+v", repo.lastNotes)
	}
	if _, decided := repo.byID["c1"].CurrentPosition(); decided {
		t.Error("the other product was decided")
	}

	// Nothing pending now; a re-run applies nothing.
	again, err := sp.Sweep(ctx)
	if err != nil || again.Decisions != 0 || again.Applied != 0 {
		t.Fatalf("second sweep = %+v %v", again, err)
	}
	if n, err := sp.Apply(ctx, app.ScopedPosition{FindingID: "src", Version: 1}); err != nil || n != 0 {
		t.Fatalf("re-apply = %d %v, want nothing (target decided)", n, err)
	}
}

// Nothing is applied from a decision that is no longer current, from a propagated Position, or
// from a release-scoped one; the row is still marked so the queue drains.
func TestScopePropagation_ApplySkipsStaleAndNonSources(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	src := decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p1", domain.StanceNotAffected, "", t0, scopeProduct())
	src = decidedBy(t, src, "p2", human, human, domain.StanceAffected, "changed my mind", t0.Add(time.Hour))
	repo.seed(src)
	repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	q := newScopeQueue(repo)
	q.marked = map[string]bool{}
	sp := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, scopeOwners())
	if n, err := sp.Apply(ctx, app.ScopedPosition{FindingID: "src", Version: 1}); err != nil || n != 0 {
		t.Fatalf("stale version applied: %d %v", n, err)
	}
	if n, err := sp.Apply(ctx, app.ScopedPosition{FindingID: "src", Version: 2}); err != nil || n != 0 {
		t.Fatalf("release-scoped v2 applied: %d %v", n, err)
	}
	if _, err := sp.Apply(ctx, app.ScopedPosition{FindingID: "ghost", Version: 1}); err == nil {
		t.Fatal("unknown source accepted")
	}
	// A propagated Position is never a source: b1 gets one from a fresh scoped decision, and is
	// then not listed as pending itself.
	repo = newRepo()
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p1", domain.StanceNotAffected, "", t0, scopeProduct()))
	repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	q = newScopeQueue(repo)
	sp = app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, scopeOwners())
	if res, err := sp.Sweep(ctx); err != nil || res.Applied != 1 {
		t.Fatalf("sweep = %+v %v", res, err)
	}
	if rows, _ := q.PendingScopedPositions(ctx, 10); len(rows) != 0 {
		t.Fatalf("a propagated Position is pending: %+v", rows)
	}
	if n, err := sp.Apply(ctx, app.ScopedPosition{FindingID: "b1", Version: 1}); err != nil || n != 0 {
		t.Fatalf("propagated Position used as a source: %d %v", n, err)
	}
	if _, decided := repo.byID["src"].CurrentPosition(); !decided || len(repo.byID["src"].Positions()) != 1 {
		t.Error("the source was touched")
	}
}

// Failures leave the row pending: the list, the Registry, the write and the mark.
func TestScopePropagation_SweepFailuresLeaveTheRowPending(t *testing.T) {
	ctx := context.Background()
	seed := func() (*fakeRepo, *scopeQueue, *ownersByRelease) {
		repo := newRepo()
		repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p1", domain.StanceNotAffected, "", t0, scopeProduct()))
		repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
		return repo, newScopeQueue(repo), scopeOwners()
	}
	repo, q, owners := seed()
	q.listErr = errors.New("db down")
	if _, err := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners).Sweep(ctx); err == nil {
		t.Fatal("list failure swallowed")
	}
	repo, q, owners = seed()
	owners.fail = map[string]bool{"rel-b1": true}
	sp := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners)
	if _, err := sp.Sweep(ctx); err == nil || len(q.marked) != 0 {
		t.Fatalf("Registry outage: err=%v marked=%v, want error and nothing marked", err, q.marked)
	}
	owners.fail = map[string]bool{"rel-a1": true} // the SOURCE release unresolvable: same answer
	if _, err := sp.Sweep(ctx); err == nil || len(q.marked) != 0 {
		t.Fatalf("Registry outage on the source: err=%v marked=%v", err, q.marked)
	}
	owners.fail = nil
	if res, err := sp.Sweep(ctx); err != nil || res.Applied != 1 || len(q.marked) != 1 {
		t.Fatalf("after recovery = %+v %v marked=%v", res, err, q.marked)
	}
	repo, q, owners = seed()
	repo.saveErr = errors.New("db down")
	if _, err := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners).Sweep(ctx); err == nil || len(q.marked) != 0 {
		t.Fatalf("write failure: err=%v marked=%v", err, q.marked)
	}
	repo, q, owners = seed()
	q.markErr = errors.New("db down")
	if _, err := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners).Sweep(ctx); err == nil {
		t.Fatal("mark failure swallowed")
	}
	repo, q, owners = seed()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners).Sweep(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled sweep = %v", err)
	}
	// Cancelled between two targets of one decision.
	repo, q, owners = seed()
	repo.seed(withPURL(t, identified(t, "a2", "rel-a2", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	cancelled, cancel = context.WithCancel(ctx)
	sp = app.NewScopePropagation(writeSvc(repo), q, undecidedByRelease{repo: repo}, owners)
	b1Reads := 0
	repo.onGetByID = func(_ int, f domain.Finding) domain.Finding {
		if f.ID() == "b1" {
			if b1Reads++; b1Reads == 2 {
				cancel() // the first target is being written (its second read); the second never starts
			}
		}
		return f
	}
	if n, err := sp.Apply(cancelled, app.ScopedPosition{FindingID: "src", Version: 1}); !errors.Is(err, context.Canceled) || n != 1 {
		t.Fatalf("cancelled apply = %d %v", n, err)
	}
}

// --- the later-born half (D4, D5) --------------------------------------------------------

// A Finding that opens on a new release of the product gets the standing product-scoped decision
// at its evaluation; a project-scoped one only within its project; a release-scoped sibling, a
// propagated sibling and another product's are ignored; two disagreeing standing decisions apply
// nothing and are counted as a conflict; two agreeing ones: the latest wins.
func TestScopePropagation_ForRelease(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src-a", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0, scopeProduct()))
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src-c", "rel-c1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceAffected, "", t0, scopeProduct()))
	repo.seed(decidedBy(t, withPURL(t, identified(t, "rel-only", "rel-a2", "fl-2", "CVE-2026-2"), tiff38, "carrier"), "p", human, human, domain.StanceAffected, "", t0))
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src-proj", "rel-a2", "fl-3", "CVE-2026-3"), tiff38, "carrier"), "p", domain.StanceMitigated, "", t0, domain.AcceptanceTerms{Scope: domain.ScopeProject}))
	// the new release of project B
	repo.seed(withPURL(t, identified(t, "new-1", "rel-b1", "fl-1", "CVE-2026-1"), tiff39, "carrier"))
	repo.seed(withPURL(t, identified(t, "new-2", "rel-b1", "fl-2", "CVE-2026-2"), tiff38, "carrier"))
	repo.seed(withPURL(t, identified(t, "new-3", "rel-b1", "fl-3", "CVE-2026-3"), tiff38, "carrier"))
	repo.seed(withPURL(t, identified(t, "new-other-pkg", "rel-b1", "fl-4", "CVE-2026-4"), httpd, "carrier"))
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src-4", "rel-a1", "fl-4", "CVE-2026-4"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0, scopeProduct()))
	owners := scopeOwners()
	sp := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, owners)

	res, err := sp.ForRelease(ctx, "rel-b1", "MRF", "B")
	if err != nil {
		t.Fatal(err)
	}
	if res.Decisions != 4 || res.Applied != 1 || res.Conflicts != 0 {
		t.Fatalf("result = %+v, want 4 considered, 1 applied", res)
	}
	pos, ok := repo.byID["new-1"].CurrentPosition()
	if !ok || pos.Stance() != domain.StanceNotAffected || pos.Inputs().PropagatedFrom.FindingID != "src-a" {
		t.Errorf("new-1 = %+v %v", pos, ok)
	}
	for _, id := range []string{"new-2", "new-3", "new-other-pkg"} {
		if _, decided := repo.byID[domain.FindingID(id)].CurrentPosition(); decided {
			t.Errorf("%s decided", id)
		}
	}
	// A conflict: a second product-scoped decision on fl-1 that disagrees. new-1 is decided
	// already, so a fresh target shows it.
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src-a2", "rel-a2", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceAffected, "", t0.Add(time.Hour), scopeProduct()))
	repo.seed(withPURL(t, identified(t, "new-5", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	res, err = sp.ForRelease(ctx, "rel-b1", "MRF", "B")
	if err != nil || res.Conflicts != 1 || res.Applied != 0 {
		t.Fatalf("conflict run = %+v %v", res, err)
	}
	if _, decided := repo.byID["new-5"].CurrentPosition(); decided {
		t.Error("a conflicted target was decided")
	}
	// Agreeing: the later one wins and is named as the source.
	repo = newRepo()
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "old", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0, scopeProduct()))
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "newer", "rel-a2", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0.Add(time.Hour), scopeProduct()))
	repo.seed(withPURL(t, identified(t, "new-1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	sp = app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, scopeOwners())
	if res, err := sp.ForRelease(ctx, "rel-b1", "MRF", "B"); err != nil || res.Applied != 1 {
		t.Fatalf("agreeing run = %+v %v", res, err)
	}
	if pos, _ := repo.byID["new-1"].CurrentPosition(); pos.Inputs().PropagatedFrom.FindingID != "newer" {
		t.Errorf("source = %+v, want the later decision", pos.Inputs().PropagatedFrom)
	}
	// Refusals and failures.
	if _, err := sp.ForRelease(ctx, "rel-b1", "", "B"); !errors.Is(err, app.ErrUnresolvedReleaseIdentity) {
		t.Errorf("blank product = %v", err)
	}
	if _, err := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo, err: errors.New("db")}, scopeOwners()).ForRelease(ctx, "rel-b1", "MRF", "B"); err == nil {
		t.Error("lister failure swallowed")
	}
	repo.seed(withPURL(t, identified(t, "new-9", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := sp.ForRelease(cancelled, "rel-b1", "MRF", "B"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled = %v", err)
	}
}

// The narrow branches of the later-born pass: an unreadable target, an unreadable sibling, an
// unlistable Faultline, a Registry outage on a sibling, a target decided between the read and
// the write, and a target the domain refuses.
func TestScopePropagation_ForReleaseFailures(t *testing.T) {
	ctx := context.Background()
	seed := func() (*fakeRepo, *ownersByRelease) {
		repo := newRepo()
		repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0, scopeProduct()))
		repo.seed(withPURL(t, identified(t, "new-1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
		return repo, scopeOwners()
	}
	run := func(repo *fakeRepo, owners *ownersByRelease) error {
		_, err := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, owners).ForRelease(ctx, "rel-b1", "MRF", "B")
		return err
	}
	repo, owners := seed()
	repo.getByIDErr = errors.New("db down")
	if run(repo, owners) == nil {
		t.Error("unreadable target swallowed")
	}
	repo, owners = seed()
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n == 1 {
			repo.getByIDErr = errors.New("db down")
		}
		return f
	}
	if run(repo, owners) == nil {
		t.Error("unreadable sibling swallowed")
	}
	repo, owners = seed()
	repo.byFaultlineErr = errors.New("db down")
	if run(repo, owners) == nil {
		t.Error("unlistable Faultline swallowed")
	}
	repo, owners = seed()
	owners.fail = map[string]bool{"rel-a1": true}
	if run(repo, owners) == nil {
		t.Error("Registry outage swallowed")
	}
	// decided between the read and the write: the write's read sees a Position — nothing applied, no error
	repo, owners = seed()
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n >= 3 && f.ID() == "new-1" {
			return decidedBy(t, f, "late", human, human, domain.StanceAffected, "", t0)
		}
		return f
	}
	if res, err := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, owners).ForRelease(ctx, "rel-b1", "MRF", "B"); err != nil || res.Applied != 0 {
		t.Errorf("decided under the write = %+v %v", res, err)
	}
	// the pair already on the target (a crash between the write and the mark): nothing twice
	repo, owners = seed()
	tgt := repo.byID["new-1"]
	p, _ := domain.NewGovernanceProposal(domain.ScopedProposalID("new-1", "src", 1), human, domain.StanceNotAffected, "", t0, value.TrustAsserted)
	_ = tgt.RaiseProposal(p)
	_ = tgt.RejectProposal(p.ID(), human, t0)
	repo.seed(tgt)
	if res, err := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, owners).ForRelease(ctx, "rel-b1", "MRF", "B"); err != nil || res.Applied != 0 {
		t.Errorf("duplicate pair = %+v %v", res, err)
	}
	// the domain refuses: an archived target cannot take a proposal
	repo, owners = seed()
	tgt = repo.byID["new-1"]
	_ = tgt.Resolve()
	_ = tgt.Archive()
	repo.seed(tgt)
	repo.byID["new-1"] = tgt
	und := undecidedByRelease{repo: repo}
	if _, err := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), und, owners).ForRelease(ctx, "rel-b1", "MRF", "B"); err == nil {
		t.Error("refused proposal swallowed")
	}
	// decided between listing and the first read: left alone, no error
	repo, owners = seed()
	repo.onGetByID = func(_ int, f domain.Finding) domain.Finding {
		if f.ID() == "new-1" {
			return decidedBy(t, f, "late", human, human, domain.StanceAffected, "", t0)
		}
		return f
	}
	if res, err := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, owners).ForRelease(ctx, "rel-b1", "MRF", "B"); err != nil || res.Applied != 0 || res.Decisions != 1 {
		t.Errorf("decided before the read = %+v %v", res, err)
	}
	// a source Position whose terms the domain refuses on the target (an accepted risk with no
	// owner, which only a reconstituted row can carry): the proposal is raised, the accept fails
	repo, owners = seed()
	noOwner := domain.ReconstituteFinding("src", "rel-a1", "fl-1", "CVE-2026-1", repo.byID["src"].Components(), domain.StagePositionEstablished, nil,
		[]domain.Position{domain.ReconstitutePosition(1, domain.StanceAcceptedRisk, "", human, domain.PositionInputs{Scope: domain.ScopeProduct}, t0)}, 3)
	repo.seed(noOwner)
	if err := run(repo, owners); !errors.Is(err, domain.ErrOwnerRequired) {
		t.Errorf("ownerless acceptance = %v, want ErrOwnerRequired", err)
	}
	// a source whose Position names no valid actor (reconstituted) makes a proposal the domain refuses
	repo, owners = seed()
	bad := domain.ReconstituteFinding("src", "rel-a1", "fl-1", "CVE-2026-1", repo.byID["src"].Components(), domain.StagePositionEstablished, nil,
		[]domain.Position{domain.ReconstitutePosition(1, domain.StanceNotAffected, "", domain.Actor{}, domain.PositionInputs{Scope: domain.ScopeProduct}, t0)}, 3)
	repo.seed(bad)
	if run(repo, owners) == nil {
		t.Error("invalid proposer swallowed")
	}
}

// The sweep rides a ticker and stops with the context.
func TestScopePropagation_RunEvery(t *testing.T) {
	repo := newRepo()
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0, scopeProduct()))
	repo.seed(withPURL(t, identified(t, "b1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	sp := app.NewScopePropagation(writeSvc(repo), newScopeQueue(repo), undecidedByRelease{repo: repo}, scopeOwners())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan app.ScopeResult, 1)
	go sp.RunEvery(ctx, time.Millisecond, func(res app.ScopeResult, err error) {
		if err == nil && res.Applied == 1 {
			select {
			case done <- res:
			default:
			}
		}
	})
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep never ran")
	}
	cancel()
	// A nil report is allowed.
	ctx2, cancel2 := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() { sp.RunEvery(ctx2, time.Millisecond, nil); close(stopped) }()
	time.Sleep(5 * time.Millisecond)
	cancel2()
	<-stopped
}

// On the worker, a scope failure defers the row like roll-forward does; after recovery the
// Position is applied BEFORE roll-forward runs, so the target carries no proposal.
func TestWorker_ScopeFailureDefersTheRow(t *testing.T) {
	ctx := context.Background()
	q, worker, _, _ := evaluationWorker(t, "MRF", "B")
	record(t, q, "rel-b1", "ev-1", domain.CauseNewSBOM)

	repo := newRepo()
	repo.seed(decidedScoped(t, withPURL(t, identified(t, "src", "rel-a1", "fl-1", "CVE-2026-1"), tiff38, "carrier"), "p", domain.StanceNotAffected, "", t0, scopeProduct()))
	repo.seed(withPURL(t, identified(t, "new-1", "rel-b1", "fl-1", "CVE-2026-1"), tiff38, "carrier"))
	owners := scopeOwners()
	owners.fail = map[string]bool{"rel-a1": true}
	svc := writeSvc(repo)
	worker.w.WithScopePropagation(app.NewScopePropagation(svc, newScopeQueue(repo), undecidedByRelease{repo: repo}, owners)).
		WithRollForward(app.NewRollForward(svc, undecidedByRelease{repo: repo}, &projectByRelease{projects: map[string]string{"rel-a1": "B", "rel-b1": "B"}}))

	worker.Tick(ctx)
	if len(q.publishedEvents()) != 0 || len(q.pending()) != 1 {
		t.Fatalf("after a scope failure: published=%d pending=%d, want 0 and 1", len(q.publishedEvents()), len(q.pending()))
	}
	owners.fail = nil
	worker.clock.advance(2 * app.EvaluationBackoffMax)
	worker.Tick(ctx)
	f := repo.byID["new-1"]
	pos, ok := f.CurrentPosition()
	if len(q.publishedEvents()) != 1 || !ok || pos.Stance() != domain.StanceNotAffected {
		t.Fatalf("after recovery: published=%d decided=%v", len(q.publishedEvents()), ok)
	}
	if ps := f.Proposals(); len(ps) != 1 || !strings.HasPrefix(string(ps[0].ID()), "scoped:") {
		t.Errorf("proposals = %+v; want only the scoped one, no roll-forward", ps)
	}
}
