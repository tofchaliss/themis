package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// expiredLister answers the sweep's question from the fake repo: suppressed, review-by before
// now, not yet marked.
type expiredLister struct {
	repo *fakeRepo
	err  error
	asks int
}

func (l *expiredLister) SuppressedWithExpiredReview(_ context.Context, now time.Time, limit int) ([]domain.FindingID, error) {
	l.asks++
	if l.err != nil {
		return nil, l.err
	}
	var out []domain.FindingID
	for _, id := range l.repo.order {
		f := l.repo.byID[id]
		pos, ok := f.CurrentPosition()
		if !ok || !domain.SuppressesTriage(pos.Stance()) {
			continue
		}
		if _, _, marked := f.DispositionStale(); marked || !domain.Expired(pos.Inputs().ReviewBy, now) {
			continue
		}
		out = append(out, id)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func staleEvents(notes []app.OutboxNote) int {
	n := 0
	for _, x := range notes {
		if x.EventType == app.EventDispositionStale {
			n++
		}
	}
	return n
}

// RF-2, the whole point: a suppressed Finding whose review date passed is re-surfaced on the
// clock — marked on the Finding (so the queue shows it) and announced — without touching the
// Position. The next sweep finds nothing: the mark stands until somebody re-decides.
func TestReviewBySweep_ResurfacesExpiredReviews(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressedUntil(t, domain.StanceAcceptedRisk, domain.ExploitSignals{}, fixedNow.Add(-24*time.Hour)))
	svc := writeSvc(repo)
	lister := &expiredLister{repo: repo}
	sweep := app.NewReviewBySweep(svc, lister, fixedClock{})

	checked, resurfaced, err := sweep.Run(context.Background())
	if err != nil || checked != 1 || resurfaced != 1 {
		t.Fatalf("run = %d/%d err=%v, want 1 checked, 1 re-surfaced", checked, resurfaced, err)
	}
	f := repo.byID["fnd-1"]
	since, reason, ok := f.DispositionStale()
	if !ok || !since.Equal(fixedNow) || reason == "" {
		t.Fatalf("mark = %v %q ok=%v, want set at the sweep time with a reason", since, reason, ok)
	}
	if pos, ok := f.CurrentPosition(); !ok || pos.Stance() != domain.StanceAcceptedRisk {
		t.Fatal("the Position must stand — the sweep re-opens the question, never the decision")
	}
	if staleEvents(repo.lastNotes) != 1 {
		t.Fatalf("stale events = %d, want 1 (subscribers still hear it)", staleEvents(repo.lastNotes))
	}
	if c, r, err := sweep.Run(context.Background()); err != nil || c != 0 || r != 0 {
		t.Fatalf("second run = %d/%d err=%v, want nothing listed", c, r, err)
	}
}

// What the sweep leaves alone: no review date, a date still ahead, an affected Position; and
// the re-check under the write (re-decided meanwhile) is a skip, not an error.
func TestReviewBySweep_LeavesTheRestAlone(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceNotAffected, domain.ExploitSignals{})) // no date agreed
	svc := writeSvc(repo)
	if c, r, err := app.NewReviewBySweep(svc, &expiredLister{repo: repo}, fixedClock{}).Run(ctx); err != nil || c != 0 || r != 0 {
		t.Fatalf("no date: %d/%d err=%v", c, r, err)
	}
	repo = newRepo()
	repo.seed(suppressedUntil(t, domain.StanceNotAffected, domain.ExploitSignals{}, fixedNow.Add(24*time.Hour)))
	if c, _, _ := app.NewReviewBySweep(writeSvc(repo), &expiredLister{repo: repo}, fixedClock{}).Run(ctx); c != 0 {
		t.Fatalf("date ahead: checked %d, want 0", c)
	}
	// Listed, then re-decided (affected) before the write: the direct entry re-checks and skips.
	repo = newRepo()
	repo.seed(suppressedUntil(t, domain.StanceNotAffected, domain.ExploitSignals{}, fixedNow.Add(-time.Hour)))
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		p, _ := domain.NewGovernanceProposal("p-aff", human, domain.StanceAffected, "", fixedNow, value.TrustAsserted)
		_ = f.RaiseProposal(p)
		_, _ = f.AcceptProposal("p-aff", human, fixedNow)
		return f
	}
	if marked, err := writeSvc(repo).ResurfaceExpiredReview(ctx, "fnd-1"); err != nil || marked {
		t.Fatalf("re-decided under the write: marked=%v err=%v", marked, err)
	}
	// Listed, then marked by the drift watcher before the write: skip too.
	repo = newRepo()
	g := suppressedUntil(t, domain.StanceNotAffected, domain.ExploitSignals{}, fixedNow.Add(-time.Hour))
	g.MarkDispositionStale("the CVE entered KEV", fixedNow.Add(-time.Minute))
	repo.seed(g)
	if marked, err := writeSvc(repo).ResurfaceExpiredReview(ctx, "fnd-1"); err != nil || marked {
		t.Fatalf("already marked: marked=%v err=%v", marked, err)
	}
	if _, reason, _ := repo.byID["fnd-1"].DispositionStale(); reason != "the CVE entered KEV" {
		t.Fatalf("the first reason must stand, got %q", reason)
	}
}

func TestReviewBySweep_FailuresSurface(t *testing.T) {
	ctx := context.Background()
	repo := newRepo()
	repo.seed(suppressedUntil(t, domain.StanceNotAffected, domain.ExploitSignals{}, fixedNow.Add(-time.Hour)))
	if _, _, err := app.NewReviewBySweep(writeSvc(repo), &expiredLister{err: errors.New("db")}, fixedClock{}).Run(ctx); err == nil {
		t.Fatal("lister failure must surface")
	}
	repo.saveErr = errors.New("db")
	if _, _, err := app.NewReviewBySweep(writeSvc(repo), &expiredLister{repo: repo}, fixedClock{}).Run(ctx); err == nil {
		t.Fatal("write failure must surface")
	}
	repo.saveErr = nil
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := app.NewReviewBySweep(writeSvc(repo), &expiredLister{repo: repo}, fixedClock{}).Run(cctx); err == nil {
		t.Fatal("cancellation must stop the sweep")
	}
}

// RunEvery ticks until cancelled and reports each pass.
func TestReviewBySweep_RunEveryReports(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressedUntil(t, domain.StanceNotAffected, domain.ExploitSignals{}, fixedNow.Add(-time.Hour)))
	lister := &expiredLister{repo: repo}
	ctx, cancel := context.WithCancel(context.Background())
	reports := make(chan int, 8)
	go app.NewReviewBySweep(writeSvc(repo), lister, fixedClock{}).RunEvery(ctx, 5*time.Millisecond, func(_, resurfaced int, err error) {
		if err == nil {
			reports <- resurfaced
		}
	})
	first := <-reports
	<-reports
	cancel()
	if first != 1 {
		t.Fatalf("first pass re-surfaced %d, want 1", first)
	}
	// A nil report is allowed.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel2()
	app.NewReviewBySweep(writeSvc(repo), lister, fixedClock{}).RunEvery(ctx2, 5*time.Millisecond, nil)
}

// The visible consumer (RF-2): a re-surfaced suppression is back in the queue at full effective
// priority, and the drift watcher now marks the Finding as well as emitting the event.
func TestReadService_ResurfacedSuppressionIsBackInTheQueue(t *testing.T) {
	proj := fakeProjection{posture: []app.PostureEntry{
		{FindingID: "quiet", BaseScore: 70, Stance: domain.StanceNotAffected},
		{FindingID: "resurfaced", BaseScore: 70, Stance: domain.StanceNotAffected, StaleSince: fixedNow, StaleReason: "the review-by date on this decision has passed"},
	}}
	got, err := app.NewReadService(newRepo(), proj, nil, 0).ReleasePosture(context.Background(), "rel-1")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ResidualPriority != 0 || got[1].ResidualPriority != 70 {
		t.Fatalf("residual quiet=%d resurfaced=%d, want 0 and 70", got[0].ResidualPriority, got[1].ResidualPriority)
	}
}

func TestReactToEnrichment_DriftMarksTheFindingOnce(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceNotAffected, domain.ExploitSignals{EPSS: 0.02}))
	s := writeSvc(repo)
	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Signals: domain.ExploitSignals{EPSS: 0.02, KEV: true}}
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
	if _, reason, ok := repo.byID["fnd-1"].DispositionStale(); !ok || reason == "" {
		t.Fatalf("drift must mark the Finding, got ok=%v reason=%q", ok, reason)
	}
	saves := repo.saveCalls
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != saves {
		t.Fatalf("a second enrichment with the same drift must not re-mark or re-announce; saved notes=%v", noteTypes(repo.lastNotes))
	}
	// Marked between the read and the write (the sweep got there first): nothing persisted.
	repo = newRepo()
	repo.seed(suppressed(t, domain.StanceNotAffected, domain.ExploitSignals{EPSS: 0.02}))
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n >= 2 {
			f.MarkDispositionStale("the review-by date on this decision has passed", fixedNow)
		}
		return f
	}
	s = writeSvc(repo)
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != 0 {
		t.Fatalf("saves = %d, want 0 when the mark was set under the write", repo.saveCalls)
	}
}
