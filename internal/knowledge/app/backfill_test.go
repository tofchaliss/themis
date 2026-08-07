package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// foldSvc builds the FaultlineService the sweep folds through.
func foldSvc(repo *fakeRepo) *app.FaultlineService {
	return app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd", "osv"), domain.NewTrustPolicy(nil))
}

// proposalFor builds one source Proposal for a CVE, as a per-CVE feed would return.
func proposalFor(t *testing.T, cve, source string) app.ProposalFor {
	t.Helper()
	id, err := value.NewCVEID(cve)
	if err != nil {
		t.Fatalf("cve: %v", err)
	}
	return app.ProposalFor{CVE: id, Proposal: vulnFacts(t, source, value.SeverityHigh)}
}

type fakeQueue struct {
	cves      []string
	err       error
	gotSource string
	gotLimit  int
}

func (f *fakeQueue) CVEsMissingSource(_ context.Context, source string, limit int) ([]string, error) {
	f.gotSource, f.gotLimit = source, limit
	return f.cves, f.err
}

type fakeCVESource struct {
	byCVE map[string]app.ProposalFor
	err   map[string]error
	asked []string
}

func (f *fakeCVESource) VulnsForCVE(_ context.Context, cve value.CVEID) (app.ProposalFor, bool, error) {
	f.asked = append(f.asked, cve.String())
	if e, ok := f.err[cve.String()]; ok {
		return app.ProposalFor{}, false, e
	}
	pf, ok := f.byCVE[cve.String()]
	return pf, ok, nil
}

// The sweep asks ONLY about CVEs the enterprise already holds. That is the whole point of D5a:
// the relevance bound becomes structural rather than a post-fetch discard, so nothing is
// retrieved that could turn out to be irrelevant.
func TestBackfill_AsksOnlyAboutCardedCVEs(t *testing.T) {
	repo := newRepo()
	fold := foldSvc(repo)
	q := &fakeQueue{cves: []string{"CVE-2024-0001", "CVE-2024-0002"}}
	src := &fakeCVESource{byCVE: map[string]app.ProposalFor{
		"CVE-2024-0001": proposalFor(t, "CVE-2024-0001", "nvd"),
		"CVE-2024-0002": proposalFor(t, "CVE-2024-0002", "nvd"),
	}}

	n, err := app.NewBackfillService("nvd", src, q, fold, 50).Enrich(context.Background())
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if n != 2 {
		t.Fatalf("folded %d, want 2", n)
	}
	if q.gotSource != "nvd" || q.gotLimit != 50 {
		t.Errorf("queue asked for source=%q limit=%d, want nvd/50", q.gotSource, q.gotLimit)
	}
	if len(src.asked) != 2 {
		t.Errorf("fetched %d CVEs, want exactly the 2 on the queue", len(src.asked))
	}
}

// One unreadable record must not stall the queue: the card simply stays on it for the next
// sweep. A per-CVE failure is data, not a system fault.
func TestBackfill_SkipsAFailedOrAbsentCVEAndContinues(t *testing.T) {
	repo := newRepo()
	q := &fakeQueue{cves: []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}}
	src := &fakeCVESource{
		byCVE: map[string]app.ProposalFor{"CVE-2024-0003": proposalFor(t, "CVE-2024-0003", "nvd")},
		err:   map[string]error{"CVE-2024-0001": errors.New("nvd 500")},
		// CVE-2024-0002 is simply absent from NVD → found=false, not an error.
	}
	n, err := app.NewBackfillService("nvd", src, q, foldSvc(repo), 50).Enrich(context.Background())
	if err != nil {
		t.Fatalf("Enrich must not fail on a per-CVE problem: %v", err)
	}
	if n != 1 {
		t.Fatalf("folded %d, want 1 — the third CVE must still be reached", n)
	}
	if len(src.asked) != 3 {
		t.Errorf("asked about %d CVEs, want all 3 attempted", len(src.asked))
	}
}

// A queue-read failure aborts: without the queue there is no work to do, and pretending
// otherwise would report a successful sweep that swept nothing.
func TestBackfill_QueueFailureAborts(t *testing.T) {
	q := &fakeQueue{err: errors.New("db down")}
	src := &fakeCVESource{}
	if _, err := app.NewBackfillService("nvd", src, q, foldSvc(newRepo()), 50).Enrich(context.Background()); err == nil {
		t.Fatal("want the queue error propagated")
	}
	if len(src.asked) != 0 {
		t.Error("no fetch should happen when the queue is unreadable")
	}
}

// A settled estate costs one query and no fetches — the property that makes a short poll
// interval affordable.
func TestBackfill_EmptyQueueDoesNoWork(t *testing.T) {
	src := &fakeCVESource{}
	n, err := app.NewBackfillService("nvd", src, &fakeQueue{}, foldSvc(newRepo()), 50).Enrich(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0/nil", n, err)
	}
	if len(src.asked) != 0 {
		t.Errorf("fetched %d CVEs for an empty queue", len(src.asked))
	}
}

func TestBackfill_NonPositiveLimitFallsBackToTheDefault(t *testing.T) {
	q := &fakeQueue{}
	if _, err := app.NewBackfillService("nvd", &fakeCVESource{}, q, foldSvc(newRepo()), 0).Enrich(context.Background()); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if q.gotLimit != app.DefaultBackfillLimit {
		t.Fatalf("limit = %d, want the %d default", q.gotLimit, app.DefaultBackfillLimit)
	}
}

// An unparseable stored CVE is a data problem in one row, not a reason to abandon the sweep.
func TestBackfill_SkipsAnUnparseableStoredCVE(t *testing.T) {
	q := &fakeQueue{cves: []string{"not-a-cve", "CVE-2024-0001"}}
	src := &fakeCVESource{byCVE: map[string]app.ProposalFor{"CVE-2024-0001": proposalFor(t, "CVE-2024-0001", "nvd")}}
	n, err := app.NewBackfillService("nvd", src, q, foldSvc(newRepo()), 50).Enrich(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1/nil", n, err)
	}
}

// A STORE failure is not a per-record problem, so it stops the sweep and returns what was folded
// before it. Continuing would burn through the whole queue against a broken store, and the CVEs
// stay queued for the next run anyway.
func TestBackfill_StoreFailureStopsTheSweep(t *testing.T) {
	repo := newRepo()
	repo.saveErr = errors.New("db down")
	q := &fakeQueue{cves: []string{"CVE-2024-0001", "CVE-2024-0002"}}
	src := &fakeCVESource{byCVE: map[string]app.ProposalFor{
		"CVE-2024-0001": proposalFor(t, "CVE-2024-0001", "nvd"),
		"CVE-2024-0002": proposalFor(t, "CVE-2024-0002", "nvd"),
	}}

	n, err := app.NewBackfillService("nvd", src, q, foldSvc(repo), 50).Enrich(context.Background())
	if err == nil {
		t.Fatal("want the store failure propagated")
	}
	if n != 0 {
		t.Fatalf("folded %d, want 0", n)
	}
	if len(src.asked) != 1 {
		t.Errorf("asked about %d CVEs, want the sweep to stop after the first failure", len(src.asked))
	}
}
