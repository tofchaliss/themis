package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// foldSvc builds the FaultlineService the sweep folds and supersedes through.
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

func sweep(repo *fakeRepo, src app.CVEVulnSource, q app.EnrichmentQueue, limit int) *app.BackfillService {
	return app.NewBackfillService("nvd", src, q, foldSvc(repo), limit, time.Hour)
}

type fakeQueue struct {
	cves      []string
	err       error
	gotSource string
	gotLimit  int
	gotStale  time.Duration
	callCount int
}

func (f *fakeQueue) CVEsNeedingRefresh(_ context.Context, source string, staleAfter time.Duration, limit int) ([]string, error) {
	f.gotSource, f.gotStale, f.gotLimit = source, staleAfter, limit
	f.callCount++
	return f.cves, f.err
}

type fakeCVESource struct {
	facts map[string]app.CVEFacts
	err   map[string]error
	asked []string
}

func (f *fakeCVESource) VulnsForCVE(_ context.Context, cve value.CVEID) (app.CVEFacts, error) {
	f.asked = append(f.asked, cve.String())
	if e, ok := f.err[cve.String()]; ok {
		return app.CVEFacts{}, e
	}
	return f.facts[cve.String()], nil
}

// The sweep asks ONLY about CVEs the enterprise already holds — the relevance bound made
// structural rather than a post-fetch discard (D5a).
func TestBackfill_AsksOnlyAboutCardedCVEs(t *testing.T) {
	repo := newRepo()
	q := &fakeQueue{cves: []string{"CVE-2024-0001", "CVE-2024-0002"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{
		"CVE-2024-0001": {Proposal: proposalFor(t, "CVE-2024-0001", "nvd"), Found: true},
		"CVE-2024-0002": {Proposal: proposalFor(t, "CVE-2024-0002", "nvd"), Found: true},
	}}

	n, err := sweep(repo, src, q, 50).Enrich(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v, want 2/nil", n, err)
	}
	if q.gotSource != "nvd" || q.gotLimit != 50 || q.gotStale != time.Hour {
		t.Errorf("queue asked source=%q limit=%d stale=%v", q.gotSource, q.gotLimit, q.gotStale)
	}
	if len(src.asked) != 2 {
		t.Errorf("fetched %d CVEs, want exactly the 2 queued", len(src.asked))
	}
}

// KN-WITHDRAW-1: a CVE the source reports WITHDRAWN retires its card. Observed live
// 2026-08-07 — CVE-2021-20095 carries NVD `vulnStatus: "Rejected"` and, before this, kept its
// card and an open Finding indefinitely.
func TestBackfill_WithdrawnCVESupersedesItsCard(t *testing.T) {
	repo := newRepo()
	fold := foldSvc(repo)
	// Card exists first — a withdrawal is only meaningful for something we hold.
	if _, _, err := fold.FoldProposal(context.Background(), cve(t, "CVE-2021-20095"),
		vulnFacts(t, "osv", value.SeverityMedium)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	q := &fakeQueue{cves: []string{"CVE-2021-20095"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{"CVE-2021-20095": {Withdrawn: true}}}

	n, err := app.NewBackfillService("nvd", src, q, fold, 50, time.Hour).Enrich(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1/nil", n, err)
	}
	got := repo.cards["CVE-2021-20095"]
	if got.Stage() != domain.StageSuperseded {
		t.Fatalf("stage = %q, want %q — a withdrawn CVE must retire its card", got.Stage(), domain.StageSuperseded)
	}
}

// Withdrawal takes precedence over facts: a rejected record may still carry old metrics, and
// enriching from them would refresh a card that should be retired.
func TestBackfill_WithdrawalWinsOverStaleFacts(t *testing.T) {
	repo := newRepo()
	fold := foldSvc(repo)
	if _, _, err := fold.FoldProposal(context.Background(), cve(t, "CVE-2021-20095"),
		vulnFacts(t, "osv", value.SeverityMedium)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	q := &fakeQueue{cves: []string{"CVE-2021-20095"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{
		"CVE-2021-20095": {Proposal: proposalFor(t, "CVE-2021-20095", "nvd"), Found: true, Withdrawn: true},
	}}

	if _, err := app.NewBackfillService("nvd", src, q, fold, 50, time.Hour).Enrich(context.Background()); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if got := repo.cards["CVE-2021-20095"]; got.Stage() != domain.StageSuperseded {
		t.Fatalf("stage = %q, want superseded", got.Stage())
	}
}

// Superseding is idempotent, so a repeated sweep costs nothing and announces nothing — the
// lifecycle is forward-only.
func TestBackfill_WithdrawalIsIdempotent(t *testing.T) {
	repo := newRepo()
	fold := foldSvc(repo)
	if _, _, err := fold.FoldProposal(context.Background(), cve(t, "CVE-2021-20095"),
		vulnFacts(t, "osv", value.SeverityMedium)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	q := &fakeQueue{cves: []string{"CVE-2021-20095"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{"CVE-2021-20095": {Withdrawn: true}}}
	bf := app.NewBackfillService("nvd", src, q, fold, 50, time.Hour)

	if n, _ := bf.Enrich(context.Background()); n != 1 {
		t.Fatalf("first sweep folded %d, want 1", n)
	}
	if n, err := bf.Enrich(context.Background()); err != nil || n != 0 {
		t.Fatalf("second sweep n=%d err=%v, want 0/nil — already terminal", n, err)
	}
}

// A withdrawal for a CVE nothing holds is not work and not an error.
func TestBackfill_WithdrawalForAnUncardedCVEIsANoOp(t *testing.T) {
	repo := newRepo()
	q := &fakeQueue{cves: []string{"CVE-2021-20095"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{"CVE-2021-20095": {Withdrawn: true}}}
	if n, err := sweep(repo, src, q, 50).Enrich(context.Background()); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0/nil", n, err)
	}
}

// One unreadable or absent record must not stall the queue: the card stays on it for the next
// sweep. A per-CVE failure is data, not a system fault.
func TestBackfill_SkipsAFailedOrAbsentCVEAndContinues(t *testing.T) {
	repo := newRepo()
	q := &fakeQueue{cves: []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"}}
	src := &fakeCVESource{
		facts: map[string]app.CVEFacts{"CVE-2024-0003": {Proposal: proposalFor(t, "CVE-2024-0003", "nvd"), Found: true}},
		err:   map[string]error{"CVE-2024-0001": errors.New("nvd 500")},
		// CVE-2024-0002 is absent from NVD → Found=false, not an error.
	}
	n, err := sweep(repo, src, q, 50).Enrich(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1/nil — the third CVE must still be reached", n, err)
	}
	if len(src.asked) != 3 {
		t.Errorf("asked about %d CVEs, want all 3 attempted", len(src.asked))
	}
}

// A queue-read failure aborts: without the queue there is no work, and reporting a successful
// sweep that swept nothing would be the ambiguity this design exists to avoid.
func TestBackfill_QueueFailureAborts(t *testing.T) {
	src := &fakeCVESource{}
	if _, err := sweep(newRepo(), src, &fakeQueue{err: errors.New("db down")}, 50).Enrich(context.Background()); err == nil {
		t.Fatal("want the queue error propagated")
	}
	if len(src.asked) != 0 {
		t.Error("no fetch should happen when the queue is unreadable")
	}
}

// A settled estate costs one query and no fetches — what makes a short poll interval affordable.
func TestBackfill_EmptyQueueDoesNoWork(t *testing.T) {
	src := &fakeCVESource{}
	n, err := sweep(newRepo(), src, &fakeQueue{}, 50).Enrich(context.Background())
	if err != nil || n != 0 || len(src.asked) != 0 {
		t.Fatalf("n=%d err=%v asked=%d, want 0/nil/0", n, err, len(src.asked))
	}
}

func TestBackfill_NonPositiveOptionsFallBackToDefaults(t *testing.T) {
	q := &fakeQueue{}
	bf := app.NewBackfillService("nvd", &fakeCVESource{}, q, foldSvc(newRepo()), 0, 0)
	if _, err := bf.Enrich(context.Background()); err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if q.gotLimit != app.DefaultBackfillLimit || q.gotStale != app.DefaultStaleAfter {
		t.Fatalf("limit=%d stale=%v, want the %d/%v defaults", q.gotLimit, q.gotStale,
			app.DefaultBackfillLimit, app.DefaultStaleAfter)
	}
}

// An unparseable stored CVE is a data problem in one row, not a reason to abandon the sweep.
func TestBackfill_SkipsAnUnparseableStoredCVE(t *testing.T) {
	q := &fakeQueue{cves: []string{"not-a-cve", "CVE-2024-0001"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{
		"CVE-2024-0001": {Proposal: proposalFor(t, "CVE-2024-0001", "nvd"), Found: true},
	}}
	if n, err := sweep(newRepo(), src, q, 50).Enrich(context.Background()); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1/nil", n, err)
	}
}

// A STORE failure stops the sweep: continuing would burn the whole queue against a broken
// store, and the CVEs stay queued for the next run anyway.
func TestBackfill_StoreFailureStopsTheSweep(t *testing.T) {
	repo := newRepo()
	repo.saveErr = errors.New("db down")
	q := &fakeQueue{cves: []string{"CVE-2024-0001", "CVE-2024-0002"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{
		"CVE-2024-0001": {Proposal: proposalFor(t, "CVE-2024-0001", "nvd"), Found: true},
		"CVE-2024-0002": {Proposal: proposalFor(t, "CVE-2024-0002", "nvd"), Found: true},
	}}
	n, err := sweep(repo, src, q, 50).Enrich(context.Background())
	if err == nil || n != 0 {
		t.Fatalf("n=%d err=%v, want the store failure propagated", n, err)
	}
	if len(src.asked) != 1 {
		t.Errorf("asked about %d CVEs, want the sweep to stop after the first failure", len(src.asked))
	}
}

// A supersede that fails at the store stops the sweep, exactly as a fold failure does — the
// distinction that matters is store-versus-record, not which operation was in flight.
func TestBackfill_SupersedeStoreFailureStopsTheSweep(t *testing.T) {
	repo := newRepo()
	fold := foldSvc(repo)
	if _, _, err := fold.FoldProposal(context.Background(), cve(t, "CVE-2021-20095"),
		vulnFacts(t, "osv", value.SeverityMedium)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	repo.saveErr = errors.New("db down")
	q := &fakeQueue{cves: []string{"CVE-2021-20095", "CVE-2024-0001"}}
	src := &fakeCVESource{facts: map[string]app.CVEFacts{"CVE-2021-20095": {Withdrawn: true}}}

	if _, err := app.NewBackfillService("nvd", src, q, fold, 50, time.Hour).Enrich(context.Background()); err == nil {
		t.Fatal("want the store failure propagated")
	}
	if len(src.asked) != 1 {
		t.Errorf("asked about %d CVEs, want the sweep to stop after the failure", len(src.asked))
	}
}
