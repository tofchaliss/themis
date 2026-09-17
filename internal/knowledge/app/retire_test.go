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

type dupSource struct {
	rows []app.DuplicateIdentityRow
	err  error
	got  int
}

func (d *dupSource) DuplicateIdentityRows(_ context.Context, limit int) ([]app.DuplicateIdentityRow, error) {
	d.got = limit
	return d.rows, d.err
}

type retirer struct {
	calls  []app.DuplicateIdentityRow
	events []domain.ComponentRetired
	done   bool
	err    error
}

func (r *retirer) RetireMatch(_ context.Context, row app.DuplicateIdentityRow, _ time.Time, event any) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	r.calls = append(r.calls, row)
	if ev, ok := event.(domain.ComponentRetired); ok {
		r.events = append(r.events, ev)
	}
	return r.done, nil
}

func retireCard(t *testing.T, repo *fakeRepo, cveID string) domain.Faultline {
	t.Helper()
	svc := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{},
		domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	cve, err := value.NewCVEID(cveID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := domain.NewVulnFactsProposal("nvd", fixedClock{}.Now(), domain.VulnFacts{Severity: value.SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	f, _, err := svc.FoldProposal(context.Background(), cve, p)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// KN-SCAN-4(b): the measured repair. 87 rows of one component, every one with its canonical twin
// already recorded — so this is a DEDUPLICATION, and the event says only "this identity does not
// denote an additional component", with no superseded-by pointer.
func TestRetireSweepRetiresDuplicateIdentities(t *testing.T) {
	repo := newRepo()
	card := retireCard(t, repo, "CVE-2023-31122")
	const raw = "app:httpd@2.4.37-65.module+el8.10.0+40257+286895ef.9"
	dups := &dupSource{rows: []app.DuplicateIdentityRow{
		{ReleaseID: "rel-1", FaultlineID: card.ID(), CVE: "CVE-2023-31122", PURL: raw},
	}}
	ret := &retirer{done: true}

	svc := app.NewRetireService(dups, ret, repo, fixedClock{}, 5)
	retired, full, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if retired != 1 || full {
		t.Fatalf("sweep = %d/%v, want 1/false", retired, full)
	}
	if len(ret.events) != 1 {
		t.Fatalf("events = %d, want 1", len(ret.events))
	}
	ev := ret.events[0]
	if ev.PURL != raw {
		t.Errorf("event PURL = %q, want the exact row being retired", ev.PURL)
	}
	if ev.Reason != domain.RetiredDuplicateIdentity {
		t.Errorf("reason = %q, want %q", ev.Reason, domain.RetiredDuplicateIdentity)
	}
	if ev.CVE != "CVE-2023-31122" || ev.ReleaseID != "rel-1" {
		t.Errorf("event = %+v, want the card's CVE and the release", ev)
	}
}

// Already retired is a no-op and must not be counted: the store guards on `retired_at IS NULL`
// and reports created=false, which is what makes a re-run free and the sweep convergent.
func TestRetireSweepAlreadyRetiredIsNotCounted(t *testing.T) {
	repo := newRepo()
	card := retireCard(t, repo, "CVE-2023-31122")
	dups := &dupSource{rows: []app.DuplicateIdentityRow{
		{ReleaseID: "rel-1", FaultlineID: card.ID(), PURL: "app:httpd@1"},
	}}
	svc := app.NewRetireService(dups, &retirer{done: false}, repo, fixedClock{}, 5)
	retired, _, err := svc.Sweep(context.Background())
	if err != nil || retired != 0 {
		t.Errorf("sweep = %d/%v, want 0/nil — a no-op must not be counted as work", retired, err)
	}
}

// One card read per distinct card, not per row: the measured population is 87 rows across many
// cards, and a read per row would be 87 reads for the same handful of cards.
func TestRetireSweepReadsEachCardOnce(t *testing.T) {
	repo := newRepo()
	card := retireCard(t, repo, "CVE-2023-31122")
	rows := []app.DuplicateIdentityRow{
		{ReleaseID: "rel-1", FaultlineID: card.ID(), PURL: "app:httpd@1"},
		{ReleaseID: "rel-2", FaultlineID: card.ID(), PURL: "app:httpd@1"},
		{ReleaseID: "rel-3", FaultlineID: card.ID(), PURL: "app:httpd@1"},
	}
	ret := &retirer{done: true}
	svc := app.NewRetireService(&dupSource{rows: rows}, ret, repo, fixedClock{}, 3)
	retired, full, err := svc.Sweep(context.Background())
	if err != nil || retired != 3 {
		t.Fatalf("sweep = %d/%v, want 3/nil", retired, err)
	}
	if !full {
		t.Error("a batch that filled the limit must report full so the caller drains again")
	}
}

// Nothing to repair is the steady state after the sweep runs once, and must be free.
func TestRetireSweepNothingToDo(t *testing.T) {
	ret := &retirer{done: true}
	svc := app.NewRetireService(&dupSource{}, ret, newRepo(), fixedClock{}, 5)
	retired, full, err := svc.Sweep(context.Background())
	if err != nil || retired != 0 || full {
		t.Fatalf("sweep = %d/%v/%v, want 0/false/nil", retired, full, err)
	}
	if len(ret.calls) != 0 {
		t.Error("nothing stale must retire nothing")
	}
}

// Every failure surfaces. A repair that swallowed an error would report success having left the
// duplicate in place — indistinguishable from a clean estate.
func TestRetireSweepErrorsPropagate(t *testing.T) {
	boom := errors.New("boom")
	repo := newRepo()
	card := retireCard(t, repo, "CVE-2023-31122")
	one := []app.DuplicateIdentityRow{{ReleaseID: "rel-1", FaultlineID: card.ID(), PURL: "app:httpd@1"}}

	for _, tc := range []struct {
		name string
		svc  *app.RetireService
	}{
		{"listing duplicates", app.NewRetireService(&dupSource{err: boom}, &retirer{}, repo, fixedClock{}, 5)},
		{"loading the card", app.NewRetireService(
			&dupSource{rows: []app.DuplicateIdentityRow{{FaultlineID: "ghost", PURL: "app:x@1"}}},
			&retirer{}, repo, fixedClock{}, 5)},
		{"retiring", app.NewRetireService(&dupSource{rows: one}, &retirer{err: boom}, repo, fixedClock{}, 5)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := tc.svc.Sweep(context.Background()); err == nil {
				t.Errorf("a failure %s must propagate", tc.name)
			}
		})
	}
}

// A misconfigured batch must not become an unbounded pass, or a zero one.
func TestRetireBatchFallsBackToTheDefault(t *testing.T) {
	dups := &dupSource{}
	for _, batch := range []int{0, -3} {
		svc := app.NewRetireService(dups, &retirer{}, newRepo(), fixedClock{}, batch)
		if _, _, err := svc.Sweep(context.Background()); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		if dups.got != app.DefaultRetireBatch {
			t.Errorf("batch %d queried limit %d, want the default %d", batch, dups.got, app.DefaultRetireBatch)
		}
	}
}
