package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// fakeLedger scripts the stale queue and records upserts.
type fakeLedger struct {
	stale    []app.CorrelatedRelease
	staleErr error
	upserts  map[string]string // release → evidence last upserted
	upsertAt map[string]time.Time
	err      error
}

func newLedger(stale ...app.CorrelatedRelease) *fakeLedger {
	return &fakeLedger{stale: stale, upserts: map[string]string{}, upsertAt: map[string]time.Time{}}
}

func (f *fakeLedger) UpsertCorrelatedRelease(_ context.Context, releaseID, evidenceID string, at time.Time) error {
	if f.err != nil {
		return f.err
	}
	f.upserts[releaseID] = evidenceID
	f.upsertAt[releaseID] = at
	return nil
}

func (f *fakeLedger) StaleReleases(_ context.Context, _ time.Time, limit int) ([]app.CorrelatedRelease, error) {
	if f.staleErr != nil {
		return nil, f.staleErr
	}
	if len(f.stale) > limit {
		return f.stale[:limit], nil
	}
	return f.stale, nil
}

// The KN-RECOR-1 core: correlation stamps the ledger inside its unit of work — including a
// plan with ZERO items, because a release whose discovery found nothing still HAD its
// discovery run and must not look eternally stale to the sweep.
func TestApplyCorrelation_StampsTheLedger(t *testing.T) {
	ledger := newLedger()
	inv := fakeInventory{inv: inventoryOf("pkg:pypi/quiet@1")}
	corr := correlation(t, inv, fakeDiscovery{}, newMatches(), newRepo()).WithLedger(ledger)

	if _, err := corr.Correlate(context.Background(), "rel-1", "ev-1"); err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if ledger.upserts["rel-1"] != "ev-1" {
		t.Fatalf("ledger = %v, want rel-1 stamped with ev-1 despite zero matches", ledger.upserts)
	}
}

func TestApplyCorrelation_LedgerErrorPropagates(t *testing.T) {
	ledger := newLedger()
	ledger.err = errors.New("ledger down")
	corr := correlation(t, fakeInventory{inv: inventoryOf("pkg:pypi/a@1")}, fakeDiscovery{}, newMatches(), newRepo()).
		WithLedger(ledger)
	if _, err := corr.Correlate(context.Background(), "rel-1", "ev-1"); err == nil {
		t.Fatal("a ledger write failure must fail the apply — ledger and matches commit together")
	}
}

// The sweep: stale releases re-run the EXISTING correlation — new CVEs published since the
// upload become matches with nobody uploading anything, which is the entire point.
func TestRediscovery_SweepFindsNewCVEsOnOldInventory(t *testing.T) {
	// The release's inventory holds one component; discovery now knows a CVE for it that it
	// did not know at upload time.
	inv := fakeInventory{inv: inventoryOf("pkg:rpm/rocky/openssl@3.0.7")}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		"pkg:rpm/rocky/openssl@3.0.7": {{CVE: cve(t, "CVE-2026-9999"), Proposal: vulnFacts(t, "osv", value.SeverityHigh)}},
	}}
	matches := newMatches()
	ledger := newLedger(app.CorrelatedRelease{ReleaseID: "rel-old", EvidenceID: "ev-old"})
	corr := correlation(t, inv, disc, matches, newRepo()).WithLedger(ledger)
	svc := app.NewRediscoveryService(ledger, corr, fixedClock{}, 0, 0)

	swept, newM, err := svc.Sweep(context.Background())
	if err != nil || swept != 1 || newM != 1 {
		t.Fatalf("Sweep = (%d, %d, %v), want the old release swept and the new CVE matched", swept, newM, err)
	}
	if ledger.upserts["rel-old"] != "ev-old" {
		t.Errorf("ledger not re-stamped — the swept release would stay eternally stale")
	}
	// A second sweep over the same knowledge converges: still swept (the fake queue does not
	// age out), but zero NEW matches — idempotence end to end.
	_, newM2, err := svc.Sweep(context.Background())
	if err != nil || newM2 != 0 {
		t.Fatalf("re-Sweep = (%d, %v), want zero new matches", newM2, err)
	}
}

// One broken release must not starve the rest: the failure is skipped (it stays stale for
// the next sweep) and the healthy release still sweeps.
func TestRediscovery_PerReleaseFailureSkips(t *testing.T) {
	inv := fakeInventory{err: errors.New("evidence down")}
	ledger := newLedger(
		app.CorrelatedRelease{ReleaseID: "rel-a", EvidenceID: "ev-a"},
		app.CorrelatedRelease{ReleaseID: "rel-b", EvidenceID: "ev-b"},
	)
	corr := correlation(t, inv, fakeDiscovery{}, newMatches(), newRepo()).WithLedger(ledger)
	svc := app.NewRediscoveryService(ledger, corr, fixedClock{}, time.Hour, 5)

	swept, _, err := svc.Sweep(context.Background())
	if err != nil || swept != 0 {
		t.Fatalf("Sweep = (%d, %v): per-release read failures must skip, not abort", swept, err)
	}
}

func TestRediscovery_QueueReadAborts(t *testing.T) {
	ledger := newLedger()
	ledger.staleErr = errors.New("db down")
	corr := correlation(t, fakeInventory{}, fakeDiscovery{}, newMatches(), newRepo())
	if _, _, err := app.NewRediscoveryService(ledger, corr, fixedClock{}, 0, 0).Sweep(context.Background()); err == nil {
		t.Fatal("a queue-read failure must abort — without the queue there is no work")
	}
}

// The limit caps a sweep so a large estate drains across ticks.
func TestRediscovery_LimitCapsASweep(t *testing.T) {
	inv := fakeInventory{inv: inventoryOf()}
	ledger := newLedger(
		app.CorrelatedRelease{ReleaseID: "rel-1", EvidenceID: "ev-1"},
		app.CorrelatedRelease{ReleaseID: "rel-2", EvidenceID: "ev-2"},
	)
	corr := correlation(t, inv, fakeDiscovery{}, newMatches(), newRepo()).WithLedger(ledger)
	svc := app.NewRediscoveryService(ledger, corr, fixedClock{}, time.Hour, 1)
	if swept, _, _ := svc.Sweep(context.Background()); swept != 1 {
		t.Fatalf("swept = %d, want the limit respected", swept)
	}
}
