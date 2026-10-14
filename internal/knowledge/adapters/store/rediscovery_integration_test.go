//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// The KN-RECOR-1 ledger: upsert keeps ONE row per release with the latest evidence (a newer
// SBOM replaces it, so the sweep always re-reads the current inventory), and the stale query
// returns oldest-first under its limit.
func TestCorrelatedReleaseLedger(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))

	t0 := time.Unix(1_700_000_000, 0).UTC()

	if err := s.UpsertCorrelatedRelease(ctx, "rel-a", "ev-1", t0); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	if err := s.UpsertCorrelatedRelease(ctx, "rel-b", "ev-2", t0.Add(time.Hour)); err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	// A newer evidence for rel-a replaces the row — latest inventory wins.
	if err := s.UpsertCorrelatedRelease(ctx, "rel-a", "ev-9", t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("re-upsert a: %v", err)
	}

	// Both are stale against a cutoff after every stamp; rel-b is now the OLDEST.
	stale, err := s.StaleReleases(ctx, t0.Add(3*time.Hour), 10)
	if err != nil {
		t.Fatalf("stale: %v", err)
	}
	if len(stale) != 2 || stale[0].ReleaseID != "rel-b" || stale[1].EvidenceID != "ev-9" {
		t.Fatalf("stale = %+v, want [rel-b, rel-a(ev-9)] oldest-first with the replaced evidence id", stale)
	}

	// KN-SCAN-5: a scanner-only release gets a row with no evidence id, and only when none
	// exists — rel-a keeps ev-9. StampDiscovered moves the scanner-only row's clock.
	if err := s.TouchScannerRelease(ctx, "rel-a", t0.Add(5*time.Hour)); err != nil {
		t.Fatalf("touch a: %v", err)
	}
	if err := s.TouchScannerRelease(ctx, "rel-c", t0); err != nil {
		t.Fatalf("touch c: %v", err)
	}
	all, _ := s.StaleReleases(ctx, t0.Add(3*time.Hour), 10)
	byRel := map[string]app.CorrelatedRelease{}
	for _, r := range all {
		byRel[r.ReleaseID] = r
	}
	if byRel["rel-a"].EvidenceID != "ev-9" || byRel["rel-c"].EvidenceID != "" || all[0].ReleaseID != "rel-c" {
		t.Fatalf("after touch: %+v, want rel-a still ev-9, rel-c with no evidence and stalest", all)
	}
	if err := s.StampDiscovered(ctx, "rel-c", t0.Add(10*time.Hour)); err != nil {
		t.Fatalf("stamp c: %v", err)
	}
	if after, _ := s.StaleReleases(ctx, t0.Add(3*time.Hour), 10); len(after) != 2 {
		t.Fatalf("after stamp: %+v, want rel-c no longer stale", after)
	}

	// The limit caps the queue; a cutoff before the stamps returns nothing (a freshly
	// discovered release is not re-asked).
	if one, _ := s.StaleReleases(ctx, t0.Add(3*time.Hour), 1); len(one) != 1 || one[0].ReleaseID != "rel-b" {
		t.Fatalf("limited stale = %+v, want only the stalest", one)
	}
	if none, _ := s.StaleReleases(ctx, t0, 10); len(none) != 0 {
		t.Fatalf("fresh releases returned as stale: %+v", none)
	}
}
