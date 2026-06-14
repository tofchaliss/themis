//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/store"
)

func TestFeedResilience_StaleFlag(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15472)
	threat := store.NewPostgresThreatSignalStore(pool)
	if _, err := pool.Exec(ctx, `
		INSERT INTO epss_kev_signals (cve_id, epss_score, kev_listed, stale, fetched_at)
		VALUES ('CVE-2024-0001', 0.5, FALSE, TRUE, NOW() - INTERVAL '26 hours')
	`); err != nil {
		t.Fatal(err)
	}
	stale, err := threat.SignalsStale(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !stale {
		t.Fatal("expected stale signals")
	}
	statusRepo := store.NewPostgresSystemStatusRepository(pool)
	status, err := statusRepo.GetSystemStatus(ctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	if status.AsOf.IsZero() {
		t.Fatal("expected as_of timestamp")
	}
	_ = time.Now()
}
