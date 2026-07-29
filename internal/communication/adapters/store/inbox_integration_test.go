//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/adapters/wiring"
	"github.com/themis-project/themis/internal/kernel/event"
)

type noopPublisher struct{}

func (noopPublisher) Publish(context.Context, event.Envelope) error { return nil }

func positionEnv(t *testing.T, id, typ string, version int, stance string) event.Envelope {
	t.Helper()
	raw, err := json.Marshal(struct {
		FindingID   string
		ReleaseID   string
		FaultlineID string
		CVE         string
		Version     int
		Stance      string
	}{"fnd-1", "rel-1", "fl-1", "CVE-2024-1", version, stance})
	if err != nil {
		t.Fatalf("marshal %s: %v", id, err)
	}
	e, err := event.NewEnvelope(id, typ, "governance", "fnd-1", typ+".v1", "fnd-1",
		time.Unix(1_700_000_000, 0).UTC(), raw)
	if err != nil {
		t.Fatalf("envelope %s: %v", id, err)
	}
	return e
}

func publishableState(t *testing.T, pool *pgxpool.Pool, findingID string) (int, bool) {
	t.Helper()
	var version int
	var stale bool
	if err := pool.QueryRow(context.Background(),
		"SELECT version, stale FROM publishable_positions WHERE finding_id = $1", findingID).Scan(&version, &stale); err != nil {
		t.Fatalf("read publishable: %v", err)
	}
	return version, stale
}

// TestInboxRejectsStaleRedelivery proves EB-06/D5 with a deterministic, non-idempotent
// observable: an out-of-date envelope redelivered after a newer one must NOT overwrite the
// newer state. Without the inbox the worklist upsert would revert version 2 → version 1; the
// inbox makes the redelivery a no-op.
func TestInboxRejectsStaleRedelivery(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	comm := wiring.Wire(pool, "http://unused", nil, nil, noopPublisher{})
	inbox := store.NewInboxConsumer(pool, comm.Consumer)

	established := positionEnv(t, "evt-v1", "governance.position_established", 1, "affected")
	revised := positionEnv(t, "evt-v2", "governance.position_revised", 2, "affected")

	if err := inbox.Handle(ctx, established); err != nil {
		t.Fatalf("apply established: %v", err)
	}
	if v, stale := publishableState(t, pool, "fnd-1"); v != 1 || stale {
		t.Fatalf("after established: version=%d stale=%v, want 1/false", v, stale)
	}

	if err := inbox.Handle(ctx, revised); err != nil {
		t.Fatalf("apply revised: %v", err)
	}
	if v, stale := publishableState(t, pool, "fnd-1"); v != 2 || !stale {
		t.Fatalf("after revised: version=%d stale=%v, want 2/true", v, stale)
	}

	// Redeliver the OLD established event: exactly-once application means no-op, so the
	// newer revised state survives.
	if err := inbox.Handle(ctx, established); err != nil {
		t.Fatalf("redeliver established: %v", err)
	}
	if v, stale := publishableState(t, pool, "fnd-1"); v != 2 || !stale {
		t.Errorf("stale redelivery reverted state: version=%d stale=%v, want 2/true", v, stale)
	}
	if got := count(t, pool, "SELECT count(*) FROM processed_events"); got != 2 {
		t.Errorf("processed_events = %d, want 2 (v1 + v2)", got)
	}
}
