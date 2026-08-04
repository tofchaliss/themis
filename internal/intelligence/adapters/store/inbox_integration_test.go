//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/kernel/event"
)

// preparerInbox is a fake inner that upserts one record — the Preparer path (reads outside the
// tx, write inside).
type preparerInbox struct {
	st       *store.Store
	rec      store.EmbeddingRecord
	prepared int
	prepErr  error
}

func (f *preparerInbox) Handle(ctx context.Context, _ event.Envelope) error {
	return f.st.Upsert(ctx, f.rec)
}

func (f *preparerInbox) Prepare(_ context.Context, _ event.Envelope) (func(context.Context) error, error) {
	f.prepared++
	if f.prepErr != nil {
		return nil, f.prepErr
	}
	return func(txCtx context.Context) error { return f.st.Upsert(txCtx, f.rec) }, nil
}

// plainInbox implements only Handler (no Prepare) — the EB-06 fallback path.
type plainInbox struct {
	st      *store.Store
	rec     store.EmbeddingRecord
	handled int
}

func (f *plainInbox) Handle(ctx context.Context, _ event.Envelope) error {
	f.handled++
	return f.st.Upsert(ctx, f.rec)
}

func processedCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM processed_events`).Scan(&n); err != nil {
		t.Fatalf("count processed_events: %v", err)
	}
	return n
}

func TestInboxExactlyOnce(t *testing.T) {
	st, pool := newStore(t)
	fake := &preparerInbox{st: st, rec: rec("100", "not_affected", []float32{1, 0, 0})}
	ic := store.NewInboxConsumer(pool, fake)
	env := event.Envelope{ID: "e-100", Type: "governance.position_established", Payload: []byte(`{}`)}

	if err := ic.Handle(context.Background(), env); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := ic.Handle(context.Background(), env); err != nil { // redelivery
		t.Fatalf("redelivery: %v", err)
	}

	if n, _ := st.Count(context.Background()); n != 1 {
		t.Fatalf("embeddings: got %d want 1 (exactly-once application)", n)
	}
	if got := processedCount(t, pool); got != 1 {
		t.Fatalf("processed_events: got %d want 1", got)
	}
	if fake.prepared != 1 {
		t.Fatalf("prepare calls: got %d want 1 (a redelivery must skip the read/embed phase)", fake.prepared)
	}
}

func TestInboxPrepareErrorClaimsNothing(t *testing.T) {
	st, pool := newStore(t)
	fake := &preparerInbox{st: st, rec: rec("101", "affected", []float32{1}), prepErr: errors.New("embedder down")}
	ic := store.NewInboxConsumer(pool, fake)
	env := event.Envelope{ID: "e-101", Type: "governance.position_established", Payload: []byte(`{}`)}

	if err := ic.Handle(context.Background(), env); err == nil {
		t.Fatal("expected the prepare error to surface for retry")
	}
	if got := processedCount(t, pool); got != 0 {
		t.Fatalf("nothing must be claimed on a prepare failure: processed_events=%d", got)
	}
	// Recovery: clear the error, redeliver → applies exactly once.
	fake.prepErr = nil
	if err := ic.Handle(context.Background(), env); err != nil {
		t.Fatalf("retry after recovery: %v", err)
	}
	if n, _ := st.Count(context.Background()); n != 1 {
		t.Fatalf("after retry: got %d want 1", n)
	}
}

func TestInboxNonPreparerFallback(t *testing.T) {
	st, pool := newStore(t)
	fake := &plainInbox{st: st, rec: rec("102", "affected", []float32{0, 1})}
	ic := store.NewInboxConsumer(pool, fake)
	env := event.Envelope{ID: "e-102", Type: "governance.position_established", Payload: []byte(`{}`)}

	if err := ic.Handle(context.Background(), env); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := ic.Handle(context.Background(), env); err != nil { // redelivery no-op
		t.Fatalf("redelivery: %v", err)
	}
	if fake.handled != 1 {
		t.Fatalf("inner Handle calls: got %d want 1 (fallback runs once, redelivery is a no-op)", fake.handled)
	}
	if n, _ := st.Count(context.Background()); n != 1 {
		t.Fatalf("embeddings: got %d want 1", n)
	}
}
