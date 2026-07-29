//go:build integration

package eventbus_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/eventbus"
	"github.com/themis-project/themis/internal/platform/observability"
)

// rawInsertSQL mirrors the Publisher's INSERT; the reader tests use it to append inside a
// held-open transaction (the Publisher only autocommits) to force the concurrent-append gap.
const rawInsertSQL = `INSERT INTO event_log (envelope_id, source_context, subject, type, occurred_at, correlation_id, schema_ref, payload)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

type recordingHandler struct{ ids []string }

func (h *recordingHandler) Handle(_ context.Context, env event.Envelope) error {
	h.ids = append(h.ids, env.ID)
	return nil
}

// failingHandler errors for its first failUntil calls, then succeeds. failUntil = a large
// number makes it permanently poison.
type failingHandler struct {
	calls     int
	failUntil int
}

func (h *failingHandler) Handle(_ context.Context, _ event.Envelope) error {
	h.calls++
	if h.calls <= h.failUntil {
		return errors.New("handler boom")
	}
	return nil
}

// cancelingHandler cancels the drain context on its first call and returns an error — a
// graceful shutdown mid-retry, which must not be mistaken for a poison halt.
type cancelingHandler struct{ cancel context.CancelFunc }

func (h *cancelingHandler) Handle(_ context.Context, _ event.Envelope) error {
	h.cancel()
	return errors.New("interrupted")
}

// mkEnvelope builds an envelope on an arbitrary stream (source_context) with an arbitrary
// type — used to exercise stream routing and interest filtering.
func mkEnvelope(t *testing.T, id, source, typ string) event.Envelope {
	t.Helper()
	e, err := event.NewEnvelope(id, typ, source, "subj-"+id, typ+".v1", "corr", time.Unix(1_700_000_000, 0).UTC(), nil)
	if err != nil {
		t.Fatalf("envelope %s: %v", id, err)
	}
	return e
}

func publish(t *testing.T, pool *pgxpool.Pool, ids ...string) {
	t.Helper()
	pub := eventbus.NewPublisher(pool)
	for _, id := range ids {
		if err := pub.Publish(context.Background(), envelope(t, id, nil)); err != nil {
			t.Fatalf("publish %s: %v", id, err)
		}
	}
}

func cursorSeq(t *testing.T, pool *pgxpool.Pool, consumer, stream string) int64 {
	t.Helper()
	var seq int64
	err := pool.QueryRow(context.Background(),
		"SELECT last_seq FROM stream_cursor WHERE consumer = $1 AND source_context = $2", consumer, stream).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return -1 // no cursor row yet
	}
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	return seq
}

func TestReader_DrainsInSeqOrderAndAdvancesCursor(t *testing.T) {
	pool := newPool(t)
	publish(t, pool, "e1", "e2", "e3")

	h := &recordingHandler{}
	r := eventbus.NewReader(pool, observability.Nop(),
		eventbus.ReaderConfig{Consumer: "c1", Stream: "evidence", BaseBackoff: time.Millisecond}, h)

	n, err := r.Drain(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if n != 3 || len(h.ids) != 3 || h.ids[0] != "e1" || h.ids[1] != "e2" || h.ids[2] != "e3" {
		t.Fatalf("drain applied %d, ids=%v", n, h.ids)
	}
	if got := cursorSeq(t, pool, "c1", "evidence"); got != 3 {
		t.Errorf("cursor = %d, want 3", got)
	}

	// Cursor is durable: a second drain has nothing new.
	if n, err := r.Drain(context.Background()); err != nil || n != 0 {
		t.Errorf("second drain applied %d err %v, want 0/nil", n, err)
	}
}

// TestReader_GapFree proves the D7 observable contract: a higher seq committed while a lower
// seq is still in-flight is NOT delivered ahead of it. The txid watermark holds both back
// until the earlier transaction settles, then delivers them in seq order.
func TestReader_GapFree(t *testing.T) {
	ctx := context.Background()
	pool := newPool(t)

	// gap-A gets the lower seq inside a transaction we hold open (uncommitted).
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	a := envelope(t, "gap-A", nil)
	if _, err := tx.Exec(ctx, rawInsertSQL, a.ID, a.SourceContext, a.Subject, a.Type, a.OccurredAt, a.CorrelationID, a.SchemaRef, nil); err != nil {
		t.Fatalf("insert gap-A: %v", err)
	}

	// gap-B gets the higher seq and commits first (autocommit via the Publisher).
	publish(t, pool, "gap-B")

	h := &recordingHandler{}
	r := eventbus.NewReader(pool, observability.Nop(),
		eventbus.ReaderConfig{Consumer: "c1", Stream: "evidence", BaseBackoff: time.Millisecond}, h)

	// While gap-A is in-flight, the reader must deliver NOTHING (delivering gap-B would strand
	// gap-A behind the cursor forever).
	if n, err := r.Drain(ctx); err != nil || n != 0 || len(h.ids) != 0 {
		t.Fatalf("drain during in-flight gap: applied %d ids %v err %v, want 0/none/nil", n, h.ids, err)
	}

	// Once gap-A commits, both are delivered in seq order.
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit gap-A: %v", err)
	}
	n, err := r.Drain(ctx)
	if err != nil {
		t.Fatalf("drain after commit: %v", err)
	}
	if n != 2 || len(h.ids) != 2 || h.ids[0] != "gap-A" || h.ids[1] != "gap-B" {
		t.Fatalf("post-commit drain applied %d ids %v, want [gap-A gap-B]", n, h.ids)
	}
}

// TestReader_PoisonHaltsStreamAndAlerts proves the D8 M5 cut: a permanently-failing event is
// retried MaxAttempts times, then halts the stream with a loud alert — never silent-skip.
func TestReader_PoisonHaltsStreamAndAlerts(t *testing.T) {
	pool := newPool(t)
	publish(t, pool, "poison", "after")

	core, logs := observer.New(zapcore.ErrorLevel)
	logger := observability.New(zap.New(core))
	h := &failingHandler{failUntil: 1 << 30} // never succeeds
	r := eventbus.NewReader(pool, logger,
		eventbus.ReaderConfig{Consumer: "c1", Stream: "evidence", MaxAttempts: 3, BaseBackoff: time.Millisecond}, h)

	n, err := r.Drain(context.Background())
	if n != 0 || !errors.Is(err, eventbus.ErrStreamHalted) {
		t.Fatalf("poison drain applied %d err %v, want 0/ErrStreamHalted", n, err)
	}
	if h.calls != 3 {
		t.Errorf("handler called %d times, want MaxAttempts=3", h.calls)
	}
	if !r.Halted() {
		t.Error("reader not halted after poison")
	}
	// Loud alert fired (OTel + console via the shared logger).
	if logs.FilterMessageSnippet("HALTED").Len() == 0 {
		t.Error("expected a loud HALTED alert, got none")
	}
	// The failing event is never skipped: the cursor did not advance.
	if got := cursorSeq(t, pool, "c1", "evidence"); got != -1 {
		t.Errorf("cursor = %d, want no advance", got)
	}
	// A halted stream applies nothing further, without re-invoking the handler.
	if n, err := r.Drain(context.Background()); n != 0 || !errors.Is(err, eventbus.ErrStreamHalted) {
		t.Errorf("post-halt drain applied %d err %v, want 0/ErrStreamHalted", n, err)
	}
	if h.calls != 3 {
		t.Errorf("handler called again after halt (%d)", h.calls)
	}
}

func TestReader_TransientRetryThenSucceeds(t *testing.T) {
	pool := newPool(t)
	publish(t, pool, "flaky")

	h := &failingHandler{failUntil: 1} // fails once, then succeeds
	r := eventbus.NewReader(pool, observability.Nop(),
		eventbus.ReaderConfig{Consumer: "c1", Stream: "evidence", MaxAttempts: 3, BaseBackoff: time.Millisecond}, h)

	n, err := r.Drain(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("drain applied %d err %v, want 1/nil", n, err)
	}
	if h.calls != 2 {
		t.Errorf("handler called %d times, want 2 (one fail + one success)", h.calls)
	}
	if got := cursorSeq(t, pool, "c1", "evidence"); got != 1 {
		t.Errorf("cursor = %d, want 1", got)
	}
	if r.Halted() {
		t.Error("reader halted on a transient (recovered) failure")
	}
}

// TestSubscription_StreamAndInterestFilter proves the D7 binding: a Reader built from a
// Subscription delivers only its stream's events (routing) and, within that stream, only the
// interest set (dispatch) — and the surviving events keep seq order (narrowing interest never
// reorders).
func TestSubscription_StreamAndInterestFilter(t *testing.T) {
	pool := newPool(t)
	pub := eventbus.NewPublisher(pool)
	ctx := context.Background()

	for _, e := range []event.Envelope{
		mkEnvelope(t, "e1", "evidence", "want.a"), // in stream, in interest
		mkEnvelope(t, "x1", "other", "want.a"),    // different stream — never delivered
		mkEnvelope(t, "e2", "evidence", "skip.b"), // in stream, OUT of interest
		mkEnvelope(t, "e3", "evidence", "want.c"), // in stream, in interest
	} {
		if err := pub.Publish(ctx, e); err != nil {
			t.Fatalf("publish %s: %v", e.ID, err)
		}
	}

	sub := eventbus.Subscription{Consumer: "c1", Stream: "evidence", Interest: []string{"want.a", "want.c"}}
	h := &recordingHandler{}
	r := sub.NewReader(pool, observability.Nop(), h)

	n, err := r.Drain(ctx)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	// All three "evidence" rows are consumed (an out-of-interest event is an applied no-op so
	// the cursor advances past it); the "other" stream is untouched.
	if n != 3 {
		t.Errorf("drained %d, want 3 (the evidence stream)", n)
	}
	// Only the interest set reached the handler, in seq order — dropping skip.b did not reorder
	// want.a ahead-of / behind want.c.
	if len(h.ids) != 2 || h.ids[0] != "e1" || h.ids[1] != "e3" {
		t.Errorf("handled %v, want [e1 e3]", h.ids)
	}
	// The consumer never read the other stream: it holds no cursor there.
	if got := cursorSeq(t, pool, "c1", "other"); got != -1 {
		t.Errorf("consumer advanced a cursor on a stream it did not subscribe to: %d", got)
	}
}

// TestReader_PerSubjectOrderPreserved proves D6: for events sharing a Subject, the platform
// preserves their relative order. FaultlineEnriched then FaultlineSuperseded for one Faultline
// are delivered in that order — the single monotonic seq cursor yields per-subject order for
// free (a consumer must never observe the supersession before the enrichment).
func TestReader_PerSubjectOrderPreserved(t *testing.T) {
	pool := newPool(t)
	pub := eventbus.NewPublisher(pool)
	ctx := context.Background()

	enriched, err := event.NewEnvelope("evt-enr", "knowledge.faultline_enriched", "knowledge", "fl-1",
		"knowledge.faultline_enriched.v1", "fl-1", time.Unix(1_700_000_000, 0).UTC(), nil)
	if err != nil {
		t.Fatalf("enriched: %v", err)
	}
	superseded, err := event.NewEnvelope("evt-sup", "knowledge.faultline_superseded", "knowledge", "fl-1",
		"knowledge.faultline_superseded.v1", "fl-1", time.Unix(1_700_000_001, 0).UTC(), nil)
	if err != nil {
		t.Fatalf("superseded: %v", err)
	}
	if err := pub.Publish(ctx, enriched); err != nil {
		t.Fatalf("publish enriched: %v", err)
	}
	if err := pub.Publish(ctx, superseded); err != nil {
		t.Fatalf("publish superseded: %v", err)
	}

	h := &recordingHandler{}
	sub := eventbus.Subscription{Consumer: "governance", Stream: "knowledge",
		Interest: []string{"knowledge.faultline_enriched", "knowledge.faultline_superseded"}}
	if _, err := sub.NewReader(pool, observability.Nop(), h).Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(h.ids) != 2 || h.ids[0] != "evt-enr" || h.ids[1] != "evt-sup" {
		t.Fatalf("per-subject delivery order for fl-1 = %v, want [evt-enr evt-sup]", h.ids)
	}
}

// TestReader_ContextCancelIsNotPoison proves a shutdown mid-retry returns the context error
// and does NOT halt the stream (no false poison).
func TestReader_ContextCancelIsNotPoison(t *testing.T) {
	pool := newPool(t)
	publish(t, pool, "e1")

	ctx, cancel := context.WithCancel(context.Background())
	r := eventbus.NewReader(pool, observability.Nop(),
		eventbus.ReaderConfig{Consumer: "c1", Stream: "evidence", MaxAttempts: 5, BaseBackoff: time.Hour}, &cancelingHandler{cancel: cancel})

	n, err := r.Drain(ctx)
	if n != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("drain applied %d err %v, want 0/context.Canceled", n, err)
	}
	if r.Halted() {
		t.Error("reader halted on a context cancel (should be a clean shutdown)")
	}
}
