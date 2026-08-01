package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
)

// txCtxKey carries an in-flight transaction through the context so a wrapped apply joins
// the caller's unit of work instead of opening its own. Only this package reads it.
type txCtxKey struct{}

func withTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txCtxKey{}, tx)
}

func txFromCtx(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx)
	return tx, ok
}

// beginOrJoin returns the ambient transaction (own=false) when one rides the context — the
// inbox unit of work — or begins a fresh one (own=true). The caller commits/rolls back only
// a transaction it owns.
func (s *Store) beginOrJoin(ctx context.Context) (pgx.Tx, bool, error) {
	if tx, ok := txFromCtx(ctx); ok {
		return tx, false, nil
	}
	tx, err := s.pool.Begin(ctx)
	return tx, true, err
}

// Handler applies one delivered envelope. The inbound Consumer satisfies it; InboxConsumer
// decorates it with exactly-once application.
type Handler interface {
	Handle(ctx context.Context, env event.Envelope) error
}

// Preparer is an optional Handler extension for consumers whose application needs slow
// external I/O (reads). Prepare performs that I/O OUTSIDE the inbox transaction and returns an
// apply func that performs ONLY the writes; the InboxConsumer runs apply inside the claimed
// transaction. This keeps the write transaction short so it never pins the cluster xmin
// horizon and starves the bus reader's gap-free watermark — the EDR-EVENTBUS-01 D7 property
// that a long-open write transaction in one context would otherwise break cluster-wide (XIDs
// are cluster-global). A handler with no external reads need not implement Preparer — the
// inbox falls back to running Handle inside the transaction (EB-06). A nil apply is a no-op.
type Preparer interface {
	Prepare(ctx context.Context, env event.Envelope) (apply func(ctx context.Context) error, err error)
}

// InboxConsumer wraps a Handler with the consumer inbox (D5 / EB-06): it claims the
// envelope id in processed_events and runs the inner Handle in ONE transaction on this
// context's own database. A redelivery of the same envelope id is a no-op.
//
// Knowledge's correlation apply fans out over an SBOM's components — many Save + RecordMatch
// writes for one EvidenceRegistered — so the event-level claim commits them atomically under
// one dedup key. (Correlation is already idempotent by design; the inbox makes exactly-once
// application uniform and explicit across contexts.)
type InboxConsumer struct {
	pool  *pgxpool.Pool
	inner Handler
}

// NewInboxConsumer wraps inner with exactly-once application over pool (this context's DB).
func NewInboxConsumer(pool *pgxpool.Pool, inner Handler) *InboxConsumer {
	return &InboxConsumer{pool: pool, inner: inner}
}

// Handle claims env.ID and applies the business change atomically; a duplicate envelope id
// short-circuits to a no-op. When the inner handler is a Preparer, the read/discovery phase
// runs BEFORE the transaction opens so only the writes are held under it (D7 — see Preparer);
// otherwise the whole Handle runs inside the transaction (EB-06).
func (ic *InboxConsumer) Handle(ctx context.Context, env event.Envelope) error {
	var apply func(context.Context) error
	if p, ok := ic.inner.(Preparer); ok {
		// Skip the (potentially slow) external reads entirely if this envelope was already
		// applied — a cheap PK probe on a redelivery. The authoritative dedup remains the
		// ON CONFLICT claim below, so a race here only costs redundant reads, never a re-apply.
		applied, err := ic.alreadyApplied(ctx, env.ID)
		if err != nil {
			return err
		}
		if applied {
			return nil // already applied — a no-op (D5); no reads, no transaction
		}
		if apply, err = p.Prepare(ctx, env); err != nil {
			return err // read-phase failure: nothing claimed, so the event is retried
		}
	}

	tx, err := ic.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx,
		`INSERT INTO processed_events (envelope_id) VALUES ($1) ON CONFLICT (envelope_id) DO NOTHING`, env.ID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return tx.Commit(ctx) // already applied — a no-op (D5)
	}

	txCtx := withTx(ctx, tx)
	if apply != nil {
		if err := apply(txCtx); err != nil {
			return err // deferred rollback undoes the claim and any partial writes
		}
	} else if err := ic.inner.Handle(txCtx, env); err != nil {
		return err // deferred rollback undoes the claim and any partial writes
	}
	return tx.Commit(ctx)
}

// alreadyApplied reports whether env.ID is already recorded in the inbox (a committed, prior
// application). It is a read-only optimization used before the read phase; the ON CONFLICT
// claim in Handle is the authoritative exactly-once guard.
func (ic *InboxConsumer) alreadyApplied(ctx context.Context, envelopeID string) (bool, error) {
	var applied bool
	err := ic.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM processed_events WHERE envelope_id = $1)`, envelopeID).Scan(&applied)
	return applied, err
}
