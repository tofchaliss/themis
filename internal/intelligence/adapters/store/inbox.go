package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
)

// withTx injects an in-flight transaction into the context so a wrapped apply (the population
// consumer's write) joins the inbox unit of work — exec() in tx.go reads it back.
func withTx(ctx context.Context, tx pgx.Tx) context.Context {
	return context.WithValue(ctx, txCtxKey{}, tx)
}

// Handler applies one delivered envelope. The inbound population Consumer satisfies it;
// InboxConsumer decorates it with exactly-once application.
type Handler interface {
	Handle(ctx context.Context, env event.Envelope) error
}

// Preparer is an optional Handler extension for a consumer whose application needs slow external
// I/O (read APIs + the embedding call). Prepare performs that I/O OUTSIDE the inbox transaction
// and returns an apply func that performs ONLY the writes; InboxConsumer runs apply inside the
// claimed transaction. This keeps the write transaction short so it never pins the cluster xmin
// horizon and starves the bus reader's watermark (EDR-EVENTBUS-01 D7) — the embedding call in
// particular can take tens of milliseconds and must not be held under a write lock. A handler
// with no external reads need not implement Preparer (the inbox runs Handle inside the tx, EB-06).
// A nil apply is a no-op that still claims the envelope.
type Preparer interface {
	Prepare(ctx context.Context, env event.Envelope) (apply func(ctx context.Context) error, err error)
}

// InboxConsumer wraps a Handler with the consumer inbox (D5 / EB-06): it claims the envelope id
// in processed_events and runs the write in ONE transaction on the Intelligence DB. A redelivery
// of the same envelope id is a no-op — exactly-once application over an at-least-once transport.
type InboxConsumer struct {
	pool  *pgxpool.Pool
	inner Handler
}

// NewInboxConsumer wraps inner with exactly-once application over pool (the Intelligence DB).
func NewInboxConsumer(pool *pgxpool.Pool, inner Handler) *InboxConsumer {
	return &InboxConsumer{pool: pool, inner: inner}
}

// Handle claims env.ID and applies the write atomically; a duplicate envelope id short-circuits
// to a no-op. When the inner handler is a Preparer, the read + embed phase runs BEFORE the
// transaction opens so only the upsert is held under it (D7 — see Preparer); otherwise the whole
// Handle runs inside the transaction (EB-06).
func (ic *InboxConsumer) Handle(ctx context.Context, env event.Envelope) error {
	var apply func(context.Context) error
	if p, ok := ic.inner.(Preparer); ok {
		// Skip the (potentially slow) reads + embed entirely if this envelope was already
		// applied — a cheap PK probe on a redelivery. The ON CONFLICT claim below stays the
		// authoritative dedup, so a race here only costs redundant reads, never a re-apply.
		applied, err := ic.alreadyApplied(ctx, env.ID)
		if err != nil {
			return err
		}
		if applied {
			return nil // already applied — a no-op (D5); no reads, no embed, no transaction
		}
		if apply, err = p.Prepare(ctx, env); err != nil {
			return err // read/embed-phase failure: nothing claimed, so the event is retried
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
			return err // deferred rollback undoes the claim and any partial write
		}
	} else if err := ic.inner.Handle(txCtx, env); err != nil {
		return err // deferred rollback undoes the claim and any partial write
	}
	return tx.Commit(ctx)
}

// alreadyApplied reports whether env.ID is already recorded in the inbox — a read-only
// optimization before the read phase; the ON CONFLICT claim in Handle is the authoritative guard.
func (ic *InboxConsumer) alreadyApplied(ctx context.Context, envelopeID string) (bool, error) {
	var applied bool
	err := ic.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM processed_events WHERE envelope_id = $1)`, envelopeID).Scan(&applied)
	return applied, err
}
