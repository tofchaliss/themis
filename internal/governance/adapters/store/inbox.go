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

// InboxConsumer wraps a Handler with the consumer inbox (D5 / EB-06): it claims the
// envelope id in processed_events and runs the inner Handle in ONE transaction on this
// context's own database. A redelivery of the same envelope id is a no-op, and the business
// writes never duplicate — exactly-once application over an at-least-once transport.
//
// The claim is per envelope, so an event that fans out to several aggregate writes (e.g. a
// FaultlineEnriched re-evaluating every affected Finding) applies atomically under one dedup
// key. Only the write path (Store.Save) joins the unit of work; reads run on the pool, which
// is correct because an inbound apply must not read-its-own-writes within a single envelope
// (its fan-out is over independent aggregates).
type InboxConsumer struct {
	pool  *pgxpool.Pool
	inner Handler
}

// NewInboxConsumer wraps inner with exactly-once application over pool (this context's DB).
func NewInboxConsumer(pool *pgxpool.Pool, inner Handler) *InboxConsumer {
	return &InboxConsumer{pool: pool, inner: inner}
}

// Handle claims env.ID and applies the inner Handle atomically; a duplicate envelope id
// short-circuits to a no-op.
func (ic *InboxConsumer) Handle(ctx context.Context, env event.Envelope) error {
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

	if err := ic.inner.Handle(withTx(ctx, tx), env); err != nil {
		return err // deferred rollback undoes the claim and any partial writes
	}
	return tx.Commit(ctx)
}
