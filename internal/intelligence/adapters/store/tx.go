package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// txCtxKey carries an in-flight transaction through the context so the population consumer's
// inbox unit of work (A4) can make an embedding upsert commit atomically with its
// processed_events claim (exactly-once). Only this package reads it; A4's inbox writes it.
type txCtxKey struct{}

// txFromCtx returns the ambient inbox transaction when one rides the context; absent one,
// writes and reads run directly on the pool.
func txFromCtx(ctx context.Context) (pgx.Tx, bool) {
	tx, ok := ctx.Value(txCtxKey{}).(pgx.Tx)
	return tx, ok
}

// pgxExec is the shared subset of *pgxpool.Pool and pgx.Tx the store uses, so a statement can
// run on the ambient inbox transaction or the pool interchangeably.
type pgxExec interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// exec picks the ambient inbox transaction when one is present, else the pool.
func (s *Store) exec(ctx context.Context) pgxExec {
	if tx, ok := txFromCtx(ctx); ok {
		return tx
	}
	return s.pool
}
