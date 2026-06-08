package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type pgPool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type pgQueryPool interface {
	pgPool
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type errRow struct{ err error }

func (r errRow) Scan(_ ...any) error { return r.err }
