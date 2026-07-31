package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Open builds an Authenticator backed by the shared `auth` database at dsn — the single
// composition helper each context service uses to wire inbound authentication (mirrors the
// per-service openBus pattern). Services only READ the auth store; the schema is created once
// by the authadmin CLI / operator (THEMIS_AUTH_MIGRATE), never migrated per service boot.
// The returned close function releases the pool.
func Open(ctx context.Context, dsn string) (*Authenticator, func(), error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, nil, err
	}
	return &Authenticator{Keys: NewStore(pool)}, pool.Close, nil
}
