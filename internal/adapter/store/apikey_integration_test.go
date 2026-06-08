//go:build integration

package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
)

func TestAPIKeyRepositoryCreateAndRevokeIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15461)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	resetIntegrationDatabase(t, pool)

	repo := store.NewPostgresAPIKeyRepository(pool)
	expiresAt := time.Now().Add(24 * time.Hour)
	record, err := repo.Create(ctx, domain.APIKeyCreateInput{
		Name:      "integration",
		KeyHash:   "$2a$10$abcdefghijklmnopqrstuv",
		Scopes:    []string{domain.ScopeAdmin},
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if record.ID == "" || record.Name != "integration" {
		t.Fatalf("record = %+v", record)
	}

	keys, err := repo.FindActiveKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].ID != record.ID {
		t.Fatalf("active keys = %+v", keys)
	}

	if err := repo.Revoke(ctx, record.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := repo.Revoke(ctx, record.ID); err == nil {
		t.Fatal("expected second revoke to fail")
	}

	keys, err = repo.FindActiveKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected no active keys after revoke, got %+v", keys)
	}
}
