//go:build integration

package queue_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/db"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestPostgresJobStoreGetAttempts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := startEmbeddedPostgres(t, 15436)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := db.RunMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	store := queue.NewPostgresJobStore(pool)
	id, err := store.Create(ctx, "", string(domain.JobTypeIngestSBOM), []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}

	attempts, err := store.GetAttempts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0", attempts)
	}

	attempts, err = store.IncrementAttempts(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}

	if err := store.MarkRunning(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkCompleted(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkFailed(ctx, "00000000-0000-0000-0000-000000000000", "boom"); err == nil {
		t.Fatal("expected missing job error")
	}
	if _, err := store.GetAttempts(ctx, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("expected missing job error")
	}
}

func TestPostgresJobStoreNotFoundErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := startEmbeddedPostgres(t, 15438)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := db.RunMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	store := queue.NewPostgresJobStore(pool)
	missing := "00000000-0000-0000-0000-000000000000"

	if err := store.MarkRunning(ctx, missing); err == nil {
		t.Fatal("expected MarkRunning error")
	}
	if err := store.MarkCompleted(ctx, missing); err == nil {
		t.Fatal("expected MarkCompleted error")
	}
	if _, err := store.IncrementAttempts(ctx, missing); err == nil {
		t.Fatal("expected IncrementAttempts error")
	}
	if _, err := store.CountByStatus(ctx, "pending"); err != nil {
		t.Fatal(err)
	}
}
