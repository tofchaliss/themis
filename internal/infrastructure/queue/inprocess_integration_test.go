//go:build integration

package queue_test

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/db"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestInProcessQueueConcurrentPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := startEmbeddedPostgres(t, 15434)
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
	var processed int64
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  8,
		MaxRetry:  3,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			atomic.AddInt64(&processed, 1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = q.Stop(stopCtx)
	})

	const total = 100
	var wg sync.WaitGroup
	wg.Add(total)
	for i := 0; i < total; i++ {
		go func() {
			defer wg.Done()
			if _, err := q.Enqueue(ctx, domain.Job{
				Type:    domain.JobTypeIngestSBOM,
				Payload: []byte(`{"batch":"concurrent"}`),
			}); err != nil {
				t.Errorf("Enqueue() error = %v", err)
			}
		}()
	}
	wg.Wait()

	waitForPostgresStatusCount(t, store, string(domain.JobStatusCompleted), total)
	if got := atomic.LoadInt64(&processed); got != total {
		t.Fatalf("processed = %d, want %d", got, total)
	}

	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM ingestion_jobs`).Scan(&rowCount); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if rowCount != total {
		t.Fatalf("row count = %d, want %d", rowCount, total)
	}
}

func TestInProcessQueueRetryCountsPersisted(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := startEmbeddedPostgres(t, 15435)
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
	q, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  1,
		MaxRetry:  3,
		BaseDelay: time.Millisecond,
		Store:     store,
		Handler: func(_ context.Context, _ domain.Job) error {
			return errors.New("always fails")
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := q.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = q.Stop(stopCtx)
	})

	if _, err := q.Enqueue(ctx, domain.Job{Type: domain.JobTypeIngestSBOM}); err != nil {
		t.Fatal(err)
	}

	waitForPostgresStatusCount(t, store, string(domain.JobStatusFailed), 1)

	var attempts int
	if err := pool.QueryRow(ctx, `SELECT attempts FROM ingestion_jobs LIMIT 1`).Scan(&attempts); err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func startEmbeddedPostgres(t *testing.T, port uint32) string {
	t.Helper()

	dir := t.TempDir()
	dbInstance := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		}))

	if err := dbInstance.Start(); err != nil {
		t.Skipf("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres): %v", err)
	}
	t.Cleanup(func() {
		_ = dbInstance.Stop()
	})

	return "postgres://themis:themis@localhost:" + strconv.FormatUint(uint64(port), 10) + "/themis?sslmode=disable"
}

func waitForPostgresStatusCount(t *testing.T, store *queue.PostgresJobStore, status string, want int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		count, err := store.CountByStatus(context.Background(), status)
		if err != nil {
			t.Fatalf("CountByStatus() error = %v", err)
		}
		if count == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	count, _ := store.CountByStatus(context.Background(), status)
	t.Fatalf("status %q count = %d, want %d", status, count, want)
}
