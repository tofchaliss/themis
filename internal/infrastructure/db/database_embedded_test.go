//go:build integration

package db

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
)

func TestConnectRunMigrationsAndVerify(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dir := t.TempDir()
	db := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(15438).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		CachePath(filepath.Join(dir, "cache")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		}))

	if err := db.Start(); err != nil {
		t.Skipf("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres): %v", err)
	}
	t.Cleanup(func() {
		_ = db.Stop()
	})

	dsn := "postgres://themis:themis@localhost:15438/themis?sslmode=disable"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := Connect(ctx, dsn, 2)
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	t.Cleanup(pool.Close)

	if err := Ping(ctx, pool); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := RunMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}

	if err := VerifySchemaVersion(dsn, migrationsPath); err != nil {
		t.Fatalf("VerifySchemaVersion() error = %v", err)
	}

	if err := RunMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations second time error = %v", err)
	}
}
