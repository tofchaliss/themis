//go:build integration

package httpserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"go.uber.org/zap"

	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestBootStartsInProcessWorkerPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dir := t.TempDir()
	port := uint32(15437)
	dbInstance := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		CachePath(filepath.Join(dir, "cache")).
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

	configPath := filepath.Join(dir, "themis.yaml")
	dsn := "postgres://themis:themis@localhost:15437/themis?sslmode=disable"
	configYAML := "server:\n  port: 8089\ndatabase:\n  dsn: \"" + dsn + "\"\n"
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	app, err := Boot(
		context.Background(),
		zap.NewNop(),
		WithConfigPath(configPath),
		WithMigrationsPath(filepath.Join("..", "..", "..", "migrations")),
	)
	if err != nil {
		t.Fatalf("Boot() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = app.Close(ctx)
	})

	if app.Workers == nil {
		t.Fatal("expected worker pool")
	}
}

func TestBootCreateWorkerPoolFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	prev := newInProcessQueue
	newInProcessQueue = func(queue.InProcessConfig) (*queue.InProcessQueue, error) {
		return nil, errors.New("create worker pool failed")
	}
	t.Cleanup(func() { newInProcessQueue = prev })

	dir := t.TempDir()
	port := uint32(15439)
	dbInstance := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(port).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		CachePath(filepath.Join(dir, "cache")).
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

	configPath := filepath.Join(dir, "themis.yaml")
	dsn := "postgres://themis:themis@localhost:15439/themis?sslmode=disable"
	configYAML := "server:\n  port: 8090\ndatabase:\n  dsn: \"" + dsn + "\"\n"
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Boot(
		context.Background(),
		zap.NewNop(),
		WithConfigPath(configPath),
		WithMigrationsPath(filepath.Join("..", "..", "..", "migrations")),
	)
	if err == nil {
		t.Fatal("expected worker pool creation failure")
	}
}
