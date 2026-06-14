//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/store"
)

var (
	sharedPostgresDSN    string
	sharedPostgresStop   func() error
	sharedPostgresFailed bool
)

func isTestListMode() bool {
	for _, arg := range os.Args {
		if arg == "-test.list" || strings.HasPrefix(arg, "-test.list=") {
			return true
		}
	}
	return false
}

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		sharedPostgresDSN = dsn
		os.Exit(m.Run())
	}
	if isTestListMode() {
		os.Exit(m.Run())
	}

	dir, err := os.MkdirTemp("", "themis-store-integration-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").
		Password("themis").
		Database("themis").
		Version(embeddedpostgres.V16).
		Port(15432).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{
			"shared_buffers":  "128kB",
			"max_connections": "10",
		})

	dbInstance := embeddedpostgres.NewDatabase(cfg)
	startErr := make(chan error, 1)
	go func() { startErr <- dbInstance.Start() }()
	select {
	case err := <-startErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "shared postgres unavailable, skipping integration DB tests: %v\n", err)
			sharedPostgresFailed = true
			os.Exit(m.Run())
		}
	case <-time.After(30 * time.Second):
		fmt.Fprintf(os.Stderr, "shared postgres start timed out, skipping integration DB tests\n")
		sharedPostgresFailed = true
		os.Exit(m.Run())
	}
	sharedPostgresDSN = "postgres://themis:themis@localhost:15432/themis?sslmode=disable"
	sharedPostgresStop = dbInstance.Stop
	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := runIntegrationMigrationsUp(sharedPostgresDSN, migrationsPath); err != nil {
		panic(fmt.Errorf("apply shared integration migrations: %w", err))
	}

	code := m.Run()
	_ = dbInstance.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func integrationDatabaseDSN(t *testing.T, port uint32) string {
	t.Helper()
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		return dsn
	}
	if sharedPostgresFailed {
		t.Skip("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres)")
	}
	if sharedPostgresDSN != "" {
		return sharedPostgresDSN
	}
	return startEmbeddedPostgres(t, port)
}

func resetIntegrationDatabase(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DO $$
		DECLARE r RECORD;
		BEGIN
			FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
				EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' RESTART IDENTITY CASCADE';
			END LOOP;
		END $$;
	`)
	if err != nil {
		t.Fatalf("truncate integration database: %v", err)
	}
}

func startEmbeddedPostgres(t *testing.T, port uint32) string {
	t.Helper()

	dir := t.TempDir()
	cfg := embeddedpostgres.DefaultConfig().
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
		})

	var lastErr error
	for attempt := range 5 {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		dbInstance := embeddedpostgres.NewDatabase(cfg)
		if err := dbInstance.Start(); err != nil {
			lastErr = err
			continue
		}
		t.Cleanup(func() {
			_ = dbInstance.Stop()
		})
		return "postgres://themis:themis@localhost:" + strconv.FormatUint(uint64(port), 10) + "/themis?sslmode=disable"
	}
	t.Skipf("embedded postgres unavailable (set THEMIS_TEST_DATABASE_DSN for external Postgres): %v", lastErr)
	return ""
}

func runIntegrationMigrationsUp(dsn, migrationsPath string) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
	}()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	version, dirty, err := m.Version()
	if err != nil {
		return err
	}
	return store.CompareSchemaVersion(version, dirty, store.BinarySchemaVersion)
}

func applyIntegrationMigrations(dsn, migrationsPath string) error {
	if dsn == sharedPostgresDSN && sharedPostgresDSN != "" {
		return nil
	}
	return runIntegrationMigrationsUp(dsn, migrationsPath)
}
