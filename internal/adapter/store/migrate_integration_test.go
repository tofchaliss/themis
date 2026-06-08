//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/adapter/store"
)

func TestMigrationsUpDownAndIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15433)
	migrationsPath := filepath.Join("..", "..", "..", "migrations")

	files, err := store.ListMigrationFiles(migrationsPath)
	if err != nil {
		t.Fatalf("ListMigrationFiles() error = %v", err)
	}
	if err := store.ValidateMigrationSet(files); err != nil {
		t.Fatalf("ValidateMigrationSet() error = %v", err)
	}

	if err := runMigrations(dsn, migrationsPath, int(store.BinarySchemaVersion)); err != nil {
		t.Fatalf("run migrations up: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	tables, err := listPublicTables(ctx, pool)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	if missing := store.MissingTables(tables); len(missing) != 0 {
		t.Fatalf("missing tables after up: %v", missing)
	}

	indexes, err := listPublicIndexes(ctx, pool)
	if err != nil {
		t.Fatalf("list indexes: %v", err)
	}
	if missing := store.MissingIndexes(indexes); len(missing) != 0 {
		t.Fatalf("missing indexes after up: %v", missing)
	}

	version, dirty, err := readMigrationVersion(dsn, migrationsPath)
	if err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if err := store.CompareSchemaVersion(version, dirty, store.BinarySchemaVersion); err != nil {
		t.Fatalf("CompareSchemaVersion() error = %v", err)
	}

	if err := runMigrations(dsn, migrationsPath, -int(store.BinarySchemaVersion)); err != nil {
		t.Fatalf("run migrations down: %v", err)
	}

	tables, err = listPublicTables(ctx, pool)
	if err != nil {
		t.Fatalf("list tables after down: %v", err)
	}
	for _, table := range store.ExpectedTables() {
		for _, existing := range tables {
			if existing == table {
				t.Fatalf("table %q still exists after down", table)
			}
		}
	}

	if err := runMigrations(dsn, migrationsPath, int(store.BinarySchemaVersion)); err != nil {
		t.Fatalf("run migrations up again: %v", err)
	}
	if err := runMigrations(dsn, migrationsPath, 0); err != nil {
		t.Fatalf("run migrations up idempotent: %v", err)
	}

	tables, err = listPublicTables(ctx, pool)
	if err != nil {
		t.Fatalf("list tables after second up: %v", err)
	}
	if missing := store.MissingTables(tables); len(missing) != 0 {
		t.Fatalf("missing tables after second up: %v", missing)
	}
}

func runMigrations(dsn, migrationsPath string, steps int) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	if steps == 0 {
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			return fmt.Errorf("run up: %w", err)
		}
		return nil
	}

	if err := m.Steps(steps); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run steps(%d): %w", steps, err)
	}
	return nil
}

func readMigrationVersion(dsn, migrationsPath string) (uint, bool, error) {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return 0, false, fmt.Errorf("create migrator: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()
	return m.Version()
}

func listPublicTables(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'
		ORDER BY table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tables = append(tables, name)
	}
	return tables, rows.Err()
}

func listPublicIndexes(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	rows, err := pool.Query(ctx, `
		SELECT indexname
		FROM pg_indexes
		WHERE schemaname = 'public'
		ORDER BY indexname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var indexes []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		indexes = append(indexes, name)
	}
	return indexes, rows.Err()
}
