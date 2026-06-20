package db

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/themis-project/themis/internal/adapter/store"
)

// BinarySchemaVersion is the highest migration version embedded in this binary.
const BinarySchemaVersion = store.BinarySchemaVersion

// ErrSchemaAhead indicates the database schema is newer than this binary supports.
var ErrSchemaAhead = store.ErrSchemaAhead

// Connect creates a PostgreSQL connection pool.
func Connect(ctx context.Context, dsn string, maxPoolSize int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database dsn: %w", err)
	}
	cfg.MaxConns = maxPoolSize

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

// RunMigrations applies pending SQL migrations from migrationsPath.
func RunMigrations(dsn, migrationsPath string) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}

// VerifySchemaVersion ensures the database schema is not ahead of the binary.
func VerifySchemaVersion(dsn, migrationsPath string) error {
	version, dirty, err := readSchemaVersion(dsn, migrationsPath)
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return nil
		}
		return fmt.Errorf("read schema version: %w", err)
	}
	return store.CompareSchemaVersion(version, dirty, BinarySchemaVersion)
}

var readSchemaVersion = defaultReadSchemaVersion

func defaultReadSchemaVersion(dsn, migrationsPath string) (uint, bool, error) {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return 0, false, fmt.Errorf("create migrator for version check: %w", err)
	}
	defer func() {
		_, _ = m.Close()
	}()

	return m.Version()
}

// VerifySchemaShape asserts the connected database matches the v0.3.0 core-model
// schema shape (all expected tables present, no legacy pre-v0.3.0 tables). It is
// the schema-skew guard (D13): a database that was not re-initialised for the
// core-model restructure fails startup loudly with an actionable message instead
// of running the new binary against an incompatible schema.
func VerifySchemaShape(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("nil database pool")
	}

	rows, err := pool.Query(ctx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public'
		  AND table_type = 'BASE TABLE'`)
	if err != nil {
		return fmt.Errorf("list public tables: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan table name: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate public tables: %w", err)
	}

	return store.VerifySchemaShape(tables)
}

// Ping checks database connectivity.
func Ping(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("nil database pool")
	}
	return pool.Ping(ctx)
}
