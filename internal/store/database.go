package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BinarySchemaVersion is the highest migration version embedded in this binary.
const BinarySchemaVersion uint = 1

// ErrSchemaAhead indicates the database schema is newer than this binary supports.
var ErrSchemaAhead = errors.New("database schema version is ahead of binary version")

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
	if dirty {
		return fmt.Errorf("database schema version %d is dirty", version)
	}
	if version > BinarySchemaVersion {
		return fmt.Errorf("%w: db=%d binary=%d", ErrSchemaAhead, version, BinarySchemaVersion)
	}
	return nil
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

// Ping checks database connectivity.
func Ping(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil {
		return errors.New("nil database pool")
	}
	return pool.Ping(ctx)
}
