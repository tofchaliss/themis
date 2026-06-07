package db

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
)

func TestConnectUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := Connect(ctx, "postgres://127.0.0.1:1/themis?connect_timeout=1", 1)
	if err == nil {
		t.Fatal("expected connect error for unreachable database")
	}
}

func TestDefaultReadSchemaVersionInvalidMigrationsPath(t *testing.T) {
	_, _, err := defaultReadSchemaVersion("postgres://localhost/themis", "/does/not/exist")
	if err == nil {
		t.Fatal("expected migrator creation error")
	}
}

func TestConnectInvalidDSN(t *testing.T) {
	_, err := Connect(context.Background(), "not-a-dsn", 1)
	if err == nil {
		t.Fatal("expected error for invalid dsn")
	}
}

func TestRunMigrationsInvalidPath(t *testing.T) {
	err := RunMigrations("postgres://localhost/themis", "/does/not/exist")
	if err == nil {
		t.Fatal("expected migration error")
	}
}

func TestVerifySchemaVersionInvalidDSN(t *testing.T) {
	err := VerifySchemaVersion("postgres://invalid:invalid@127.0.0.1:1/nope", "migrations")
	if err == nil {
		t.Fatal("expected schema version error")
	}
}

func TestPingNilPool(t *testing.T) {
	if err := Ping(context.Background(), nil); err == nil {
		t.Fatal("expected nil pool error")
	}
}

func TestVerifySchemaVersionBranches(t *testing.T) {
	orig := readSchemaVersion
	t.Cleanup(func() { readSchemaVersion = orig })

	readSchemaVersion = func(string, string) (uint, bool, error) {
		return 0, false, migrate.ErrNilVersion
	}
	if err := VerifySchemaVersion("dsn", "migrations"); err != nil {
		t.Fatalf("nil version: %v", err)
	}

	readSchemaVersion = func(string, string) (uint, bool, error) {
		return 0, false, errors.New("read failed")
	}
	if err := VerifySchemaVersion("dsn", "migrations"); err == nil {
		t.Fatal("expected read error")
	}

	readSchemaVersion = func(string, string) (uint, bool, error) {
		return 2, true, nil
	}
	if err := VerifySchemaVersion("dsn", "migrations"); err == nil {
		t.Fatal("expected dirty error")
	}

	readSchemaVersion = func(string, string) (uint, bool, error) {
		return BinarySchemaVersion + 1, false, nil
	}
	if err := VerifySchemaVersion("dsn", "migrations"); !errors.Is(err, ErrSchemaAhead) {
		t.Fatalf("expected ErrSchemaAhead, got %v", err)
	}

	readSchemaVersion = func(string, string) (uint, bool, error) {
		return 1, false, nil
	}
	if err := VerifySchemaVersion("dsn", "migrations"); err != nil {
		t.Fatalf("valid version: %v", err)
	}
}

func TestErrSchemaAhead(t *testing.T) {
	if ErrSchemaAhead == nil {
		t.Fatal("expected ErrSchemaAhead")
	}
	if !errors.Is(ErrSchemaAhead, ErrSchemaAhead) {
		t.Fatal("errors.Is failed")
	}
}
