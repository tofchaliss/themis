//go:build integration

package auth_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/platform/auth"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "auth-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15544).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping auth store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15544/themis?sslmode=disable"
	if err := migrateUp(testDSN); err != nil {
		_ = db.Stop()
		panic(err)
	}
	code := m.Run()
	_ = db.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func migrateUp(dsn string) error {
	path, _ := filepath.Abs("migrations")
	m, err := migrate.New("file://"+path, dsn)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testDSN == "" {
		t.Skip("no database")
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	if _, err := pool.Exec(context.Background(), "TRUNCATE api_keys"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE api_keys")
		pool.Close()
	})
	return pool
}

func TestStoreCreateActiveRevoke(t *testing.T) {
	ctx := context.Background()
	s := auth.NewStore(newPool(t))

	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	if err := s.CreateKey(ctx, auth.APIKey{ID: "k1", Name: "ci", KeyHash: "h1", Scopes: []string{auth.ScopeAdmin}}); err != nil {
		t.Fatalf("create k1: %v", err)
	}
	if err := s.CreateKey(ctx, auth.APIKey{ID: "k2", Name: "reader", KeyHash: "h2", Scopes: []string{auth.ScopeRead}, ExpiresAt: &expiry}); err != nil {
		t.Fatalf("create k2: %v", err)
	}

	keys, err := s.ActiveKeys(ctx)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("active keys = %d, want 2", len(keys))
	}

	byID := map[string]auth.APIKey{}
	for _, k := range keys {
		byID[k.ID] = k
	}
	if byID["k1"].Name != "ci" || len(byID["k1"].Scopes) != 1 || byID["k1"].Scopes[0] != auth.ScopeAdmin {
		t.Errorf("k1 round-trip wrong: %+v", byID["k1"])
	}
	if got := byID["k2"].ExpiresAt; got == nil || !got.Equal(expiry) {
		t.Errorf("k2 expiry round-trip = %v, want %v", got, expiry)
	}

	if err := s.RevokeKey(ctx, "k1"); err != nil {
		t.Fatalf("revoke k1: %v", err)
	}
	keys, err = s.ActiveKeys(ctx)
	if err != nil {
		t.Fatalf("active after revoke: %v", err)
	}
	if len(keys) != 1 || keys[0].ID != "k2" {
		t.Fatalf("after revoke active = %+v, want only k2", keys)
	}
}

func TestStoreRevokeNotFound(t *testing.T) {
	ctx := context.Background()
	s := auth.NewStore(newPool(t))

	if err := s.RevokeKey(ctx, "missing"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("revoke unknown = %v, want ErrNotFound", err)
	}

	if err := s.CreateKey(ctx, auth.APIKey{ID: "k", Name: "n", KeyHash: "h"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.RevokeKey(ctx, "k"); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	if err := s.RevokeKey(ctx, "k"); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("second revoke = %v, want ErrNotFound", err)
	}
}
