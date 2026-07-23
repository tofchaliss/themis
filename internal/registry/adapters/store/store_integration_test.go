//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/domain"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "registry-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15533).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping registry store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15533/themis?sslmode=disable"
	if err := migrateUp(testDSN); err != nil {
		_ = db.Stop()
		panic(err)
	}
	code := m.Run()
	_ = db.Stop()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func migrationsDir() string {
	path, _ := filepath.Abs("migrations")
	return "file://" + path
}

func migrateUp(dsn string) error {
	m, err := migrate.New(migrationsDir(), dsn)
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
	truncate(t, pool)
	t.Cleanup(func() {
		truncate(t, pool)
		pool.Close()
	})
	return pool
}

func truncate(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), "TRUNCATE releases, projects, products RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// seed inserts a Product → Project → Release chain and returns their ids.
func seed(t *testing.T, s *store.Store) (domain.ProductID, domain.ProjectID, domain.ReleaseID) {
	t.Helper()
	ctx := context.Background()
	prod, _ := domain.NewProduct("prod-1", "Themis")
	if err := s.SaveProduct(ctx, prod); err != nil {
		t.Fatalf("save product: %v", err)
	}
	proj, _ := domain.NewProject("proj-1", "prod-1", "api")
	if err := s.SaveProject(ctx, proj); err != nil {
		t.Fatalf("save project: %v", err)
	}
	rel, _ := domain.NewRelease("rel-1", "proj-1", "1.2.3")
	if err := s.SaveRelease(ctx, rel); err != nil {
		t.Fatalf("save release: %v", err)
	}
	return prod.ID(), proj.ID(), rel.ID()
}

func TestRegisterAndLookup(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	_, projID, relID := seed(t, s)

	got, err := s.GetRelease(ctx, relID)
	if err != nil {
		t.Fatalf("get release: %v", err)
	}
	if got.ID() != relID || got.ProjectID() != projID || got.Version() != "1.2.3" {
		t.Errorf("release = %+v", got)
	}

	list, err := s.ListReleases(ctx, projID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID() != relID {
		t.Errorf("list = %+v", list)
	}
}

func TestExists(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	prodID, projID, relID := seed(t, s)

	for _, tc := range []struct {
		name  string
		check func() (bool, error)
		want  bool
	}{
		{"product yes", func() (bool, error) { return s.ProductExists(ctx, string(prodID)) }, true},
		{"product no", func() (bool, error) { return s.ProductExists(ctx, "nope") }, false},
		{"project yes", func() (bool, error) { return s.ProjectExists(ctx, string(projID)) }, true},
		{"project no", func() (bool, error) { return s.ProjectExists(ctx, "nope") }, false},
		{"release yes", func() (bool, error) { return s.ReleaseExists(ctx, string(relID)) }, true},
		{"release no", func() (bool, error) { return s.ReleaseExists(ctx, "nope") }, false},
	} {
		got, err := tc.check()
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestGetRelease_NotFound(t *testing.T) {
	pool := newPool(t)
	s := store.New(pool)
	if _, err := s.GetRelease(context.Background(), "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetRelease(missing) = %v, want ErrNotFound", err)
	}
}

func TestForeignKeysEnforceMembership(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	// Project referencing a non-existent Product → FK violation.
	orphanProj, _ := domain.NewProject("proj-x", "no-such-product", "api")
	if err := s.SaveProject(ctx, orphanProj); err == nil {
		t.Error("SaveProject with unknown product: expected FK error")
	}
	// Release referencing a non-existent Project → FK violation.
	orphanRel, _ := domain.NewRelease("rel-x", "no-such-project", "1.0")
	if err := s.SaveRelease(ctx, orphanRel); err == nil {
		t.Error("SaveRelease with unknown project: expected FK error")
	}
	// Duplicate product id → PK violation.
	prod, _ := domain.NewProduct("dup", "A")
	if err := s.SaveProduct(ctx, prod); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveProduct(ctx, prod); err == nil {
		t.Error("duplicate product: expected PK error")
	}
}

func TestReadPaths_MalformedRow(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	// Insert a release with an empty version directly, bypassing the domain, so the
	// read paths hit their reconstruction (NewRelease) error branch.
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ('p','A')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, product_id, name) VALUES ('j','p','api')`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO releases (id, project_id, version) VALUES ('bad','j','')`); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetRelease(ctx, "bad"); err == nil {
		t.Error("GetRelease with empty version: want reconstruction error")
	}
	if _, err := s.ListReleases(ctx, "j"); err == nil {
		t.Error("ListReleases with empty version: want reconstruction error")
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)
	seed(t, s)

	if err := s.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM products").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("products after purge = %d, want 0", n)
	}
}

func TestMigration_DownUp(t *testing.T) {
	if testDSN == "" {
		t.Skip("no database")
	}
	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("down: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("up: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(context.Background(), "SELECT 1 FROM releases LIMIT 0"); err != nil {
		t.Fatalf("releases table missing after down/up: %v", err)
	}
}
