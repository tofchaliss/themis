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

	"github.com/themis-project/themis/internal/intelligence/adapters/store"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "intelligence-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15577).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"max_connections": "30"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping intelligence store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15577/themis?sslmode=disable"
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

func newStore(t *testing.T) (*store.Store, *pgxpool.Pool) {
	t.Helper()
	if testDSN == "" {
		t.Skip("no database")
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	st := store.New(pool)
	if err := st.Purge(context.Background()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Purge(context.Background())
		pool.Close()
	})
	return st, pool
}

func rec(id, stance string, vec []float32) store.EmbeddingRecord {
	return store.EmbeddingRecord{
		FindingID:   id,
		FaultlineID: "fl-" + id,
		ReleaseID:   "rel-" + id,
		CVE:         "CVE-2026-" + id,
		Component:   "pkg:golang/example/" + id,
		Stance:      stance,
		Rationale:   "because " + id,
		Model:       "nomic-embed-text",
		Vector:      vec,
		TextHash:    "hash-" + id,
	}
}

// --- tests ---------------------------------------------------------------------------

func TestUpsertAndLoadAllRoundTrip(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	want := rec("001", "not_affected", []float32{0.1, -0.2, 0.3, 0.4})
	if err := st.Upsert(ctx, want); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	all, err := st.LoadAll(ctx)
	if err != nil {
		t.Fatalf("loadall: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("rows: got %d want 1", len(all))
	}
	got := all[0]
	if got.FindingID != want.FindingID || got.FaultlineID != want.FaultlineID || got.ReleaseID != want.ReleaseID ||
		got.CVE != want.CVE || got.Component != want.Component || got.Stance != want.Stance ||
		got.Rationale != want.Rationale || got.Model != want.Model || got.TextHash != want.TextHash {
		t.Fatalf("labels mismatch:\n got %+v\nwant %+v", got, want)
	}
	if len(got.Vector) != len(want.Vector) {
		t.Fatalf("vector length: got %d want %d", len(got.Vector), len(want.Vector))
	}
	for i := range want.Vector {
		if got.Vector[i] != want.Vector[i] {
			t.Errorf("vector[%d]: got %v want %v", i, got.Vector[i], want.Vector[i])
		}
	}
}

func TestUpsertOverwritesByFindingID(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	if err := st.Upsert(ctx, rec("007", "affected", []float32{1, 0, 0})); err != nil {
		t.Fatalf("upsert v1: %v", err)
	}
	// A later PositionRevised for the same Finding re-embeds and overwrites the one row.
	if err := st.Upsert(ctx, rec("007", "not_affected", []float32{0, 1, 0})); err != nil {
		t.Fatalf("upsert v2: %v", err)
	}

	all, err := st.LoadAll(ctx)
	if err != nil {
		t.Fatalf("loadall: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("rows: got %d want 1 (upsert must overwrite, not append)", len(all))
	}
	if all[0].Stance != "not_affected" {
		t.Fatalf("stance: got %q want the revised %q", all[0].Stance, "not_affected")
	}
}

func TestTextHashFoundAndMissing(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	if _, ok, err := st.TextHash(ctx, "absent"); err != nil || ok {
		t.Fatalf("missing: got ok=%v err=%v, want ok=false err=nil", ok, err)
	}
	if err := st.Upsert(ctx, rec("042", "affected", []float32{0.5, 0.5})); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	h, ok, err := st.TextHash(ctx, "042")
	if err != nil || !ok {
		t.Fatalf("present: got ok=%v err=%v, want ok=true err=nil", ok, err)
	}
	if h != "hash-042" {
		t.Fatalf("hash: got %q want %q", h, "hash-042")
	}
}

func TestCountAndLoadAllEmpty(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	n, err := st.Count(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("count: got %d want 0", n)
	}
	all, err := st.LoadAll(ctx)
	if err != nil {
		t.Fatalf("loadall: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("rows: got %d want 0", len(all))
	}

	if err := st.Upsert(ctx, rec("100", "affected", []float32{1})); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if n, _ := st.Count(ctx); n != 1 {
		t.Fatalf("count after upsert: got %d want 1", n)
	}
}

func TestUpsertValidation(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	if err := st.Upsert(ctx, rec("", "affected", []float32{1})); err == nil {
		t.Error("expected error for empty FindingID")
	}
	if err := st.Upsert(ctx, rec("x", "affected", nil)); err == nil {
		t.Error("expected error for empty vector")
	}
}

func TestMigrationsReversible(t *testing.T) {
	if testDSN == "" {
		t.Skip("no database")
	}
	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	defer m.Close()
	if err := m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("down: %v", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("up: %v", err)
	}
	// Tables exist again after the up→down→up cycle.
	st, _ := newStore(t)
	if _, err := st.Count(context.Background()); err != nil {
		t.Fatalf("count after reversible migrate: %v", err)
	}
}
