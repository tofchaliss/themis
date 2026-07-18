//go:build integration

package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "evidence-store-*")
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
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping evidence store integration tests: %v\n", err)
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
	if _, err := pool.Exec(context.Background(), "TRUNCATE evidence_outbox, evidence RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func sampleEvidence(t *testing.T, id, releaseID string, raw []byte) (domain.Evidence, domain.EvidenceRegistered) {
	t.Helper()
	purl, err := value.NewPURL("pkg:deb/debian/openssl@3.0.11")
	if err != nil {
		t.Fatalf("purl: %v", err)
	}
	inv := domain.NewInventory([]domain.Component{{PURL: purl, Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}}, nil)
	e, err := domain.NewEvidence(domain.EvidenceID(id), domain.KindSBOM, value.NewContentFingerprint(raw),
		domain.SubjectRef{ReleaseID: releaseID}, domain.Provenance{Source: "trivy"}, domain.TrustAccepted, inv, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	return e, domain.NewEvidenceRegistered(e, time.Unix(1_700_000_001, 0))
}

func count(t *testing.T, pool *pgxpool.Pool, query string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func TestSave_Idempotent(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	e1, ev1 := sampleEvidence(t, "ev-1", "rel-1", []byte("raw-A"))
	r1, err := s.Save(ctx, e1, []byte("raw-A"), ev1)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.Created {
		t.Error("first save should be Created")
	}

	// Same bytes, different candidate id → dedup to the first id, no new event.
	e2, ev2 := sampleEvidence(t, "ev-2", "rel-1", []byte("raw-A"))
	r2, err := s.Save(ctx, e2, []byte("raw-A"), ev2)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Created {
		t.Error("duplicate save should not be Created")
	}
	if r2.ID != r1.ID {
		t.Errorf("dedup id = %s, want %s", r2.ID, r1.ID)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence"); got != 1 {
		t.Errorf("evidence rows = %d, want 1", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence_outbox"); got != 1 {
		t.Errorf("outbox rows = %d, want 1 (one event only)", got)
	}
}

func TestSave_ConcurrentDuplicate(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	raw := []byte("raw-concurrent")

	const n = 5
	prepared := make([]domain.Evidence, n)
	events := make([]domain.EvidenceRegistered, n)
	for i := range prepared {
		prepared[i], events[i] = sampleEvidence(t, fmt.Sprintf("ev-%d", i), "rel-1", raw)
	}

	var (
		wg      sync.WaitGroup
		created int32
		ids     [n]domain.EvidenceID
		errs    [n]error
	)
	for i := range prepared {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := store.New(pool).Save(ctx, prepared[i], raw, events[i])
			if err != nil {
				errs[i] = err
				return
			}
			ids[i] = r.ID
			if r.Created {
				atomic.AddInt32(&created, 1)
			}
		}(i)
	}
	wg.Wait()

	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("save %d: %v", i, errs[i])
		}
	}
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Errorf("id[%d]=%s != id[0]=%s", i, ids[i], ids[0])
		}
	}
	if created != 1 {
		t.Errorf("created count = %d, want exactly 1", created)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence"); got != 1 {
		t.Errorf("evidence rows = %d, want 1", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence_outbox"); got != 1 {
		t.Errorf("outbox rows = %d, want 1", got)
	}
}

func TestGetAndList(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	e, ev := sampleEvidence(t, "ev-1", "rel-42", []byte("raw-get"))
	r, err := s.Save(ctx, e, []byte("raw-get"), ev)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.GetByID(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject().ReleaseID != "rel-42" || got.Kind() != domain.KindSBOM {
		t.Errorf("GetByID = %+v", got)
	}
	if !got.Fingerprint().Equal(value.NewContentFingerprint([]byte("raw-get"))) {
		t.Error("fingerprint did not round-trip")
	}

	inv, err := s.GetInventory(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Components()) != 1 {
		t.Errorf("inventory components = %d, want 1", len(inv.Components()))
	}

	list, err := s.ListByRelease(ctx, "rel-42")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != r.ID {
		t.Errorf("list = %+v", list)
	}

	if _, err := s.GetByID(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByID(nope) = %v, want ErrNotFound", err)
	}
	if _, err := s.GetInventory(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetInventory(nope) = %v, want ErrNotFound", err)
	}
}

type fakePublisher struct {
	mu        sync.Mutex
	delivered []store.OutboxNote
	failFirst bool
	calls     int
}

func (p *fakePublisher) Publish(_ context.Context, n store.OutboxNote) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.failFirst && p.calls == 1 {
		return errors.New("publish boom")
	}
	p.delivered = append(p.delivered, n)
	return nil
}

func TestRelay_DeliverAndRetry(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	e, ev := sampleEvidence(t, "ev-1", "rel-1", []byte("raw-relay"))
	if _, err := store.New(pool).Save(ctx, e, []byte("raw-relay"), ev); err != nil {
		t.Fatal(err)
	}

	pub := &fakePublisher{failFirst: true}
	relay := store.NewRelay(pool, pub, 10)

	// First pass: publish fails → 0 delivered; note stays unsent, attempts++.
	if n, err := relay.DeliverPending(ctx); err != nil || n != 0 {
		t.Fatalf("pass 1: n=%d err=%v, want 0/nil", n, err)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence_outbox WHERE sent_at IS NULL"); got != 1 {
		t.Errorf("unsent after fail = %d, want 1", got)
	}
	if got := count(t, pool, "SELECT coalesce(max(attempts),0) FROM evidence_outbox"); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}

	// Second pass: publish succeeds → 1 delivered; note marked sent.
	if n, err := relay.DeliverPending(ctx); err != nil || n != 1 {
		t.Fatalf("pass 2: n=%d err=%v, want 1/nil", n, err)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence_outbox WHERE sent_at IS NULL"); got != 0 {
		t.Errorf("unsent after success = %d, want 0", got)
	}

	// Third pass: nothing left to deliver.
	if n, err := relay.DeliverPending(ctx); err != nil || n != 0 {
		t.Fatalf("pass 3: n=%d err=%v, want 0/nil", n, err)
	}
	if len(pub.delivered) != 1 {
		t.Errorf("publisher received %d notes, want 1", len(pub.delivered))
	}
}

func TestGet_MalformedRow(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	// Insert a row directly with a bad fingerprint and a bad inventory (bypassing
	// the domain), so the read paths hit their reconstruction error branches.
	if _, err := pool.Exec(ctx, `
		INSERT INTO evidence (id, kind, fingerprint, subject_release_id, trust_status, raw_document, canonical_inventory, filed_at)
		VALUES ($1,'sbom',$2,'rel-1','accepted',$3,$4, now())
	`, "bad-1", "NOT-A-HEX", []byte("{}"), `{"components":[{"purl":"not-a-purl"}]}`); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetByID(ctx, "bad-1"); err == nil {
		t.Error("GetByID with bad fingerprint: want error")
	}
	if _, err := s.GetInventory(ctx, "bad-1"); err == nil {
		t.Error("GetInventory with bad inventory: want error")
	}

	// Fix the fingerprint; the bad inventory now trips GetByID's unmarshal branch.
	const validFP = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if _, err := pool.Exec(ctx, `UPDATE evidence SET fingerprint = $1 WHERE id = 'bad-1'`, validFP); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetByID(ctx, "bad-1"); err == nil {
		t.Error("GetByID with bad inventory: want error")
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	e, ev := sampleEvidence(t, "ev-1", "rel-1", []byte("raw-purge"))
	if _, err := s.Save(ctx, e, []byte("raw-purge"), ev); err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence"); got != 0 {
		t.Errorf("evidence rows after purge = %d, want 0", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence_outbox"); got != 0 {
		t.Errorf("outbox rows after purge = %d, want 0", got)
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
	if _, err := pool.Exec(context.Background(), "SELECT 1 FROM evidence LIMIT 0"); err != nil {
		t.Fatalf("evidence table missing after down/up: %v", err)
	}
}
