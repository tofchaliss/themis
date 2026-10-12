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
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/event"
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
	if _, err := pool.Exec(context.Background(), "TRUNCATE intake_receipts, evidence_outbox, evidence RESTART IDENTITY CASCADE"); err != nil {
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

	// Same bytes, DIFFERENT release → a loud refusal naming where the content lives,
	// never a silent created=false that leaves rel-2 with no evidence (D3 note,
	// measured live 2026-08-19).
	e3, ev3 := sampleEvidence(t, "ev-3", "rel-2", []byte("raw-A"))
	_, err = s.Save(ctx, e3, []byte("raw-A"), ev3)
	var cfe *app.ContentFiledElsewhereError
	if !errors.As(err, &cfe) {
		t.Fatalf("cross-release duplicate: err = %v, want ContentFiledElsewhereError", err)
	}
	if cfe.ReleaseID != "rel-1" || cfe.EvidenceID != string(r1.ID) {
		t.Errorf("refusal names release %q evidence %q, want rel-1 / %s", cfe.ReleaseID, cfe.EvidenceID, r1.ID)
	}
	if got := count(t, pool, "SELECT count(*) FROM evidence"); got != 1 {
		t.Errorf("evidence rows after refusal = %d, want 1 (nothing stored)", got)
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

	// GetRawDocument returns the stored kind + raw bytes (the read path Knowledge uses for VEX).
	kind, doc, err := s.GetRawDocument(ctx, r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if kind != "sbom" || string(doc) != "raw-get" {
		t.Errorf("raw document = (%q, %q), want (sbom, raw-get)", kind, string(doc))
	}
	if _, _, err := s.GetRawDocument(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetRawDocument(nope) = %v, want ErrNotFound", err)
	}

	list, err := s.ListByRelease(ctx, "rel-42")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != r.ID {
		t.Errorf("list = %+v", list)
	}
	if list[0].ProvenanceSource != "trivy" {
		t.Errorf("list provenance_source = %q, want trivy", list[0].ProvenanceSource)
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
	delivered []event.Envelope
	failFirst bool
	calls     int
}

func (p *fakePublisher) Publish(_ context.Context, env event.Envelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.failFirst && p.calls == 1 {
		return errors.New("publish boom")
	}
	p.delivered = append(p.delivered, env)
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
	for _, table := range []string{"evidence", "evidence_outbox", "intake_receipts"} {
		if _, err := pool.Exec(context.Background(), "SELECT 1 FROM "+table+" LIMIT 0"); err != nil {
			t.Errorf("%s table missing after down/up: %v", table, err)
		}
	}
}

// TestIntakeReceipts_TableShape pins migration 000003's columns, because the receipt
// is a CONTRACT with the operator — the record that someone tried, including the
// attempts that were refused (D9) — and a column quietly renamed or dropped breaks a
// read nobody is testing.
func TestIntakeReceipts_TableShape(t *testing.T) {
	pool := newPool(t)
	rows, err := pool.Query(context.Background(), `
		SELECT column_name, is_nullable FROM information_schema.columns
		WHERE table_name = 'intake_receipts' ORDER BY column_name
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var name, nullable string
		if err := rows.Scan(&name, &nullable); err != nil {
			t.Fatal(err)
		}
		got[name] = nullable
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"intake_id": "NO",
		// Nullable, and that is the decision: a receipt with no asserted key must
		// not collide with every other keyless receipt on the UNIQUE constraint.
		"idempotency_key": "YES",
		"status":          "NO",
		"reason":          "NO",
		"detail":          "NO",
		"evidence_id":     "YES",
		// NOT NULL but defaulted to '': an attempt refused at detection never
		// reached release resolution, and D9 requires it to leave a receipt anyway.
		"release_id":       "NO",
		"detected_kind":    "NO",
		"detected_format":  "NO",
		"findings_total":   "NO",
		"findings_skipped": "NO",
		"components":       "NO",
		"source_digest":    "NO",
		"converted_by":     "NO",
		// What THIS attempt submitted (B5). NOT NULL DEFAULT '': a build id nobody
		// asserted is the fact "none", not an unknown.
		"build_id":   "NO",
		"created_at": "NO",
		"updated_at": "NO",
	}
	for name, nullable := range want {
		if got[name] == "" {
			t.Errorf("column %q is missing", name)
			continue
		}
		if got[name] != nullable {
			t.Errorf("column %q is_nullable = %q, want %q", name, got[name], nullable)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("unexpected column %q — the receipt's columns are the contract", name)
		}
	}
}

// TestIntakeReceipts_IdempotencyKeyBindsOnlyAssertedKeys — D12 needs both halves:
// at most one receipt per asserted key, and NO constraint at all on the keyless ones.
// Postgres allows any number of NULLs in a unique index, which is exactly that.
func TestIntakeReceipts_IdempotencyKeyBindsOnlyAssertedKeys(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	for _, id := range []string{"in-1", "in-2", "in-3"} {
		if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{IntakeID: id, Status: domain.ReceiptAccepted}); err != nil {
			t.Fatalf("keyless receipt %s: %v", id, err)
		}
	}
	if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{IntakeID: "in-4", IdempotencyKey: "k", Status: domain.ReceiptAccepted}); err != nil {
		t.Fatalf("first keyed receipt: %v", err)
	}

	err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{IntakeID: "in-5", IdempotencyKey: "k", Status: domain.ReceiptAccepted})
	if !errors.Is(err, store.ErrIdempotencyKeyTaken) {
		t.Fatalf("second receipt under one key = %v, want ErrIdempotencyKeyTaken — a retry is not a persistence failure", err)
	}
	// The same receipt re-writing itself under its own key is an ADVANCE, not a
	// collision: that is how the overflow worker records what it finished.
	if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{
		IntakeID: "in-4", IdempotencyKey: "k", Status: domain.ReceiptFiled, EvidenceID: "ev-1",
	}); err != nil {
		t.Fatalf("advancing a keyed receipt: %v", err)
	}
	if got := count(t, pool, "SELECT count(*) FROM intake_receipts"); got != 4 {
		t.Errorf("%d receipts, want 4", got)
	}
}

// TestIntakeReceipts_SaveLoadAdvance — the round trip, including the two-field rule
// surviving storage and `updated_at` moving while `created_at` stays put.
func TestIntakeReceipts_SaveLoadAdvance(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	refused := store.IntakeReceipt{
		IntakeID: "in-1", IdempotencyKey: "key-1", Status: domain.ReceiptRejected,
		Reason: domain.ReasonSchemaInvalid, Detail: "findings[2] is not an object",
		ReleaseID: "rel-1", DetectedKind: "vuln-report", DetectedFormat: "cortex-json",
		FindingsTotal: 500, FindingsSkipped: 73, SourceDigest: "abc", ConvertedBy: "cortex@1",
	}
	if err := s.SaveIntakeReceipt(ctx, refused); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadIntakeReceipt(ctx, "in-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Reason != domain.ReasonSchemaInvalid || got.Detail != refused.Detail {
		t.Errorf("reason=%q detail=%q; the pair must stay two columns", got.Reason, got.Detail)
	}
	if got.FindingsTotal != 500 || got.FindingsSkipped != 73 {
		t.Errorf("counts = %d/%d", got.FindingsTotal, got.FindingsSkipped)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps = %v / %v", got.CreatedAt, got.UpdatedAt)
	}

	byKey, err := s.FindIntakeReceiptByIdempotencyKey(ctx, "key-1")
	if err != nil || byKey.IntakeID != "in-1" {
		t.Fatalf("by key = %+v, %v", byKey, err)
	}

	// An empty key matches nothing: a keyless submission asserts no identity, and
	// returning "the receipt with no key" would collapse every keyless attempt.
	if _, err := s.FindIntakeReceiptByIdempotencyKey(ctx, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("empty key = %v, want ErrNotFound", err)
	}
	if _, err := s.LoadIntakeReceipt(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id = %v, want ErrNotFound", err)
	}

	advanced := got
	advanced.Status, advanced.EvidenceID, advanced.Components = domain.ReceiptFiled, "ev-9", 1184
	advanced.Reason, advanced.Detail = "", ""
	if err := s.SaveIntakeReceipt(ctx, advanced); err != nil {
		t.Fatal(err)
	}
	after, err := s.LoadIntakeReceipt(ctx, "in-1")
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != domain.ReceiptFiled || after.EvidenceID != "ev-9" || after.Components != 1184 {
		t.Errorf("advanced receipt = %+v", after)
	}
	if !after.CreatedAt.Equal(got.CreatedAt) {
		t.Errorf("created_at moved: %v -> %v", got.CreatedAt, after.CreatedAt)
	}
	if after.UpdatedAt.Before(got.UpdatedAt) {
		t.Errorf("updated_at went backwards: %v -> %v", got.UpdatedAt, after.UpdatedAt)
	}
}

// TestIntakeReceipts_PurgeExpired — the TTL sweep. Receipts are operational records,
// not evidence, so deleting them removes no document.
func TestIntakeReceipts_PurgeExpired(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	for _, id := range []string{"old", "fresh"} {
		if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{IntakeID: id, Status: domain.ReceiptFiled, EvidenceID: "ev-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	backdate(t, pool, "old", 40*24*time.Hour)

	n, err := s.PurgeExpiredReceipts(ctx, time.Now().UTC().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("purged %d, want 1", n)
	}
	if _, err := s.LoadIntakeReceipt(ctx, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the expired receipt survived: %v", err)
	}
	if _, err := s.LoadIntakeReceipt(ctx, "fresh"); err != nil {
		t.Errorf("a receipt inside the TTL was deleted: %v", err)
	}
}

// TestIntakeReceipts_FailStaleNonTerminal is the startup recovery: a receipt stuck
// non-terminal after a crash would have a client polling a goroutine that no longer
// exists. The terminals are left exactly as they are — rewriting a finished record is
// what the domain's immutability rule forbids, and the sweep must not do it either.
func TestIntakeReceipts_FailStaleNonTerminal(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	seed := []struct {
		id     string
		status domain.ReceiptStatus
		stale  bool
	}{
		{"stale-accepted", domain.ReceiptAccepted, true},
		{"stale-converting", domain.ReceiptConverting, true},
		{"stale-filed", domain.ReceiptFiled, true},
		{"stale-rejected", domain.ReceiptRejected, true},
		{"fresh-accepted", domain.ReceiptAccepted, false},
	}
	for _, s0 := range seed {
		rec := store.IntakeReceipt{IntakeID: s0.id, Status: s0.status, Detail: "original"}
		if s0.status == domain.ReceiptFiled {
			rec.EvidenceID = "ev-" + s0.id
		}
		if s0.status == domain.ReceiptRejected {
			rec.Reason = domain.ReasonEmptyReport
		}
		if err := s.SaveIntakeReceipt(ctx, rec); err != nil {
			t.Fatal(err)
		}
		if s0.stale {
			backdate(t, pool, s0.id, time.Hour)
		}
	}

	const detail = "interrupted by restart; resubmit"
	n, err := s.FailStaleNonTerminalReceipts(ctx, time.Now().UTC().Add(-time.Minute), detail)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("recovered %d, want the 2 stale non-terminal receipts", n)
	}
	for _, id := range []string{"stale-accepted", "stale-converting"} {
		got, err := s.LoadIntakeReceipt(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Status != domain.ReceiptFailed || got.Detail != detail {
			t.Errorf("%s = %q / %q, want failed naming the action", id, got.Status, got.Detail)
		}
		if got.Reason != "" {
			t.Errorf("%s carries reason %q; a failure is a statement about Themis and names none", id, got.Reason)
		}
	}
	for _, id := range []string{"stale-filed", "stale-rejected", "fresh-accepted"} {
		got, err := s.LoadIntakeReceipt(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.Detail != "original" {
			t.Errorf("%s was rewritten: detail = %q", id, got.Detail)
		}
	}
}

// TestHasInventory_ReleaseScopedAndSBOMOnly — D6's precondition, and the two things
// that make it safe: another release's inventory can never satisfy it, and a scanner
// report is not an inventory.
func TestHasInventory_ReleaseScopedAndSBOMOnly(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	if has, err := s.HasInventory(ctx, "rel-1"); err != nil || has {
		t.Fatalf("empty estate: has=%v err=%v", has, err)
	}

	e, ev := sampleEvidence(t, "ev-sbom", "rel-1", []byte("sbom-A"))
	if _, err := s.Save(ctx, e, []byte("sbom-A"), ev); err != nil {
		t.Fatal(err)
	}
	if has, err := s.HasInventory(ctx, "rel-1"); err != nil || !has {
		t.Errorf("after the SBOM: has=%v err=%v", has, err)
	}
	if has, err := s.HasInventory(ctx, "rel-2"); err != nil || has {
		t.Errorf("rel-2 = %v; another release's inventory must never satisfy the precondition", has)
	}

	report, reportEv := sampleReport(t, "ev-report", "rel-3", []byte(`{"findings":[]}`))
	if _, err := s.Save(ctx, report, []byte(`{"findings":[]}`), reportEv); err != nil {
		t.Fatal(err)
	}
	if has, err := s.HasInventory(ctx, "rel-3"); err != nil || has {
		t.Errorf("rel-3 = %v; a scanner report is not an SBOM-derived inventory", has)
	}
}

// backdate ages a receipt so the sweeps have something to find without the test
// sleeping.
func backdate(t *testing.T, pool *pgxpool.Pool, intakeID string, by time.Duration) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE intake_receipts SET created_at = created_at - $1::interval WHERE intake_id = $2`,
		by.String(), intakeID); err != nil {
		t.Fatalf("backdate %s: %v", intakeID, err)
	}
}

// TestBuildIDPersistsAndReadsBack — the build id reaches both of 000004's columns and
// comes back out of both. They are separate facts and may differ: the evidence row
// records what was FILED, the receipt records what THAT ATTEMPT submitted (B5).
func TestBuildIDPersistsAndReadsBack(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	const filedBuild = "Jenkins/OAMP-core/1917"
	raw := []byte("sbom-with-a-build-id")
	e, ev := buildEvidence(t, "ev-build", "rel-build", raw, filedBuild)
	if _, err := s.Save(ctx, e, raw, ev); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := s.GetByID(ctx, "ev-build")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Provenance().BuildID != filedBuild {
		t.Errorf("filed BuildID = %q, want %q", got.Provenance().BuildID, filedBuild)
	}
	if got.Provenance().Source != "trivy" {
		t.Errorf("the new column disturbed its neighbours: %+v", got.Provenance())
	}

	const retryBuild = "Jenkins/OAMP-core/1918"
	if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{
		IntakeID: "in-build", Status: domain.ReceiptFiled, EvidenceID: "ev-build",
		ReleaseID: "rel-build", BuildID: retryBuild,
	}); err != nil {
		t.Fatalf("receipt save: %v", err)
	}
	rec, err := s.LoadIntakeReceipt(ctx, "in-build")
	if err != nil {
		t.Fatalf("receipt load: %v", err)
	}
	if rec.BuildID != retryBuild {
		t.Errorf("receipt BuildID = %q, want %q", rec.BuildID, retryBuild)
	}

	// A receipt with no asserted build id reads back as the empty string, not as a
	// scan failure: NOT NULL DEFAULT '' is what makes "none" a fact (B5).
	if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{
		IntakeID: "in-none", Status: domain.ReceiptAccepted,
	}); err != nil {
		t.Fatalf("receipt with no build id: %v", err)
	}
	none, err := s.LoadIntakeReceipt(ctx, "in-none")
	if err != nil || none.BuildID != "" {
		t.Errorf("absent build id = %q (err %v), want empty", none.BuildID, err)
	}
}

// TestBuildIDMigrationReversible — 000004 up → down → up with rows in the tables.
// Only the two columns move: every document and every receipt is still there
// afterwards with the rest of its provenance intact, because the down migration
// touches no data and the re-up defaults rather than rewrites.
func TestBuildIDMigrationReversible(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := store.New(pool)

	raw := []byte("sbom-across-a-migration")
	e, ev := buildEvidence(t, "ev-mig", "rel-mig", raw, "build-before-down")
	if _, err := s.Save(ctx, e, raw, ev); err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	if err := s.SaveIntakeReceipt(ctx, store.IntakeReceipt{
		IntakeID: "in-mig", Status: domain.ReceiptFiled, EvidenceID: "ev-mig",
		ReleaseID: "rel-mig", SourceDigest: "abc", BuildID: "build-before-down",
	}); err != nil {
		t.Fatalf("seed receipt: %v", err)
	}

	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	// The re-up is also the repair: a failure part-way through must not leave the
	// shared database a version behind for every later test. It closes the migrator
	// too, rather than a `defer` doing it — a deferred close runs BEFORE the
	// cleanups, which would hand the repair a closed migrator.
	t.Cleanup(func() {
		upErr := m.Up()
		m.Close()
		if upErr != nil && !errors.Is(upErr, migrate.ErrNoChange) {
			t.Fatalf("restore: %v", upErr)
		}
	})

	if err := m.Steps(-1); err != nil {
		t.Fatalf("down one step: %v", err)
	}
	for table, column := range map[string]string{"evidence": "provenance_build_id", "intake_receipts": "build_id"} {
		if hasColumn(t, table, column) {
			t.Errorf("%s.%s survived the down migration", table, column)
		}
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("up again: %v", err)
	}

	after, err := pgxpool.New(ctx, testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer after.Close()
	if got := count(t, after, "SELECT count(*) FROM evidence"); got != 1 {
		t.Errorf("evidence rows after up/down/up = %d, want 1", got)
	}
	if got := count(t, after, "SELECT count(*) FROM intake_receipts"); got != 1 {
		t.Errorf("receipt rows after up/down/up = %d, want 1", got)
	}

	reread, err := store.New(after).GetByID(ctx, "ev-mig")
	if err != nil {
		t.Fatalf("get after up/down/up: %v", err)
	}
	if reread.Provenance().Source != "trivy" || reread.Subject().ReleaseID != "rel-mig" {
		t.Errorf("the surviving row lost something: %+v / %+v", reread.Provenance(), reread.Subject())
	}
	// The dropped column's values went with the column — the re-up DEFAULTS them, it
	// does not resurrect them. Asserted rather than left to be discovered: what 000004
	// guarantees is that the ROW survives a reversal, not that a dropped value does.
	if reread.Provenance().BuildID != "" {
		t.Errorf("re-added column = %q, want the '' default", reread.Provenance().BuildID)
	}
	rec, err := store.New(after).LoadIntakeReceipt(ctx, "in-mig")
	if err != nil {
		t.Fatalf("receipt after up/down/up: %v", err)
	}
	if rec.SourceDigest != "abc" || rec.BuildID != "" {
		t.Errorf("receipt after up/down/up = %+v", rec)
	}
}

func hasColumn(t *testing.T, table, column string) bool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	var ok bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS(SELECT 1 FROM information_schema.columns
			WHERE table_name = $1 AND column_name = $2)
	`, table, column).Scan(&ok); err != nil {
		t.Fatalf("column probe %s.%s: %v", table, column, err)
	}
	return ok
}

func buildEvidence(t *testing.T, id, releaseID string, raw []byte, buildID string) (domain.Evidence, domain.EvidenceRegistered) {
	t.Helper()
	purl, err := value.NewPURL("pkg:deb/debian/openssl@3.0.11")
	if err != nil {
		t.Fatalf("purl: %v", err)
	}
	inv := domain.NewInventory([]domain.Component{{PURL: purl, Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}}, nil)
	e, err := domain.NewEvidence(domain.EvidenceID(id), domain.KindSBOM, value.NewContentFingerprint(raw),
		domain.SubjectRef{ReleaseID: releaseID},
		domain.Provenance{Source: "trivy", BuildID: buildID},
		domain.TrustAccepted, inv, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	return e, domain.NewEvidenceRegistered(e, time.Unix(1_700_000_001, 0))
}

func sampleReport(t *testing.T, id, releaseID string, raw []byte) (domain.Evidence, domain.EvidenceRegistered) {
	t.Helper()
	e, err := domain.NewEvidence(domain.EvidenceID(id), domain.KindScannerReport, value.NewContentFingerprint(raw),
		domain.SubjectRef{ReleaseID: releaseID}, domain.Provenance{Source: "cortex"}, domain.TrustAccepted,
		domain.NewInventory(nil, nil), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("report evidence: %v", err)
	}
	return e, domain.NewEvidenceRegistered(e, time.Unix(1_700_000_001, 0))
}
