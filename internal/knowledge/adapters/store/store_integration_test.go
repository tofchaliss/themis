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

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "knowledge-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15522).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"max_connections": "30"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping knowledge store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15522/themis?sslmode=disable"
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
	if _, err := pool.Exec(context.Background(), "TRUNCATE knowledge_outbox, faultline_proposals, faultlines RESTART IDENTITY CASCADE"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

func count(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func cveID(t *testing.T, s string) value.CVEID {
	t.Helper()
	c, err := value.NewCVEID(s)
	if err != nil {
		t.Fatalf("cve: %v", err)
	}
	return c
}

func vulnFacts(t *testing.T, source string, sev value.Severity, ranges ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0), domain.VulnFacts{Severity: sev, CVSS: c, AffectedRanges: ranges})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

type seqIDs struct{ n int64 }

func (s *seqIDs) NewID() string { return fmt.Sprintf("fl-%d", atomic.AddInt64(&s.n, 1)) }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

func service(pool *pgxpool.Pool) *app.FaultlineService {
	return app.NewFaultlineService(store.New(pool), &seqIDs{}, realClock{}, domain.NewPrecedence("redhat", "nvd", "osv"))
}

func TestSaveAndReload(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := service(pool)
	st := store.New(pool)

	// Fold a proposal → creates the card.
	id, err := s.FoldProposal(ctx, cveID(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"))
	if err != nil {
		t.Fatal(err)
	}

	got, found, err := st.GetByCVE(ctx, "CVE-2024-1")
	if err != nil || !found {
		t.Fatalf("GetByCVE: found=%v err=%v", found, err)
	}
	if got.ID() != id || got.CVE().String() != "CVE-2024-1" || got.Stage() != domain.StageEnriched {
		t.Errorf("card = %+v", got)
	}
	if got.View().Severity != value.SeverityHigh || got.View().CVSS.Score() != 7.5 || len(got.View().AffectedRanges) != 1 {
		t.Errorf("view did not round-trip: %+v", got.View())
	}
	if len(got.Proposals()) != 1 {
		t.Errorf("proposals = %d, want 1", len(got.Proposals()))
	}

	byID, err := st.GetByID(ctx, id)
	if err != nil || byID.CVE().String() != "CVE-2024-1" {
		t.Errorf("GetByID = %+v, err=%v", byID, err)
	}

	if _, found, _ := st.GetByCVE(ctx, "CVE-9999-9"); found {
		t.Error("GetByCVE for unknown CVE should not be found")
	}
	if _, err := st.GetByID(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetByID(nope) = %v, want ErrNotFound", err)
	}
}

func TestViewChangeEmitsOneEvent(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := service(pool)

	// Create → Created + Enriched (2 events).
	if _, err := s.FoldProposal(ctx, cveID(t, "CVE-2024-2"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	// Duplicate fold → no view change → no new event.
	if _, err := s.FoldProposal(ctx, cveID(t, "CVE-2024-2"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox"); n != 2 {
		t.Errorf("outbox notes = %d, want 2 (created + enriched, none on the duplicate)", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type = $1", app.EventFaultlineEnriched); n != 1 {
		t.Errorf("enriched events = %d, want 1", n)
	}
	// Both proposals are recorded (append-only), even though only one changed the view.
	if n := count(t, pool, "SELECT count(*) FROM faultline_proposals"); n != 2 {
		t.Errorf("proposals persisted = %d, want 2", n)
	}
}

func TestOptimisticConcurrency_StaleUpdateRejected(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	prec := domain.NewPrecedence("nvd")

	f, _ := domain.NewFaultline("fl-x", cveID(t, "CVE-2024-3"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec) // version 1
	if err := st.Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	// A save with a stale expected version is rejected.
	f.FoldProposal(vulnFacts(t, "osv", value.SeverityMedium), prec) // version 2
	if err := st.Save(ctx, f, false, 0, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("stale update err = %v, want ErrConcurrent", err)
	}
	// With the correct expected version it succeeds.
	if err := st.Save(ctx, f, false, 1, nil); err != nil {
		t.Fatalf("current update: %v", err)
	}
}

func TestConcurrentEnrichConverges(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := service(pool)
	c := cveID(t, "CVE-2024-4")

	const workers = 8
	var wg sync.WaitGroup
	errs := make([]error, workers)
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = s.FoldProposal(ctx, c, vulnFacts(t, fmt.Sprintf("src-%d", i), value.SeverityMedium))
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
	}
	// Exactly one card, all proposals folded, version reflects every fold — no lost update.
	if n := count(t, pool, "SELECT count(*) FROM faultlines WHERE cve = 'CVE-2024-4'"); n != 1 {
		t.Errorf("faultlines = %d, want 1", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM faultline_proposals"); n != workers {
		t.Errorf("proposals = %d, want %d", n, workers)
	}
	var version int
	if err := pool.QueryRow(ctx, "SELECT version FROM faultlines WHERE cve = 'CVE-2024-4'").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != workers {
		t.Errorf("version = %d, want %d (one bump per fold)", version, workers)
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
	// One fold → 2 outbox notes (created + enriched).
	if _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-5"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}

	pub := &fakePublisher{failFirst: true}
	relay := store.NewRelay(pool, pub, 10)

	// First pass: the first note fails, the second delivers.
	if n, err := relay.DeliverPending(ctx); err != nil || n != 1 {
		t.Fatalf("pass 1: n=%d err=%v, want 1/nil", n, err)
	}
	if got := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE sent_at IS NULL"); got != 1 {
		t.Errorf("unsent after pass 1 = %d, want 1", got)
	}
	// Second pass: the retried note delivers.
	if n, err := relay.DeliverPending(ctx); err != nil || n != 1 {
		t.Fatalf("pass 2: n=%d err=%v, want 1/nil", n, err)
	}
	if got := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE sent_at IS NULL"); got != 0 {
		t.Errorf("unsent after pass 2 = %d, want 0", got)
	}
	if len(pub.delivered) != 2 {
		t.Errorf("delivered %d notes, want 2", len(pub.delivered))
	}
}

func exploitSig(t *testing.T, source string, epss float64, kev, pub bool) domain.Proposal {
	t.Helper()
	p, err := domain.NewExploitSignalProposal(source, time.Unix(1_700_000_000, 0), domain.ExploitSignal{EPSS: epss, KEV: kev, ExploitPublic: pub})
	if err != nil {
		t.Fatalf("exploit proposal: %v", err)
	}
	return p
}

func applic(t *testing.T, source, pkg, status string) domain.Proposal {
	t.Helper()
	p, err := domain.NewApplicabilityProposal(source, time.Unix(1_700_000_000, 0), domain.Applicability{Package: pkg, Status: status})
	if err != nil {
		t.Fatalf("applicability proposal: %v", err)
	}
	return p
}

// TestCodecAllKinds round-trips all three proposal kinds + the full view through the DB.
func TestCodecAllKinds(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	prec := domain.NewPrecedence("nvd")

	f, _ := domain.NewFaultline("fl-codec", cveID(t, "CVE-2024-7"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"), prec)
	f.FoldProposal(exploitSig(t, "kev", 0.5, true, true), prec)
	f.FoldProposal(applic(t, "redhat", "openssl", "not_affected"), prec)
	if err := st.Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	got, found, err := st.GetByCVE(ctx, "CVE-2024-7")
	if err != nil || !found {
		t.Fatalf("reload: err=%v found=%v", err, found)
	}
	if len(got.Proposals()) != 3 {
		t.Fatalf("proposals = %d, want 3", len(got.Proposals()))
	}
	v := got.View()
	if v.EPSS != 0.5 || !v.KEV || !v.ExploitPublic || len(v.Applicabilities) != 1 {
		t.Errorf("view kinds not reconstructed: %+v", v)
	}
	kinds := map[domain.ProposalKind]int{}
	for _, p := range got.Proposals() {
		kinds[p.Kind()]++
	}
	if kinds[domain.KindVulnFacts] != 1 || kinds[domain.KindExploitSignal] != 1 || kinds[domain.KindApplicability] != 1 {
		t.Errorf("proposal kinds did not round-trip: %v", kinds)
	}
}

// TestDuplicateCreateIsConcurrent proves a same-CVE create race maps to ErrConcurrent.
func TestDuplicateCreateIsConcurrent(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	prec := domain.NewPrecedence("nvd")

	a, _ := domain.NewFaultline("fl-a", cveID(t, "CVE-2024-6"))
	a.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec)
	if err := st.Save(ctx, a, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	b, _ := domain.NewFaultline("fl-b", cveID(t, "CVE-2024-6")) // same CVE, different id
	b.FoldProposal(vulnFacts(t, "osv", value.SeverityLow), prec)
	if err := st.Save(ctx, b, true, 0, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("duplicate create err = %v, want ErrConcurrent", err)
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	if _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-10"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	_ = store.NewRelay(pool, &fakePublisher{}, 0) // batch<=0 → default
	if err := store.New(pool).Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n := count(t, pool, "SELECT count(*) FROM faultlines"); n != 0 {
		t.Errorf("faultlines after purge = %d, want 0", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox"); n != 0 {
		t.Errorf("outbox after purge = %d, want 0", n)
	}
}

// TestLoad_MalformedRows exercises the reconstruction error branches by inserting rows
// that bypass the domain.
func TestLoad_MalformedRows(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	// A view whose CVSS score is out of range → unmarshalView error.
	if _, err := pool.Exec(ctx, `INSERT INTO faultlines (id,cve,stage,version,view,created_at,updated_at)
		VALUES ('bad-view','CVE-2024-8','created',1,'{"cvss_score":99}'::jsonb, now(), now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetByID(ctx, "bad-view"); err == nil {
		t.Error("bad view: want reconstruction error")
	}

	// A valid card with a proposal of an unknown kind → unmarshalProposal error.
	if _, err := pool.Exec(ctx, `INSERT INTO faultlines (id,cve,stage,version,view,created_at,updated_at)
		VALUES ('good','CVE-2024-9','created',1,'{"cvss_score":0}'::jsonb, now(), now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO faultline_proposals (faultline_id,seq,source,observed_at,kind,payload)
		VALUES ('good',0,'nvd', now(), 'bogus', '{}'::jsonb)`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetByID(ctx, "good"); err == nil {
		t.Error("bad proposal kind: want reconstruction error")
	}
}

func TestRecordMatch(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	id, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-11"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}

	m := app.Match{
		ReleaseID: "rel-1", FaultlineID: id, CVE: "CVE-2024-11",
		Component: app.InventoryComponent{PURL: "pkg:deb/debian/openssl@3.0"}, OccurredAt: time.Now().UTC(),
	}
	created, err := st.RecordMatch(ctx, m)
	if err != nil || !created {
		t.Fatalf("first match: created=%v err=%v", created, err)
	}

	var stage string
	if err := pool.QueryRow(ctx, "SELECT stage FROM faultlines WHERE id=$1", string(id)).Scan(&stage); err != nil {
		t.Fatal(err)
	}
	if stage != "correlated" {
		t.Errorf("stage after match = %s, want correlated", stage)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type=$1", app.EventComponentMatched); n != 1 {
		t.Errorf("ComponentMatched events = %d, want 1", n)
	}

	// Idempotent: the same occurrence records no new match and emits no new event.
	created2, err := st.RecordMatch(ctx, m)
	if err != nil || created2 {
		t.Errorf("duplicate match: created=%v err=%v, want false/nil", created2, err)
	}
	if n := count(t, pool, "SELECT count(*) FROM faultline_matches"); n != 1 {
		t.Errorf("match rows = %d, want 1", n)
	}
}

func TestWatchState(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	if ts, err := st.LastSuccess(ctx); err != nil || !ts.IsZero() {
		t.Errorf("empty watermark = %v err=%v, want zero time", ts, err)
	}
	want := time.Unix(1_700_000_000, 0).UTC()
	if err := st.SetLastSuccess(ctx, want); err != nil {
		t.Fatal(err)
	}
	if got, err := st.LastSuccess(ctx); err != nil || !got.Equal(want) {
		t.Errorf("watermark = %v err=%v, want %v", got, err, want)
	}
	// A second set upserts the single row.
	want2 := want.Add(time.Hour)
	if err := st.SetLastSuccess(ctx, want2); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.LastSuccess(ctx); !got.Equal(want2) {
		t.Errorf("watermark after update = %v, want %v", got, want2)
	}
}

func TestAffectedReleasesAndReconcile(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	id, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-12"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"rel-b", "rel-a"} { // inserted out of order
		if _, err := st.RecordMatch(ctx, app.Match{
			ReleaseID: rel, FaultlineID: id, CVE: "CVE-2024-12",
			Component: app.InventoryComponent{PURL: "pkg:deb/debian/openssl@3.0"}, OccurredAt: time.Now().UTC(),
		}); err != nil {
			t.Fatal(err)
		}
	}

	rels, err := st.AffectedReleases(ctx, string(id))
	if err != nil || len(rels) != 2 || rels[0] != "rel-a" || rels[1] != "rel-b" {
		t.Errorf("affected releases = %v err=%v, want sorted [rel-a rel-b]", rels, err)
	}
	if empty, _ := st.AffectedReleases(ctx, "no-such-card"); len(empty) != 0 {
		t.Errorf("affected releases for unknown card = %v, want empty", empty)
	}

	// Simulate a crash that left the card un-correlated despite having matches, then
	// reconcile: state-based recovery advances it to Correlated (D11).
	if _, err := pool.Exec(ctx, "UPDATE faultlines SET stage='enriched' WHERE id=$1", string(id)); err != nil {
		t.Fatal(err)
	}
	n, err := st.ReconcileStuckStages(ctx)
	if err != nil || n != 1 {
		t.Errorf("reconcile fixed = %d err=%v, want 1", n, err)
	}
	var stage string
	if err := pool.QueryRow(ctx, "SELECT stage FROM faultlines WHERE id=$1", string(id)).Scan(&stage); err != nil {
		t.Fatal(err)
	}
	if stage != "correlated" {
		t.Errorf("stage after reconcile = %s, want correlated", stage)
	}
	// A second reconcile is a no-op — nothing stuck.
	if n, _ := st.ReconcileStuckStages(ctx); n != 0 {
		t.Errorf("second reconcile fixed = %d, want 0", n)
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
	if _, err := pool.Exec(context.Background(), "SELECT 1 FROM faultlines LIMIT 0"); err != nil {
		t.Fatalf("faultlines table missing after down/up: %v", err)
	}
}
