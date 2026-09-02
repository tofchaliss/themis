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

	"github.com/themis-project/themis/internal/kernel/event"
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
	if _, err := pool.Exec(context.Background(), "TRUNCATE processed_events, knowledge_watch_state, faultline_matches, knowledge_outbox, faultline_proposals, faultlines, feed_health RESTART IDENTITY CASCADE"); err != nil {
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

// vulnFactsFixed builds facts whose fix version carries NO package — the pre-attribution shape a
// CPE-keyed source (NVD) still legitimately produces.
func vulnFactsFixed(t *testing.T, source string, fixed ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, Fixes: domain.UnattributedFixes(fixed)})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

// vulnFactsFixedFor builds facts whose fix version IS attributed to a package.
func vulnFactsFixedFor(t *testing.T, source, pkg string, fixed ...string) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
	fixes := make([]domain.FixedVersion, 0, len(fixed))
	for _, f := range fixed {
		fixes = append(fixes, domain.FixedVersion{Package: pkg, Version: f})
	}
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, Fixes: fixes})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

type seqIDs struct{ n int64 }

func (s *seqIDs) NewID() string { return fmt.Sprintf("fl-%d", atomic.AddInt64(&s.n, 1)) }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now().UTC() }

// TestKnownCVEs proves the relevance-bound query returns exactly the CVEs that have a card.
func TestKnownCVEs(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	svc := service(pool)
	ctx := context.Background()

	if set, err := st.KnownCVEs(ctx); err != nil || len(set) != 0 {
		t.Fatalf("empty store: got (%v, %v), want (∅, nil)", set, err)
	}
	for _, id := range []string{"CVE-2024-10", "CVE-2024-11"} {
		if _, _, err := svc.FoldProposal(ctx, cveID(t, id), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
			t.Fatalf("fold %s: %v", id, err)
		}
	}
	set, err := st.KnownCVEs(ctx)
	if err != nil {
		t.Fatalf("KnownCVEs: %v", err)
	}
	if len(set) != 2 {
		t.Fatalf("got %d CVEs, want 2: %v", len(set), set)
	}
	for _, id := range []string{"CVE-2024-10", "CVE-2024-11"} {
		if _, ok := set[id]; !ok {
			t.Errorf("known set missing %s", id)
		}
	}
}

func service(pool *pgxpool.Pool) *app.FaultlineService {
	return app.NewFaultlineService(store.New(pool), &seqIDs{}, realClock{}, domain.NewPrecedence("redhat", "nvd", "osv"), domain.NewTrustPolicy(nil))
}

func TestSaveAndReload(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	s := service(pool)
	st := store.New(pool)

	// Fold a proposal → creates the card.
	f, _, err := s.FoldProposal(ctx, cveID(t, "CVE-2024-1"), vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"))
	if err != nil {
		t.Fatal(err)
	}
	id := f.ID()

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
	if _, _, err := s.FoldProposal(ctx, cveID(t, "CVE-2024-2"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	// Duplicate fold → no view change → no new event.
	if _, _, err := s.FoldProposal(ctx, cveID(t, "CVE-2024-2"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox"); n != 2 {
		t.Errorf("outbox notes = %d, want 2 (created + enriched, none on the duplicate)", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type = $1", app.EventFaultlineEnriched); n != 1 {
		t.Errorf("enriched events = %d, want 1", n)
	}
	// The verbatim restatement is NOT persisted (KN-PROPOSAL-BLOAT-1). This asserted 2 before,
	// and that reading produced 28,128 exploit-signal rows across 239 cards holding 221 distinct
	// payloads. Append-only is intact — every DISTINCT value a source reports is still kept in
	// order, and nothing is ever mutated or removed; what is dropped is a restatement carrying no
	// information but a timestamp.
	if n := count(t, pool, "SELECT count(*) FROM faultline_proposals"); n != 1 {
		t.Errorf("proposals persisted = %d, want 1 — a source repeating itself is not an observation", n)
	}
}

func TestOptimisticConcurrency_StaleUpdateRejected(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	prec := domain.NewPrecedence("nvd")

	f, _ := domain.NewFaultline("fl-x", cveID(t, "CVE-2024-3"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, domain.NewTrustPolicy(nil)) // version 1
	if err := st.Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	// A save with a stale expected version is rejected.
	f.FoldProposal(vulnFacts(t, "osv", value.SeverityMedium), prec, domain.NewTrustPolicy(nil)) // version 2
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
			_, _, errs[i] = s.FoldProposal(ctx, c, vulnFacts(t, fmt.Sprintf("src-%d", i), value.SeverityMedium))
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
	// One fold → 2 outbox notes (created + enriched).
	if _, _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-5"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
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
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"), prec, domain.NewTrustPolicy(nil))
	f.FoldProposal(exploitSig(t, "kev", 0.5, true, true), prec, domain.NewTrustPolicy(nil))
	f.FoldProposal(applic(t, "redhat", "openssl", "not_affected"), prec, domain.NewTrustPolicy(nil))
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
	a.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, domain.NewTrustPolicy(nil))
	if err := st.Save(ctx, a, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	b, _ := domain.NewFaultline("fl-b", cveID(t, "CVE-2024-6")) // same CVE, different id
	b.FoldProposal(vulnFacts(t, "osv", value.SeverityLow), prec, domain.NewTrustPolicy(nil))
	if err := st.Save(ctx, b, true, 0, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("duplicate create err = %v, want ErrConcurrent", err)
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	if _, _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-10"), vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
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

	f, _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-11"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	id := f.ID()

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

// The occurrence-verdict lifecycle on one match row (EDR-VERDICT-01 D2/D6): recorded with its
// verdict and stamp; a re-judgement that CHANGES the state updates the row and emits
// ComponentVerdictChanged; one that confirms it advances the stamp silently; the row is never
// duplicated and never deleted.
func TestRecordMatch_VerdictLifecycle(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	f, _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-47"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	m := app.Match{
		ReleaseID: "rel-1", FaultlineID: f.ID(), CVE: "CVE-2024-47",
		Component:  app.InventoryComponent{PURL: "pkg:rpm/rhel/openssl@1.0.2k-10.el8", Version: "1.0.2k-10.el8", Ecosystem: "rpm"},
		Verdict:    domain.OpenVerdict(),
		CardVersion: 1, OccurredAt: time.Now().UTC(),
	}
	if created, err := st.RecordMatch(ctx, m); err != nil || !created {
		t.Fatalf("first match: created=%v err=%v", created, err)
	}
	var state string
	var stamp int64
	row := func() {
		t.Helper()
		if err := pool.QueryRow(ctx,
			"SELECT verdict_state, verdict_card_version FROM faultline_matches WHERE component_purl=$1",
			m.Component.PURL).Scan(&state, &stamp); err != nil {
			t.Fatal(err)
		}
	}
	row()
	if state != "open" || stamp != 1 {
		t.Fatalf("recorded verdict = %s@%d, want open@1", state, stamp)
	}

	// Re-judged against a newer card with the SAME conclusion: stamp advances, no event.
	m.CardVersion = 3
	if created, err := st.RecordMatch(ctx, m); err != nil || created {
		t.Fatalf("stamp refresh: created=%v err=%v, want false/nil", created, err)
	}
	row()
	if state != "open" || stamp != 3 {
		t.Errorf("after confirm = %s@%d, want open@3", state, stamp)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type=$1", app.EventComponentVerdictChanged); n != 0 {
		t.Errorf("verdict events after a confirming re-judgement = %d, want 0", n)
	}

	// A re-judgement that CHANGES the state: row updated in place, ONE change event queued.
	m.CardVersion = 4
	m.Verdict = domain.ClearedVendorFix(domain.VerdictGradeObserved, "vendor fix 1.0.2k-16.el8 present")
	if created, err := st.RecordMatch(ctx, m); err != nil || created {
		t.Fatalf("re-judgement: created=%v err=%v, want false/nil (no new row)", created, err)
	}
	row()
	if state != "cleared_vendor_fix" || stamp != 4 {
		t.Errorf("after clearance = %s@%d, want cleared_vendor_fix@4", state, stamp)
	}
	if n := count(t, pool, "SELECT count(*) FROM faultline_matches"); n != 1 {
		t.Errorf("match rows = %d, want 1 — a re-judgement must never duplicate the occurrence", n)
	}
	if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type=$1", app.EventComponentVerdictChanged); n != 1 {
		t.Errorf("ComponentVerdictChanged events = %d, want exactly 1", n)
	}
}

func TestCVEsNeedingRefresh(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	prec := domain.NewPrecedence("nvd", "osv")
	pol := domain.NewTrustPolicy(nil)
	// Two cards: one already carries an "nvd" Proposal, the other only "osv".
	a, _ := domain.NewFaultline("fl-nvd", cveID(t, "CVE-2024-0001"))
	a.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, pol)
	if err := st.Save(ctx, a, true, 0, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := domain.NewFaultline("fl-osv", cveID(t, "CVE-2024-0002"))
	b.FoldProposal(vulnFacts(t, "osv", value.SeverityMedium), prec, pol)
	if err := st.Save(ctx, b, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	// A staleness window wider than the fixture's observed_at (2023-11-14), so nothing already
	// enriched counts as stale and only never-enriched cards come back.
	const neverStale = 20 * 365 * 24 * time.Hour
	got, err := st.CVEsNeedingRefresh(ctx, "nvd", neverStale, 10)
	if err != nil {
		t.Fatalf("CVEsMissingSource: %v", err)
	}
	if len(got) != 1 || got[0] != "CVE-2024-0002" {
		t.Fatalf("got %v, want only the card with no nvd Proposal", got)
	}
	// A settled estate returns nothing, so a sweep costs one query and no fetches.
	if none, err := st.CVEsNeedingRefresh(ctx, "osv", neverStale, 10); err != nil {
		t.Fatalf("CVEsMissingSource: %v", err)
	} else if len(none) != 1 || none[0] != "CVE-2024-0001" {
		t.Fatalf("got %v, want only the card with no osv Proposal", none)
	}
	// A ZERO staleness window makes everything due — this is the refresh half (NVD-REFRESH-1):
	// an already-enriched card must come back once its facts age out, or the sweep would report
	// an empty queue while carrying stale scores and live cards for withdrawn CVEs.
	if all, err := st.CVEsNeedingRefresh(ctx, "nvd", 0, 10); err != nil || len(all) != 2 {
		t.Fatalf("got %v err=%v, want BOTH cards due when nothing is fresh", all, err)
	}
	// Never-enriched sorts first, so a large estate drains front-to-back.
	if all, _ := st.CVEsNeedingRefresh(ctx, "nvd", 0, 10); all[0] != "CVE-2024-0002" {
		t.Errorf("first due = %q, want the never-enriched card", all[0])
	}
	// A superseded card is excluded: the lifecycle is terminal, so re-fetching it would spend
	// requests to learn nothing and keep a retired card in rotation forever.
	b.Supersede()
	if err := st.Save(ctx, b, false, b.Version()-1, nil); err != nil {
		t.Fatalf("supersede save: %v", err)
	}
	if due, err := st.CVEsNeedingRefresh(ctx, "nvd", 0, 10); err != nil || len(due) != 1 || due[0] != "CVE-2024-0001" {
		t.Fatalf("got %v err=%v, want the superseded card excluded", due, err)
	}

	// A non-positive limit does no work at all rather than fetching everything.
	if zero, err := st.CVEsNeedingRefresh(ctx, "nvd", time.Hour, 0); err != nil || zero != nil {
		t.Fatalf("limit 0 = %v err=%v, want nil", zero, err)
	}
}

func TestAffectedReleasesAndReconcile(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	f, _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2024-12"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	id := f.ID()
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

// CardsNeedingAttribution drives the re-attribution sweep (KN-FIX-2): cards holding fix versions
// with no package, paired with a component detailed enough to ask a feed about again.
func TestCardsNeedingAttribution(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	svc := service(pool)

	// Card A: unattributed fixes + a fully-detailed match → eligible.
	a, _, err := svc.FoldProposal(ctx, cveID(t, "CVE-2024-21"), vulnFactsFixed(t, "nvd", "1.2.3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordMatch(ctx, app.Match{
		ReleaseID: "rel-1", FaultlineID: a.ID(), CVE: "CVE-2024-21", OccurredAt: time.Now().UTC(),
		Component: app.InventoryComponent{
			PURL: "pkg:rpm/rocky/python3-ply@3.9", Name: "python3-ply",
			Version: "3.9", Ecosystem: "rpm", Source: "python-ply",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Card B: fixes ALREADY attributed → nothing to do, must not be returned.
	b, _, err := svc.FoldProposal(ctx, cveID(t, "CVE-2024-22"), vulnFactsFixedFor(t, "osv", "openssl", "3.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordMatch(ctx, app.Match{
		ReleaseID: "rel-1", FaultlineID: b.ID(), CVE: "CVE-2024-22", OccurredAt: time.Now().UTC(),
		Component: app.InventoryComponent{PURL: "pkg:rpm/rocky/openssl@3.0", Name: "openssl", Ecosystem: "rpm"},
	}); err != nil {
		t.Fatal(err)
	}

	// Card C: unattributed, but its match predates migration 000005 and carries a PURL alone.
	// A component we cannot re-query is one we must not guess about, so it is skipped.
	c, _, err := svc.FoldProposal(ctx, cveID(t, "CVE-2024-23"), vulnFactsFixed(t, "nvd", "9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.RecordMatch(ctx, app.Match{
		ReleaseID: "rel-1", FaultlineID: c.ID(), CVE: "CVE-2024-23", OccurredAt: time.Now().UTC(),
		Component: app.InventoryComponent{PURL: "pkg:rpm/rocky/legacy@1.0"}, // no ecosystem
	}); err != nil {
		t.Fatal(err)
	}

	got, err := st.CardsNeedingAttribution(ctx, 10)
	if err != nil {
		t.Fatalf("CardsNeedingAttribution: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("cards = %+v, want exactly the unattributed one with a re-queryable component", got)
	}
	if got[0].CVE != "CVE-2024-21" {
		t.Errorf("cve = %q, want CVE-2024-21", got[0].CVE)
	}
	// The source package is the point: it is the only key that joins python3-ply to python-ply.
	if got[0].Component.Source != "python-ply" || got[0].Component.Ecosystem != "rpm" {
		t.Errorf("component = %+v, want the full detail needed to re-query", got[0].Component)
	}
}

// MatchesForFaultline is what lets a card correct classes stamped before its carrier attribution
// arrived (EDR-CORRELATION-01 D4). It must return the FULL component, not just an id: the class
// is recomputed from the component's package, so a row that lost `source` on the way back would
// silently reclassify a carrier as scope.
func TestMatchesForFaultline(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	f, _, err := service(pool).FoldProposal(ctx, cveID(t, "CVE-2019-10086"), vulnFacts(t, "nvd", value.SeverityHigh))
	if err != nil {
		t.Fatal(err)
	}
	id := f.ID()

	for _, m := range []app.Match{
		{ReleaseID: "rel-1", FaultlineID: id, CVE: "CVE-2019-10086", OccurredAt: time.Now().UTC(),
			Component: app.InventoryComponent{
				PURL: "pkg:rpm/rocky/javapackages-filesystem@5.3.0", Name: "javapackages-filesystem",
				Version: "5.3.0", Ecosystem: "rpm", Source: "javapackages-tools",
			}},
		{ReleaseID: "rel-2", FaultlineID: id, CVE: "CVE-2019-10086", OccurredAt: time.Now().UTC(),
			Component: app.InventoryComponent{
				PURL: "pkg:rpm/rocky/apache-commons-beanutils@1.9.3", Name: "apache-commons-beanutils",
				Version: "1.9.3", Ecosystem: "rpm", Source: "apache-commons-beanutils",
			}},
	} {
		if _, err := st.RecordMatch(ctx, m); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	occ, err := st.MatchesForFaultline(ctx, string(id))
	if err != nil {
		t.Fatalf("MatchesForFaultline: %v", err)
	}
	if len(occ) != 2 {
		t.Fatalf("occurrences = %d, want 2", len(occ))
	}
	// Ordered by release then purl, so a re-announcement is deterministic.
	if occ[0].ReleaseID != "rel-1" || occ[1].ReleaseID != "rel-2" {
		t.Errorf("order = %s,%s, want rel-1,rel-2", occ[0].ReleaseID, occ[1].ReleaseID)
	}
	if occ[0].Component.Source != "javapackages-tools" || occ[0].Component.Name != "javapackages-filesystem" {
		t.Errorf("component round-trip lost detail: %+v", occ[0].Component)
	}
	// A card nobody has matched yields nothing rather than an error.
	empty, err := st.MatchesForFaultline(ctx, "no-such-card")
	if err != nil || len(empty) != 0 {
		t.Errorf("unmatched card: occ=%v err=%v, want empty/nil", empty, err)
	}
}
