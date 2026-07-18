//go:build integration

package store_test

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

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "governance-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15511).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"max_connections": "30"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping governance store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15511/themis?sslmode=disable"
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
	if _, err := pool.Exec(context.Background(),
		`TRUNCATE governance_outbox, finding_positions, finding_proposals, finding_components, findings RESTART IDENTITY CASCADE`); err != nil {
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

var (
	human = domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
	epoch = time.Unix(1_700_000_000, 0).UTC()
)

func newFinding(t *testing.T, id, rel, fl, cve string) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding(domain.FindingID(id), rel, fl, cve)
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// --- tests ---------------------------------------------------------------------------

func TestSaveAndLoadRoundTrip(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	f := newFinding(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:apk/openssl@3", Name: "openssl", Version: "3", Ecosystem: "Alpine"}); err != nil {
		t.Fatal(err)
	}
	notes := []app.OutboxNote{{EventType: app.EventFindingOpened, Event: domain.NewFindingOpened(f, epoch), OccurredAt: epoch}}
	if err := st.Save(ctx, f, true, 0, notes); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := st.GetByID(ctx, "fnd-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ReleaseID() != "rel-1" || got.FaultlineID() != "fl-1" || got.CVE() != "CVE-2024-1" || got.Stage() != domain.StageIdentified {
		t.Errorf("finding = %+v", got)
	}
	if len(got.Components()) != 1 || got.Components()[0].PURL != "pkg:apk/openssl@3" {
		t.Errorf("components = %+v", got.Components())
	}

	// GetByKey resolves the same aggregate.
	byKey, found, err := st.GetByKey(ctx, "rel-1", "fl-1")
	if err != nil || !found || byKey.ID() != "fnd-1" {
		t.Errorf("by key: found=%v id=%q err=%v", found, byKey.ID(), err)
	}
	// Unknown key / id.
	if _, found, _ := st.GetByKey(ctx, "rel-x", "fl-x"); found {
		t.Error("unknown key should be not found")
	}
	if _, err := st.GetByID(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id err = %v, want ErrNotFound", err)
	}
	if got := count(t, pool, `SELECT count(*) FROM governance_outbox`); got != 1 {
		t.Errorf("outbox rows = %d, want 1", got)
	}
}

func TestDecisionRoundTrip(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	f := newFinding(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err := st.Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	// Raise + accept, then persist the mutated aggregate.
	f, _, _ = load(t, st, "fnd-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "confirmed exploitable", epoch)
	if err := f.RaiseProposal(p); err != nil {
		t.Fatal(err)
	}
	pos, err := f.AcceptProposal("p1", human, epoch)
	if err != nil {
		t.Fatal(err)
	}
	notes := []app.OutboxNote{
		{EventType: app.EventProposalAccepted, Event: domain.NewProposalAccepted(f, "p1", pos, epoch), OccurredAt: epoch},
	}
	if err := st.Save(ctx, f, false, 0, notes); err != nil {
		t.Fatalf("save decision: %v", err)
	}

	got, _, _ := load(t, st, "fnd-1")
	if got.Stage() != domain.StagePositionEstablished {
		t.Errorf("stage = %q", got.Stage())
	}
	cur, ok := got.CurrentPosition()
	if !ok || cur.Version() != 1 || cur.Stance() != domain.StanceAffected || cur.Actor() != human {
		t.Errorf("current position = %+v ok=%v", cur, ok)
	}
	if cur.Inputs().AcceptedProposalID != "p1" || cur.Inputs().FaultlineRef != "fl-1" {
		t.Errorf("inputs = %+v", cur.Inputs())
	}
	if ps := got.Proposals(); len(ps) != 1 || ps[0].Status() != domain.StatusAccepted || ps[0].DecidedBy() != human {
		t.Errorf("proposal = %+v", got.Proposals())
	}
	// The materialized current-position columns are set.
	if got := count(t, pool, `SELECT count(*) FROM findings WHERE current_stance = 'affected' AND current_position_version = 1`); got != 1 {
		t.Errorf("materialized current position not set (%d)", got)
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	f := newFinding(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	if err := st.Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	// Two loads at version 0; each resolves and saves — the second must lose.
	a, _, _ := load(t, st, "fnd-1")
	b, _, _ := load(t, st, "fnd-1")
	_ = a.Resolve()
	_ = b.Archive()
	if err := st.Save(ctx, a, false, 0, nil); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if err := st.Save(ctx, b, false, 0, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("second save err = %v, want ErrConcurrent", err)
	}
}

func TestConcurrentCreateConverges(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	// Two different Finding ids for the same (Release, Faultline) — the unique business
	// key makes the second create collapse to ErrConcurrent so the app retries as update.
	a := newFinding(t, "fnd-a", "rel-1", "fl-1", "CVE-1")
	b := newFinding(t, "fnd-b", "rel-1", "fl-1", "CVE-1")
	if err := st.Save(ctx, a, true, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(ctx, b, true, 0, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("duplicate (release,faultline) create err = %v, want ErrConcurrent", err)
	}
}

func TestOutboxRelay(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	f := newFinding(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	notes := []app.OutboxNote{{EventType: app.EventFindingOpened, Event: domain.NewFindingOpened(f, epoch), OccurredAt: epoch}}
	if err := st.Save(ctx, f, true, 0, notes); err != nil {
		t.Fatal(err)
	}

	// A failing publisher increments attempts and delivers nothing.
	fp := &fakePublisher{failFirst: true}
	relay := store.NewRelay(pool, fp, 10)
	if n, err := relay.DeliverPending(ctx); err != nil || n != 0 {
		t.Fatalf("failing relay: n=%d err=%v", n, err)
	}
	if got := count(t, pool, `SELECT attempts FROM governance_outbox WHERE finding_id = 'fnd-1'`); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}

	// A healthy pass delivers and marks sent; a second pass is a no-op.
	fp.failFirst = false
	if n, err := relay.DeliverPending(ctx); err != nil || n != 1 {
		t.Fatalf("healthy relay: n=%d err=%v", n, err)
	}
	if n, _ := relay.DeliverPending(ctx); n != 0 {
		t.Errorf("second pass delivered %d, want 0", n)
	}
	if got := count(t, pool, `SELECT count(*) FROM governance_outbox WHERE sent_at IS NULL`); got != 0 {
		t.Errorf("unsent = %d, want 0", got)
	}
}

func TestProjectionsAndFanout(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	// Two Findings on one Faultline (two releases) + one unrelated.
	seed := func(id, rel, fl string, stance domain.Stance) {
		f := newFinding(t, id, rel, fl, "CVE-1")
		if stance != "" {
			p, _ := domain.NewGovernanceProposal(domain.ProposalID("p-"+id), human, stance, "x", epoch)
			_ = f.RaiseProposal(p)
			_, _ = f.AcceptProposal(domain.ProposalID("p-"+id), human, epoch)
		}
		if err := st.Save(ctx, f, true, 0, nil); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("fnd-1", "rel-1", "fl-1", domain.StanceAffected)
	seed("fnd-2", "rel-2", "fl-1", "")
	seed("fnd-3", "rel-3", "fl-9", domain.StanceNotAffected)

	// Fan-out: both Findings on fl-1.
	ids, err := st.FindingsByFaultline(ctx, "fl-1")
	if err != nil || len(ids) != 2 {
		t.Fatalf("fan-out = %v err=%v", ids, err)
	}

	// Blast radius: releases affected by fl-1.
	blast, err := st.FaultlineBlastRadius(ctx, "fl-1")
	if err != nil || len(blast) != 2 || blast[0] != "rel-1" || blast[1] != "rel-2" {
		t.Errorf("blast = %v err=%v", blast, err)
	}

	// Release posture: rel-1 has one Finding with an established Position.
	posture, err := st.ReleasePosture(ctx, "rel-1")
	if err != nil || len(posture) != 1 {
		t.Fatalf("posture = %+v err=%v", posture, err)
	}
	if !posture[0].HasPosition || posture[0].Stance != domain.StanceAffected {
		t.Errorf("posture[0] = %+v", posture[0])
	}
	// rel-2's Finding has no Position yet.
	p2, _ := st.ReleasePosture(ctx, "rel-2")
	if len(p2) != 1 || p2[0].HasPosition {
		t.Errorf("rel-2 posture = %+v", p2)
	}
}

func TestCrashResumePendingDecisionSurvives(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// A Finding awaiting a human: Under Investigation with an open proposal.
	f := newFinding(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	p, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "needs review", epoch)
	_ = f.RaiseProposal(p)
	if err := store.New(pool).Save(ctx, f, true, 0, nil); err != nil {
		t.Fatal(err)
	}

	// "Restart": a fresh Store over the same pool re-reads the durable human-wait state —
	// the pending decision is never lost and never auto-decided (D12).
	revived := store.New(pool)
	got, err := revived.GetByID(ctx, "fnd-1")
	if err != nil {
		t.Fatalf("resume get: %v", err)
	}
	if got.Stage() != domain.StageUnderInvestigation {
		t.Errorf("stage = %q, want under_investigation", got.Stage())
	}
	ps := got.Proposals()
	if len(ps) != 1 || !ps[0].IsOpen() {
		t.Errorf("proposal not preserved open: %+v", ps)
	}
	if _, ok := got.CurrentPosition(); ok {
		t.Error("a pending decision must never auto-establish a Position")
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	f := newFinding(t, "fnd-1", "rel-1", "fl-1", "CVE-1")
	_, _ = f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:a"})
	notes := []app.OutboxNote{{EventType: app.EventFindingOpened, Event: domain.NewFindingOpened(f, epoch), OccurredAt: epoch}}
	if err := st.Save(ctx, f, true, 0, notes); err != nil {
		t.Fatal(err)
	}
	if err := st.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := count(t, pool, `SELECT count(*) FROM findings`); got != 0 {
		t.Errorf("findings after purge = %d", got)
	}
}

func TestMigrationDownUp(t *testing.T) {
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
}

// load reloads a Finding by id, failing the test on error.
func load(t *testing.T, st *store.Store, id domain.FindingID) (domain.Finding, bool, error) {
	t.Helper()
	f, err := st.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("load %s: %v", id, err)
	}
	return f, true, nil
}

type fakePublisher struct {
	failFirst bool
	delivered []store.OutboxNote
}

func (p *fakePublisher) Publish(_ context.Context, n store.OutboxNote) error {
	if p.failFirst {
		return errors.New("bus down")
	}
	p.delivered = append(p.delivered, n)
	return nil
}
