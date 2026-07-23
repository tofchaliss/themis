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

	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "communication-store-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("themis").
		Version(embeddedpostgres.V16).Port(15500).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"max_connections": "30"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping communication store integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15500/themis?sslmode=disable"
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
		`TRUNCATE publishable_positions, communication_outbox, publications RESTART IDENTITY CASCADE`); err != nil {
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

var epoch = time.Unix(1_700_000_000, 0).UTC()

func publication(t *testing.T, id string, stance domain.Stance, supersedes domain.PublicationID) domain.Publication {
	t.Helper()
	snap := domain.PositionSnapshot{
		FindingID: "fnd-1", Version: 2, Stance: stance, Rationale: "vendor VEX confirms",
		Lineage: domain.Lineage{ReleaseID: "rel-1", FindingID: "fnd-1", FaultlineID: "fl-1", CVE: "CVE-2024-1"},
	}
	art, err := domain.Materialize(snap, domain.ArtifactVEX)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	p, err := domain.NewPublication(domain.PublicationID(id), art, "openvex", "tooling", "export", []byte(`{"vex":true}`), supersedes, epoch)
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}
	return p
}

// --- tests ---------------------------------------------------------------------------

func TestSaveAndLoadRoundTrip(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	pub := publication(t, "pub-1", domain.StanceNotAffected, "")
	notes := []app.OutboxNote{{EventType: app.EventPublicationCreated, Event: domain.NewPublicationCreated(pub, epoch), OccurredAt: epoch}}
	if err := st.Save(ctx, pub, nil, 0, notes); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := st.GetByID(ctx, "pub-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Type() != domain.ArtifactVEX || got.Stance() != domain.StanceNotAffected || got.Format() != "openvex" {
		t.Errorf("publication = %+v", got)
	}
	if string(got.Payload()) != `{"vex":true}` || got.PayloadPruned() {
		t.Errorf("payload = %q pruned=%v", got.Payload(), got.PayloadPruned())
	}
	if got.Lineage().CVE != "CVE-2024-1" || got.Artifact().Title == "" {
		t.Errorf("lineage/artifact = %+v / %q", got.Lineage(), got.Artifact().Title)
	}
	if got.Delivery().Status != domain.DeliveryPending {
		t.Errorf("delivery = %+v", got.Delivery())
	}

	// CurrentPublication resolves the identity tuple.
	cur, found, err := st.CurrentPublication(ctx, "rel-1", "fl-1", domain.ArtifactVEX, "tooling")
	if err != nil || !found || cur.ID() != "pub-1" {
		t.Errorf("current: found=%v id=%q err=%v", found, cur.ID(), err)
	}
	if _, found, _ := st.CurrentPublication(ctx, "rel-x", "fl-x", domain.ArtifactVEX, "tooling"); found {
		t.Error("unknown identity should be not found")
	}
	if _, err := st.GetByID(ctx, "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown id err = %v, want ErrNotFound", err)
	}
	if got := count(t, pool, `SELECT count(*) FROM communication_outbox`); got != 1 {
		t.Errorf("outbox rows = %d, want 1", got)
	}
}

func TestSupersedeAndConcurrency(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	prior := publication(t, "pub-1", domain.StanceAffected, "")
	if err := st.Save(ctx, prior, nil, 0, nil); err != nil {
		t.Fatal(err)
	}

	// Re-publish v2 supersedes pub-1.
	next := publication(t, "pub-2", domain.StanceMitigated, "pub-1")
	priorPrev := prior.Version()
	if err := prior.Supersede("pub-2"); err != nil {
		t.Fatal(err)
	}
	notes := []app.OutboxNote{
		{EventType: app.EventPublicationCreated, Event: domain.NewPublicationCreated(next, epoch), OccurredAt: epoch},
		{EventType: app.EventPublicationSuperseded, Event: domain.NewPublicationSuperseded(prior, epoch), OccurredAt: epoch},
	}
	if err := st.Save(ctx, next, &prior, priorPrev, notes); err != nil {
		t.Fatalf("supersede save: %v", err)
	}

	// Current is now pub-2; pub-1 is superseded.
	cur, _, _ := st.CurrentPublication(ctx, "rel-1", "fl-1", domain.ArtifactVEX, "tooling")
	if cur.ID() != "pub-2" || cur.Supersedes() != "pub-1" {
		t.Errorf("current = %q supersedes %q", cur.ID(), cur.Supersedes())
	}
	old, _ := st.GetByID(ctx, "pub-1")
	if !old.IsSuperseded() || old.SupersededBy() != "pub-2" {
		t.Errorf("pub-1 not superseded: %+v", old)
	}

	// A stale-version supersede loses (concurrent re-publish already advanced it).
	loser := publication(t, "pub-3", domain.StanceAffected, "pub-1")
	if err := st.Save(ctx, loser, &old, priorPrev, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("stale supersede err = %v, want ErrConcurrent", err)
	}
}

func TestMarkPublishableUpsert(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	if err := st.MarkPublishable(ctx, app.QueueEntry{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-1", Version: 1, Stance: domain.StanceAffected}); err != nil {
		t.Fatal(err)
	}
	// Upsert: a revision updates the same row (stale).
	if err := st.MarkPublishable(ctx, app.QueueEntry{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-1", Version: 2, Stance: domain.StanceMitigated, Stale: true}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, pool, `SELECT count(*) FROM publishable_positions`); n != 1 {
		t.Errorf("queue rows = %d, want 1 (upsert)", n)
	}
	if n := count(t, pool, `SELECT version FROM publishable_positions WHERE finding_id='fnd-1'`); n != 2 {
		t.Errorf("queue version = %d, want 2", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM publishable_positions WHERE stale=true`); n != 1 {
		t.Error("revision should mark the entry stale")
	}
}

func TestPurge(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	if err := st.Save(ctx, publication(t, "pub-1", domain.StanceAffected, ""), nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM publications`); n != 0 {
		t.Errorf("publications after purge = %d", n)
	}
}

func TestDeliveryQueueAndUpdate(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	pub := publication(t, "pub-1", domain.StanceAffected, "")
	if err := st.Save(ctx, pub, nil, 0, nil); err != nil {
		t.Fatal(err)
	}

	// The pending publication is in the delivery queue.
	undelivered, err := st.UndeliveredPublications(ctx, 10)
	if err != nil || len(undelivered) != 1 || undelivered[0].ID() != "pub-1" {
		t.Fatalf("undelivered = %+v err=%v", undelivered, err)
	}

	// Record delivery (version-guarded) + a terminal event.
	prev := pub.Version()
	pub.MarkDelivered(epoch)
	notes := []app.OutboxNote{{EventType: app.EventPublicationDelivered, Event: domain.NewPublicationDelivered(pub, epoch), OccurredAt: epoch}}
	if err := st.UpdateDelivery(ctx, pub, prev, notes); err != nil {
		t.Fatalf("update delivery: %v", err)
	}
	got, _ := st.GetByID(ctx, "pub-1")
	if got.Delivery().Status != domain.DeliveryDelivered {
		t.Errorf("delivery = %+v", got.Delivery())
	}
	// No longer in the delivery queue.
	if u, _ := st.UndeliveredPublications(ctx, 10); len(u) != 0 {
		t.Errorf("delivered publication still queued: %d", len(u))
	}
	// Stale-version update loses.
	if err := st.UpdateDelivery(ctx, pub, prev, nil); !errors.Is(err, app.ErrConcurrent) {
		t.Errorf("stale update err = %v, want ErrConcurrent", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM communication_outbox WHERE event_type=$1`, app.EventPublicationDelivered); n != 1 {
		t.Errorf("delivered event rows = %d, want 1", n)
	}
}

func TestListByReleaseAndQueue(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	if err := st.Save(ctx, publication(t, "pub-1", domain.StanceAffected, ""), nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkPublishable(ctx, app.QueueEntry{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-1", Version: 1, Stance: domain.StanceAffected}); err != nil {
		t.Fatal(err)
	}

	pubs, err := st.ListByRelease(ctx, "rel-1")
	if err != nil || len(pubs) != 1 || pubs[0].ID() != "pub-1" {
		t.Errorf("list = %+v err=%v", pubs, err)
	}
	q, err := st.PublishableQueue(ctx)
	if err != nil || len(q) != 1 || q[0].FindingID != "fnd-1" || q[0].Stance != domain.StanceAffected {
		t.Errorf("queue = %+v err=%v", q, err)
	}
}

func TestOutboxRelay(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	pub := publication(t, "pub-1", domain.StanceAffected, "")
	notes := []app.OutboxNote{{EventType: app.EventPublicationCreated, Event: domain.NewPublicationCreated(pub, epoch), OccurredAt: epoch}}
	if err := st.Save(ctx, pub, nil, 0, notes); err != nil {
		t.Fatal(err)
	}

	fp := &fakePublisher{failFirst: true}
	relay := store.NewRelay(pool, fp, 10)
	if n, err := relay.DeliverPending(ctx); err != nil || n != 0 {
		t.Fatalf("failing relay: n=%d err=%v", n, err)
	}
	if got := count(t, pool, `SELECT attempts FROM communication_outbox WHERE publication_id='pub-1'`); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
	fp.failFirst = false
	if n, err := relay.DeliverPending(ctx); err != nil || n != 1 {
		t.Fatalf("healthy relay: n=%d err=%v", n, err)
	}
	if n, _ := relay.DeliverPending(ctx); n != 0 {
		t.Errorf("second pass delivered %d, want 0", n)
	}
}

type fakePublisher struct{ failFirst bool }

func (p *fakePublisher) Publish(_ context.Context, _ store.OutboxNote) error {
	if p.failFirst {
		return errors.New("bus down")
	}
	return nil
}

func TestPrunePayloadsRetention(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	// A delivered publication; then prune payloads recorded before "now".
	pub := publication(t, "pub-1", domain.StanceAffected, "")
	if err := st.Save(ctx, pub, nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	prev := pub.Version()
	pub.MarkDelivered(epoch)
	if err := st.UpdateDelivery(ctx, pub, prev, nil); err != nil {
		t.Fatal(err)
	}

	// Nothing to prune before the record's own timestamp.
	if n, err := st.PrunePayloads(ctx, epoch); err != nil || n != 0 {
		t.Fatalf("early prune: n=%d err=%v, want 0", n, err)
	}
	// Prune anything recorded before a later cutoff.
	if n, err := st.PrunePayloads(ctx, epoch.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: n=%d err=%v, want 1", n, err)
	}
	got, _ := st.GetByID(ctx, "pub-1")
	if !got.PayloadPruned() {
		t.Error("payload should be pruned (NULL)")
	}
	// Re-prune is a no-op (payload already NULL).
	if n, _ := st.PrunePayloads(ctx, epoch.Add(time.Hour)); n != 0 {
		t.Errorf("re-prune pruned %d, want 0", n)
	}
}

func TestCrashResumeUndeliveredAndQueue(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	// A pending publication + a queued publishable position, persisted.
	if err := store.New(pool).Save(ctx, publication(t, "pub-1", domain.StanceAffected, ""), nil, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.New(pool).MarkPublishable(ctx, app.QueueEntry{FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", Version: 1, Stance: domain.StanceAffected}); err != nil {
		t.Fatal(err)
	}

	// "Restart": a fresh Store over the same pool re-reads durable state — the undelivered
	// Publication is never lost (resumes delivery) and was never auto-published/auto-delivered.
	revived := store.New(pool)
	undelivered, err := revived.UndeliveredPublications(ctx, 10)
	if err != nil || len(undelivered) != 1 || undelivered[0].Delivery().Status != domain.DeliveryPending {
		t.Errorf("undelivered after restart = %+v err=%v", undelivered, err)
	}
	q, err := revived.PublishableQueue(ctx)
	if err != nil || len(q) != 1 {
		t.Errorf("queue after restart = %+v err=%v", q, err)
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
