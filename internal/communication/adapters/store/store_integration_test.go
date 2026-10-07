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
	"github.com/themis-project/themis/internal/kernel/event"
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
		`TRUNCATE delivery_attempts, delivery_intents, processed_events, publishable_positions,
			communication_outbox, publications RESTART IDENTITY CASCADE`); err != nil {
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
	if got := count(t, pool, `SELECT attempts FROM communication_outbox WHERE subject='pub-1'`); got != 1 {
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

func (p *fakePublisher) Publish(_ context.Context, _ event.Envelope) error {
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

// The rollup store round-trip (D13/D5): save → current → supersede-on-republish → history
// keeps both → optimistic concurrency refuses a stale prior → unknown id is its own error.
func TestRollupStoreRoundTrip(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)

	product := domain.RollupProductRef{Product: "MRF", Project: "cdmrf-oamp", Version: "20.1.0.0-118", ReleaseID: "rel-1"}
	asOf := time.Date(2026, 9, 2, 17, 0, 0, 0, time.UTC)
	art, err := domain.MaterializeRollup(product, asOf, []domain.RollupEntry{
		{FindingID: "f1", CVE: "CVE-2025-47273", OpenComponents: []string{"pkg:pypi/setuptools@70.3.0"},
			Annotations: []string{"39.2.0 cleared"}},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := domain.NewRollupPublication("rp-1", art, "openvex", "customer", []byte(`{"v":1}`), "", asOf)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRollup(ctx, first, nil, 0); err != nil {
		t.Fatalf("save: %v", err)
	}

	cur, found, err := st.CurrentRollup(ctx, "rel-1", "openvex", "customer")
	if err != nil || !found || cur.ID() != "rp-1" || cur.Statements() != 1 || cur.WithdrawnExcluded() != 2 ||
		len(cur.InputSet()) != 1 || cur.InputSet()[0].FindingID != "f1" || !cur.AsOf().Equal(asOf) ||
		cur.ProductPURL() != product.PURL() || string(cur.Payload()) != `{"v":1}` {
		t.Fatalf("current = %+v found=%v err=%v", cur, found, err)
	}
	// A different audience is a different chain.
	if _, found, _ := st.CurrentRollup(ctx, "rel-1", "openvex", ""); found {
		t.Error("audience must scope the chain")
	}

	// Republish supersedes.
	second, err := domain.NewRollupPublication("rp-2", art, "openvex", "customer", []byte(`{"v":2}`), "rp-1", asOf.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	prior := cur
	prevVersion := prior.Version()
	if err := prior.Supersede("rp-2"); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveRollup(ctx, second, &prior, prevVersion); err != nil {
		t.Fatalf("supersede save: %v", err)
	}
	cur, found, err = st.CurrentRollup(ctx, "rel-1", "openvex", "customer")
	if err != nil || !found || cur.ID() != "rp-2" {
		t.Fatalf("current after republish = %v", cur.ID())
	}
	old, err := st.GetRollup(ctx, "rp-1")
	if err != nil || old.SupersededBy() != "rp-2" || old.Version() != 2 {
		t.Fatalf("superseded old = %+v err=%v", old, err)
	}
	if hist, err := st.ListRollups(ctx, "rel-1"); err != nil || len(hist) != 2 {
		t.Fatalf("history = %d err=%v — D5 keeps both", len(hist), err)
	}

	// A STALE prior (wrong version) loses the race explicitly.
	third, _ := domain.NewRollupPublication("rp-3", art, "openvex", "customer", []byte(`{"v":3}`), "rp-2", asOf.Add(2*time.Minute))
	staleP := cur
	_ = staleP.Supersede("rp-3")
	if err := st.SaveRollup(ctx, third, &staleP, 99); !errors.Is(err, app.ErrConcurrent) {
		t.Fatalf("stale prior err = %v, want ErrConcurrent", err)
	}

	if _, err := st.GetRollup(ctx, "ghost"); !errors.Is(err, domain.ErrRollupNotFound) {
		t.Errorf("unknown rollup err = %v", err)
	}
}

// --- N-M1a: outward-delivery intents -------------------------------------------------------

const (
	intentID1 = "11111111-1111-4111-8111-111111111111"
	intentID2 = "22222222-2222-4222-8222-222222222222"
	intentID3 = "33333333-3333-4333-8333-333333333333"
)

func pendingIntent(id string, typ app.IntentType, originEventID string, due time.Time) app.Intent {
	return app.Intent{
		ID: id, Type: typ, Destination: "dest-" + string(typ), State: app.IntentPending,
		NextAttemptAt: due, Result: map[string]string{},
		Snapshot: map[string]string{"release_id": "rel-1", "cve": "CVE-2026-1"},
		Lineage: app.IntentLineage{
			SourceContext: "governance", EventType: "governance.finding_opened",
			EventID: originEventID, EventTime: epoch, CorrelationID: "corr-1",
		},
		OriginEventID: originEventID,
		ReleaseID:     "rel-1", FindingID: "fnd-1",
		CreatedAt: due, UpdatedAt: due,
	}
}

// The deduplication rule: the SAME originating event yields ONE intent, and the second
// CreateIntent returns the first row rather than failing or duplicating. An intent with no
// originating event (worker-sourced) is exempt — two of them are two notifications.
func TestDeliveryIntentIdempotenceOnTheEventID(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	first, err := st.CreateIntent(ctx, pendingIntent(intentID1, app.IntentJiraIssue, "env-1", epoch))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if first.ID != intentID1 || first.State != app.IntentPending || first.Attempts != 0 {
		t.Errorf("stored = %+v", first)
	}
	if first.Snapshot["cve"] != "CVE-2026-1" || first.Lineage.CorrelationID != "corr-1" {
		t.Errorf("snapshot/lineage round-trip = %+v / %+v", first.Snapshot, first.Lineage)
	}
	if len(first.PayloadBytes) != 0 || first.PayloadSHA256 != "" {
		t.Errorf("payload columns must stay empty in N-M1a: %q / %q", first.PayloadSHA256, first.PayloadBytes)
	}

	// A replay of the same envelope, even with a freshly minted intent id.
	second, err := st.CreateIntent(ctx, pendingIntent(intentID2, app.IntentJiraIssue, "env-1", epoch))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if second.ID != intentID1 {
		t.Errorf("replay returned %s, want the existing %s", second.ID, intentID1)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_intents`); n != 1 {
		t.Fatalf("rows = %d, want 1 — the event id is the dedup key", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_intents WHERE type='jira_issue'`); n != 1 {
		t.Errorf("jira_issue rows = %d, want 1", n)
	}

	// Worker-sourced intents carry NULL and never collide.
	for _, id := range []string{intentID2, intentID3} {
		if _, err := st.CreateIntent(ctx, pendingIntent(id, app.IntentEmail, "", epoch)); err != nil {
			t.Fatalf("create worker-sourced %s: %v", id, err)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_intents WHERE origin_event_id IS NULL`); n != 2 {
		t.Errorf("worker-sourced rows = %d, want 2", n)
	}
}

// The work cycle: only DUE pending intents are claimed, an attempt advances the counters and
// appends to the ledger, and the delivered transition is terminal.
func TestDeliveryIntentWorkCycle(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	due := pendingIntent(intentID1, app.IntentJiraIssue, "env-1", epoch)
	later := pendingIntent(intentID2, app.IntentEmail, "env-2", epoch.Add(time.Hour))
	for _, in := range []app.Intent{due, later} {
		if _, err := st.CreateIntent(ctx, in); err != nil {
			t.Fatalf("create: %v", err)
		}
	}

	work, err := st.GetPendingForWork(ctx, epoch, 10)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(work) != 1 || work[0].ID != intentID1 {
		t.Fatalf("work = %+v, want only the due intent", work)
	}
	if work, err = st.GetPendingForWork(ctx, epoch.Add(2*time.Hour), 10); err != nil || len(work) != 2 {
		t.Fatalf("work later = %d err=%v, want both", len(work), err)
	}

	// A failed attempt: counters move, state does NOT.
	at := epoch.Add(time.Minute)
	if err := st.RecordAttempt(ctx, app.Attempt{
		IntentID: intentID1, AttemptNo: 1, Outcome: app.AttemptFailure,
		Error: "refused", At: at, NextAttemptAt: at.Add(time.Second),
	}); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	in, err := st.GetIntent(ctx, intentID1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if in.State != app.IntentPending || in.Attempts != 1 || in.LastError != "refused" {
		t.Errorf("after failure = %+v", in)
	}
	if !in.NextAttemptAt.Equal(at.Add(time.Second)) || !in.LastAttemptAt.Equal(at) {
		t.Errorf("attempt times = %s / %s", in.NextAttemptAt, in.LastAttemptAt)
	}

	// A successful attempt, then the terminal transition.
	if err := st.RecordAttempt(ctx, app.Attempt{
		IntentID: intentID1, AttemptNo: 2, Outcome: app.AttemptSuccess, StatusCode: 200,
		ResponseExcerpt: "accepted", At: at.Add(time.Second), NextAttemptAt: at.Add(time.Second),
	}); err != nil {
		t.Fatalf("record success: %v", err)
	}
	if err := st.MarkDelivered(ctx, intentID1, map[string]string{"reference": "JIRA-7"}); err != nil {
		t.Fatalf("mark delivered: %v", err)
	}
	if in, err = st.GetIntent(ctx, intentID1); err != nil {
		t.Fatalf("get: %v", err)
	}
	if in.State != app.IntentDelivered || in.Result["reference"] != "JIRA-7" || in.LastError != "" {
		t.Errorf("delivered = %+v", in)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_attempts WHERE intent_id=$1`, intentID1); n != 2 {
		t.Errorf("ledger rows = %d, want 2 (append-only)", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_attempts WHERE intent_id=$1 AND outcome='success' AND status_code=200`, intentID1); n != 1 {
		t.Errorf("success ledger row missing")
	}

	// A delivered intent is not work, and cannot be delivered, cancelled or retried again.
	if work, err = st.GetPendingForWork(ctx, epoch.Add(2*time.Hour), 10); err != nil || len(work) != 1 {
		t.Errorf("work after delivery = %+v err=%v", work, err)
	}
	for name, err := range map[string]error{
		"deliver": st.MarkDelivered(ctx, intentID1, nil),
		"cancel":  st.CancelIntent(ctx, intentID1),
		"retry":   st.RetryIntent(ctx, intentID1),
		"dead":    st.MarkDeadLetter(ctx, intentID1, "late"),
	} {
		if !errors.Is(err, app.ErrIntentNotFound) {
			t.Errorf("%s on a delivered intent: err = %v, want ErrIntentNotFound", name, err)
		}
	}
}

// The operator surface: dead-letters are listed newest-first with paging and a window, retry
// resets the counters, cancel abandons, and an unknown id is an error rather than a silent
// success.
func TestDeliveryIntentDeadLetterRetryAndCancel(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	for i, id := range []string{intentID1, intentID2, intentID3} {
		in := pendingIntent(id, app.IntentJiraIssue, fmt.Sprintf("env-%d", i), epoch)
		if _, err := st.CreateIntent(ctx, in); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	for _, id := range []string{intentID1, intentID2} {
		if err := st.RecordAttempt(ctx, app.Attempt{
			IntentID: id, AttemptNo: 3, Outcome: app.AttemptFailure, Error: "gave up",
			At: epoch, NextAttemptAt: epoch,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
		if err := st.MarkDeadLetter(ctx, id, "gave up"); err != nil {
			t.Fatalf("dead letter: %v", err)
		}
	}

	dead, err := st.ListDeadLetters(ctx, epoch.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(dead) != 2 {
		t.Fatalf("dead letters = %d, want 2 (the pending one is not listed)", len(dead))
	}
	if dead[0].State != app.IntentDeadLetter || dead[0].LastError != "gave up" || dead[0].Attempts != 3 {
		t.Errorf("dead letter = %+v", dead[0])
	}
	if paged, err := st.ListDeadLetters(ctx, epoch.Add(-time.Hour), 1); err != nil || len(paged) != 1 {
		t.Errorf("paged = %d err=%v, want 1", len(paged), err)
	}
	// The window excludes rows updated before `since`.
	if recent, err := st.ListDeadLetters(ctx, time.Now().UTC().Add(time.Hour), 10); err != nil || len(recent) != 0 {
		t.Errorf("future window = %d err=%v, want 0", len(recent), err)
	}

	// Retry puts one back to work with a clean slate; the ledger is NOT erased.
	if err := st.RetryIntent(ctx, intentID1); err != nil {
		t.Fatalf("retry: %v", err)
	}
	in, err := st.GetIntent(ctx, intentID1)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if in.State != app.IntentPending || in.Attempts != 0 || in.LastError != "" {
		t.Errorf("retried = %+v", in)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_attempts WHERE intent_id=$1`, intentID1); n != 1 {
		t.Errorf("retry erased the attempt ledger (rows = %d)", n)
	}
	work, err := st.GetPendingForWork(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(work) != 2 {
		t.Errorf("work after retry = %d, want 2 (the retried one and the untouched one)", len(work))
	}

	// Cancel abandons the other one.
	if err := st.CancelIntent(ctx, intentID2); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if in, err = st.GetIntent(ctx, intentID2); err != nil || in.State != app.IntentCancelled {
		t.Errorf("cancelled = %+v err=%v", in, err)
	}

	// An unknown id is an error on every operator path.
	const ghost = "99999999-9999-4999-8999-999999999999"
	for name, err := range map[string]error{
		"get":    errOf(st.GetIntent(ctx, ghost)),
		"retry":  st.RetryIntent(ctx, ghost),
		"cancel": st.CancelIntent(ctx, ghost),
	} {
		if !errors.Is(err, app.ErrIntentNotFound) {
			t.Errorf("%s(ghost): err = %v, want ErrIntentNotFound", name, err)
		}
	}
}

func errOf(_ app.Intent, err error) error { return err }

// The intent tables go with a Purge (dev reset), and the attempt ledger cascades.
func TestPurgeClearsDeliveryIntents(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	if _, err := st.CreateIntent(ctx, pendingIntent(intentID1, app.IntentEmail, "env-1", epoch)); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := st.RecordAttempt(ctx, app.Attempt{
		IntentID: intentID1, AttemptNo: 1, Outcome: app.AttemptFailure, Error: "x", At: epoch, NextAttemptAt: epoch,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}
	if err := st.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_intents`); n != 0 {
		t.Errorf("intents after purge = %d", n)
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_attempts`); n != 0 {
		t.Errorf("attempts after purge = %d", n)
	}
}
