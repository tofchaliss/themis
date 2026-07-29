//go:build integration

package eventbus_test

import (
	"context"
	"encoding/json"
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

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/eventbus"
)

var testDSN string

func TestMain(m *testing.M) {
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		testDSN = dsn
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "eventbus-*")
	if err != nil {
		panic(err)
	}
	cfg := embeddedpostgres.DefaultConfig().
		Username("themis").Password("themis").Database("bus").
		Version(embeddedpostgres.V16).Port(15566).
		DataPath(filepath.Join(dir, "data")).
		RuntimePath(filepath.Join(dir, "runtime")).
		BinariesPath(filepath.Join(dir, "bin")).
		StartParameters(map[string]string{"shared_buffers": "128kB", "max_connections": "10"})
	db := embeddedpostgres.NewDatabase(cfg)
	if err := db.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "embedded postgres unavailable, skipping eventbus integration tests: %v\n", err)
		os.Exit(0)
	}
	testDSN = "postgres://themis:themis@localhost:15566/bus?sslmode=disable"
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
	defer func() { _, _ = m.Close() }()
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return err
	}
	return nil
}

// TestMigration_DownUp proves the bus migrations are reversible (up/down gate): a full Down
// then Up leaves the event_log (with its insert_xid8 watermark column) and stream_cursor
// intact.
func TestMigration_DownUp(t *testing.T) {
	if testDSN == "" {
		t.Skip("no database")
	}
	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.Close() }()
	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("down: %v", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		t.Fatalf("up: %v", err)
	}
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, q := range []string{
		"SELECT insert_xid8 FROM event_log LIMIT 0",
		"SELECT consumer, source_context, last_seq FROM stream_cursor LIMIT 0",
	} {
		if _, err := pool.Exec(context.Background(), q); err != nil {
			t.Fatalf("schema missing after down/up (%q): %v", q, err)
		}
	}
}

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	// Isolate each test: the event_log is a shared append log and stream_cursor a shared
	// read position.
	if _, err := pool.Exec(context.Background(), "TRUNCATE event_log, stream_cursor RESTART IDENTITY"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return pool
}

func envelope(t *testing.T, id string, payload json.RawMessage) event.Envelope {
	t.Helper()
	e, err := event.NewEnvelope(id, "evidence.registered", "evidence", "rel-1",
		"evidence.registered.v1", "corr-1", time.Unix(1_700_000_000, 0).UTC(), payload)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	return e
}

func countByEnvelopeID(t *testing.T, pool *pgxpool.Pool, id string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		"SELECT count(*) FROM event_log WHERE envelope_id = $1", id).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", id, err)
	}
	return n
}

// TestPublisher_AppendAndIdempotency proves the EB-04 contract: one log row per distinct
// envelope, with every field faithfully persisted, and an idempotent re-publish (the
// at-least-once relay redelivering must not duplicate the row).
func TestPublisher_AppendAndIdempotency(t *testing.T) {
	pool := newPool(t)
	pub := eventbus.NewPublisher(pool)
	ctx := context.Background()

	env := envelope(t, "evt-1", json.RawMessage(`{"evidence_id":"ev-1"}`))
	if err := pub.Publish(ctx, env); err != nil {
		t.Fatalf("first publish: %v", err)
	}

	// Fields round-trip, and seq is assigned by the BIGSERIAL default.
	var (
		seq                                   int64
		source, subject, typ, corr, schemaRef string
		payload                               []byte
		occurred                              time.Time
	)
	if err := pool.QueryRow(ctx, `
		SELECT seq, source_context, subject, type, correlation_id, schema_ref, payload, occurred_at
		FROM event_log WHERE envelope_id = $1`, env.ID).
		Scan(&seq, &source, &subject, &typ, &corr, &schemaRef, &payload, &occurred); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if seq <= 0 || source != "evidence" || subject != "rel-1" || typ != "evidence.registered" ||
		corr != "corr-1" || schemaRef != "evidence.registered.v1" || string(payload) != `{"evidence_id": "ev-1"}` ||
		!occurred.Equal(env.OccurredAt) {
		t.Errorf("row = seq:%d source:%s subject:%s type:%s corr:%s schema:%s payload:%s occurred:%s",
			seq, source, subject, typ, corr, schemaRef, payload, occurred)
	}

	// Re-publish the same envelope: at-most-once append, still exactly one row, no error.
	if err := pub.Publish(ctx, env); err != nil {
		t.Fatalf("idempotent re-publish: %v", err)
	}
	if got := countByEnvelopeID(t, pool, env.ID); got != 1 {
		t.Errorf("after re-publish, rows = %d, want 1", got)
	}

	// A distinct envelope appends a second row with a higher seq.
	env2 := envelope(t, "evt-2", nil) // nil payload → SQL NULL
	if err := pub.Publish(ctx, env2); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if got := countByEnvelopeID(t, pool, env2.ID); got != 1 {
		t.Errorf("env2 rows = %d, want 1", got)
	}
	var payload2 *string
	var seq2 int64
	if err := pool.QueryRow(ctx, "SELECT seq, payload FROM event_log WHERE envelope_id = $1", env2.ID).
		Scan(&seq2, &payload2); err != nil {
		t.Fatalf("read env2: %v", err)
	}
	if payload2 != nil {
		t.Errorf("nil-payload envelope stored payload = %v, want NULL", *payload2)
	}
	if seq2 <= seq {
		t.Errorf("seq not monotonic: env2 seq %d not greater than env1 seq %d", seq2, seq)
	}
}

// TestPublisher_SurfacesError proves Publish returns (does not swallow) an append error,
// so the relay leaves the outbox row unsent for retry. An invalid-JSON payload is a
// convenient way to force a DB error against the JSONB column.
func TestPublisher_SurfacesError(t *testing.T) {
	pool := newPool(t)
	pub := eventbus.NewPublisher(pool)

	env := envelope(t, "evt-bad", json.RawMessage(`not json`))
	if err := pub.Publish(context.Background(), env); err == nil {
		t.Fatal("expected error for invalid-JSON payload, got nil")
	}
	if got := countByEnvelopeID(t, pool, env.ID); got != 0 {
		t.Errorf("failed publish left %d rows, want 0", got)
	}
}
