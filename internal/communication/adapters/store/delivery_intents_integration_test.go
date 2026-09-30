//go:build integration

package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

var intentEpoch = time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)

// scalar reads one text value, returning "" when the row is absent — so a missing index is a
// readable assertion failure rather than a fatal scan error.
func scalar(t *testing.T, pool *pgxpool.Pool, query string, args ...any) string {
	t.Helper()
	var s string
	err := pool.QueryRow(context.Background(), query, args...).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatalf("scalar %q: %v", query, err)
	}
	return s
}

func testIntent(t *testing.T, id string, kind domain.DeliveryKind, eventID string) domain.DeliveryIntent {
	t.Helper()
	return testIntentTo(t, id, kind, eventID, "governance.finding_opened", "default")
}

// testIntentTo builds an intent with every component of the dedup key
// (origin_event_id, origin_event_type, kind, destination) under the caller's control, so a test
// can vary exactly one of them at a time.
func testIntentTo(t *testing.T, id string, kind domain.DeliveryKind, eventID, eventType, destination string) domain.DeliveryIntent {
	t.Helper()
	in, err := domain.NewDeliveryIntent(id, kind, destination, domain.DeliveryOrigin{
		EventID: eventID, EventType: eventType, EventTime: intentEpoch,
		FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1",
		ProductID: "prod-1", ProposalID: "prop-1", PositionVersion: 2,
	}, 3, intentEpoch)
	if err != nil {
		t.Fatalf("build intent %s: %v", id, err)
	}
	return in
}

// The whole record survives the round trip: the lineage columns, the snapshot fields that
// are NOT columns (faultline, CVE, proposal), the frozen payload bytes and their hash. A
// field that writes but does not read back is a silently narrowed audit trail.
func TestDeliveryIntent_RoundTrips(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	in := testIntent(t, "int-1", domain.DeliveryJiraIssue, "env-1")
	created, err := st.SaveIntent(ctx, in)
	if err != nil || !created {
		t.Fatalf("save = %v, %v", created, err)
	}

	got, err := st.GetIntent(ctx, "int-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Kind() != domain.DeliveryJiraIssue || got.Destination() != "default" ||
		got.Status() != domain.IntentPending || got.MaxAttempts() != 3 {
		t.Errorf("record = %s/%s/%s max=%d", got.Kind(), got.Destination(), got.Status(), got.MaxAttempts())
	}
	if string(got.Payload()) != string(in.Payload()) || got.PayloadHash() != in.PayloadHash() {
		t.Errorf("payload did not round-trip:\n got %s (%s)\nwant %s (%s)",
			got.Payload(), got.PayloadHash(), in.Payload(), in.PayloadHash())
	}
	o := got.Origin()
	if o.EventID != "env-1" || o.FindingID != "fnd-1" || o.ReleaseID != "rel-1" || o.ProductID != "prod-1" {
		t.Errorf("lineage columns = %+v", o)
	}
	// These three live only in the snapshot JSONB — the columns do not carry them.
	if o.FaultlineID != "fl-1" || o.CVE != "CVE-2026-1" || o.ProposalID != "prop-1" {
		t.Errorf("snapshot-only lineage lost: %+v", o)
	}

	if _, err := st.GetIntent(ctx, "nope"); !errors.Is(err, app.ErrIntentNotFound) {
		t.Errorf("get unknown = %v, want ErrIntentNotFound", err)
	}
}

// The dedup guarantee, enforced by the UNIQUE index rather than by a prior SELECT: a
// replayed envelope produces no second outward action, and says so instead of erroring.
func TestDeliveryIntent_UniquePerOriginKindDestination(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	first := testIntent(t, "int-1", domain.DeliveryJiraIssue, "env-1")
	if created, err := st.SaveIntent(ctx, first); err != nil || !created {
		t.Fatalf("first save = %v, %v", created, err)
	}

	// Same origin event + kind + destination, DIFFERENT id: refused by the index.
	replay := testIntent(t, "int-2", domain.DeliveryJiraIssue, "env-1")
	created, err := st.SaveIntent(ctx, replay)
	if err != nil {
		t.Fatalf("replay save errored: %v", err)
	}
	if created {
		t.Error("a replayed envelope created a second intent")
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_intents`); n != 1 {
		t.Errorf("rows = %d, want 1", n)
	}

	// Each of the FOUR key components, varied one at a time: every one of them makes a
	// different outward action, so every one of them must be admitted. Asserting only the
	// refusal would pass just as well on an index that is too WIDE or too narrow.
	for _, c := range []struct {
		name   string
		intent domain.DeliveryIntent
	}{
		{"kind", testIntentTo(t, "int-3", domain.DeliveryEmail, "env-1", "governance.finding_opened", "default")},
		{"event id", testIntentTo(t, "int-4", domain.DeliveryJiraIssue, "env-2", "governance.finding_opened", "default")},
		{"event type", testIntentTo(t, "int-5", domain.DeliveryJiraIssue, "env-1", "governance.proposal_accepted", "default")},
		{"destination", testIntentTo(t, "int-6", domain.DeliveryJiraIssue, "env-1", "governance.finding_opened", "secondary")},
	} {
		if created, err := st.SaveIntent(ctx, c.intent); err != nil || !created {
			t.Errorf("distinct %s = %v, %v", c.name, created, err)
		}
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_intents`); n != 5 {
		t.Errorf("rows = %d, want 5 (the first plus one per key component)", n)
	}

	// The index is really there, really unique, and really on the FOUR columns the store's
	// ON CONFLICT names — a conflict target that does not match a unique index is a runtime
	// error, and one that matches a DIFFERENT index would dedup on the wrong identity.
	def := scalar(t, pool, `SELECT indexdef FROM pg_indexes
		WHERE tablename = 'delivery_intents' AND indexname = 'ux_delivery_intents_origin'`)
	if def == "" {
		t.Fatal("ux_delivery_intents_origin is missing")
	}
	if !strings.Contains(def, "UNIQUE") {
		t.Errorf("ux_delivery_intents_origin is not unique: %s", def)
	}
	for _, col := range []string{"origin_event_id", "origin_event_type", "kind", "destination"} {
		if !strings.Contains(def, col) {
			t.Errorf("ux_delivery_intents_origin does not cover %s: %s", col, def)
		}
	}
	// NOT origin_event_seq: the bus seq is not part of the wire Envelope, so the dedup identity
	// is the envelope id (EDR-DELIVERY-01 D11). Pinned here so the deviation stays deliberate.
	if strings.Contains(def, "origin_event_seq") {
		t.Errorf("the index keys on a bus seq the Envelope does not carry: %s", def)
	}
}

// The attempt history is append-only and must stay in step with the counter it is evidence
// for — which is why the update and the insert share a transaction.
func TestDeliveryIntent_AttemptHistoryIsAppendOnly(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()
	policy := domain.BackoffPolicy{Base: time.Minute, Cap: time.Hour}

	in := testIntent(t, "int-1", domain.DeliveryEmail, "env-1")
	if _, err := st.SaveIntent(ctx, in); err != nil {
		t.Fatalf("save: %v", err)
	}

	for i := 1; i <= 3; i++ {
		at := intentEpoch.Add(time.Duration(i) * time.Minute)
		att, ok := in.RecordFailure("relay refused", at, policy)
		if !ok {
			t.Fatalf("attempt %d not recorded", i)
		}
		if err := st.RecordAttempt(ctx, in, att); err != nil {
			t.Fatalf("record attempt %d: %v", i, err)
		}
	}

	got, err := st.GetIntent(ctx, "int-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status() != domain.IntentDeadLetter || got.Attempts() != 3 || got.LastError() != "relay refused" {
		t.Errorf("stamped state = %s attempts=%d err=%q", got.Status(), got.Attempts(), got.LastError())
	}

	history, err := st.IntentAttempts(ctx, "int-1")
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history = %d rows, want 3", len(history))
	}
	for i, a := range history {
		if a.AttemptNo != i+1 || a.OK || a.Error != "relay refused" || a.At.IsZero() {
			t.Errorf("history[%d] = %+v", i, a)
		}
	}

	// An operator retry re-opens the row and keeps every one of those rows.
	if err := got.Retry(intentEpoch.Add(time.Hour)); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if err := st.SaveIntentState(ctx, got); err != nil {
		t.Fatalf("save state: %v", err)
	}
	back, _ := st.GetIntent(ctx, "int-1")
	if back.Status() != domain.IntentPending || back.Attempts() != 0 || back.LastError() != "" {
		t.Errorf("after retry = %s attempts=%d err=%q", back.Status(), back.Attempts(), back.LastError())
	}
	if n := count(t, pool, `SELECT count(*) FROM delivery_attempts WHERE intent_id = 'int-1'`); n != 3 {
		t.Errorf("history rows after retry = %d, want 3 — a retry must not erase it", n)
	}
}

// The worker's queue: one kind at a time, only what is due, oldest first. This is what makes
// a Jira outage unable to starve the mail channel.
func TestDeliveryIntent_DueIntentsAreScopedByKindAndDueTime(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	for _, seed := range []struct {
		id   string
		kind domain.DeliveryKind
		evt  string
	}{
		{"int-1", domain.DeliveryJiraIssue, "env-1"},
		{"int-2", domain.DeliveryEmail, "env-2"},
		{"int-3", domain.DeliveryJiraIssue, "env-3"},
	} {
		if _, err := st.SaveIntent(ctx, testIntent(t, seed.id, seed.kind, seed.evt)); err != nil {
			t.Fatalf("save %s: %v", seed.id, err)
		}
	}

	due, err := st.DueIntents(ctx, domain.DeliveryJiraIssue, intentEpoch, 10)
	if err != nil {
		t.Fatalf("due: %v", err)
	}
	if len(due) != 2 || due[0].ID() != "int-1" || due[1].ID() != "int-3" {
		t.Errorf("due = %v", ids(due))
	}
	if limited, err := st.DueIntents(ctx, domain.DeliveryJiraIssue, intentEpoch, 1); err != nil || len(limited) != 1 {
		t.Errorf("limited due = %v, %v", ids(limited), err)
	}

	// A failure pushes the row past its backoff, so the very next pass does not see it.
	in := due[0]
	att, _ := in.RecordFailure("jira 503", intentEpoch, domain.BackoffPolicy{Base: time.Minute, Cap: time.Hour})
	if err := st.RecordAttempt(ctx, in, att); err != nil {
		t.Fatalf("record: %v", err)
	}
	again, _ := st.DueIntents(ctx, domain.DeliveryJiraIssue, intentEpoch, 10)
	if len(again) != 1 || again[0].ID() != "int-3" {
		t.Errorf("due after backoff = %v, want [int-3]", ids(again))
	}
	later, _ := st.DueIntents(ctx, domain.DeliveryJiraIssue, intentEpoch.Add(2*time.Minute), 10)
	if len(later) != 2 {
		t.Errorf("due once the backoff elapsed = %v, want both", ids(later))
	}

	// A terminal row is off the queue entirely.
	done := later[0]
	ok, _ := done.RecordSuccess(intentEpoch.Add(3 * time.Minute))
	if err := st.RecordAttempt(ctx, done, ok); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	final, _ := st.DueIntents(ctx, domain.DeliveryJiraIssue, intentEpoch.Add(time.Hour), 10)
	if len(final) != 1 {
		t.Errorf("due after a delivery = %v, want 1", ids(final))
	}
}

func TestDeliveryIntent_ListAndCount(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	jira := testIntent(t, "int-1", domain.DeliveryJiraIssue, "env-1")
	mail := testIntent(t, "int-2", domain.DeliveryEmail, "env-2")
	for _, in := range []domain.DeliveryIntent{jira, mail} {
		if _, err := st.SaveIntent(ctx, in); err != nil {
			t.Fatalf("save: %v", err)
		}
	}
	att, _ := jira.RecordFailure("boom", intentEpoch, domain.BackoffPolicy{})
	jira.RecordFailure("boom", intentEpoch, domain.BackoffPolicy{})
	att, _ = jira.RecordFailure("boom", intentEpoch, domain.BackoffPolicy{})
	if err := st.RecordAttempt(ctx, jira, att); err != nil {
		t.Fatalf("dead-letter: %v", err)
	}

	dead, err := st.ListIntents(ctx, app.IntentFilter{Status: domain.IntentDeadLetter, Limit: 10})
	if err != nil || len(dead) != 1 || dead[0].ID() != "int-1" {
		t.Errorf("dead letters = %v, %v", ids(dead), err)
	}
	byKind, err := st.ListIntents(ctx, app.IntentFilter{Kind: domain.DeliveryEmail, Limit: 10})
	if err != nil || len(byKind) != 1 || byKind[0].ID() != "int-2" {
		t.Errorf("by kind = %v, %v", ids(byKind), err)
	}
	all, err := st.ListIntents(ctx, app.IntentFilter{Limit: 10})
	if err != nil || len(all) != 2 {
		t.Errorf("all = %v, %v", ids(all), err)
	}
	paged, err := st.ListIntents(ctx, app.IntentFilter{Limit: 1, Offset: 1})
	if err != nil || len(paged) != 1 {
		t.Errorf("paged = %v, %v", ids(paged), err)
	}

	counts, err := st.CountIntentsByStatus(ctx)
	if err != nil {
		t.Fatalf("counts: %v", err)
	}
	if counts[domain.IntentDeadLetter] != 1 || counts[domain.IntentPending] != 1 {
		t.Errorf("counts = %v", counts)
	}
}

// Reversibility is a task gate: the two migrations must come back down and go up again, or
// a bad deploy cannot be backed out.
func TestDeliveryIntentMigrations_ReverseAndReapply(t *testing.T) {
	if testDSN == "" {
		t.Skip("no database")
	}
	m, err := migrate.New(migrationsDir(), testDSN)
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	defer func() { _, _ = m.Close() }()

	// Both tables exist at head.
	pool, err := pgxpool.New(context.Background(), testDSN)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	for _, table := range []string{"delivery_intents", "delivery_attempts"} {
		if n := count(t, pool, `SELECT count(*) FROM information_schema.tables WHERE table_name = $1`, table); n != 1 {
			t.Fatalf("%s missing at head", table)
		}
	}

	// Down past both, then back up.
	if err := m.Steps(-2); err != nil {
		t.Fatalf("down 2: %v", err)
	}
	for _, table := range []string{"delivery_intents", "delivery_attempts"} {
		if n := count(t, pool, `SELECT count(*) FROM information_schema.tables WHERE table_name = $1`, table); n != 0 {
			t.Errorf("%s survived its down migration", table)
		}
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		t.Fatalf("re-apply: %v", err)
	}
	for _, table := range []string{"delivery_intents", "delivery_attempts"} {
		if n := count(t, pool, `SELECT count(*) FROM information_schema.tables WHERE table_name = $1`, table); n != 1 {
			t.Errorf("%s did not come back", table)
		}
	}
}

// The migrations and the store must describe the SAME schema. The round-trip test proves the
// columns the store touches work; this one proves the migration defines exactly them — no column
// the code writes is missing (a runtime error on first insert) and no column it never reads is
// left behind (dead schema that the next author has to guess about). Both tables are checked,
// because "two tables with these columns" is the step's acceptance criterion.
//
// On the SCHEMA NAME: the acceptance text says `communication.delivery_intents`, which names the
// communication DATABASE, not a Postgres schema. This repository is database-per-context and every
// Communication table lives in the default `public` schema (`publications`, `communication_outbox`,
// `publishable_positions`, `release_rollups` — none of them schema-qualified), so these two follow
// that convention. Asserted here so the reading is on the record rather than inferred.
func TestDeliveryIntentMigrations_SchemaMatchesTheStore(t *testing.T) {
	pool := newPool(t)

	for table, want := range map[string][]string{
		"delivery_intents": {
			"attempts", "created_at", "destination", "finding_id", "id", "kind", "last_error",
			"max_attempts", "next_attempt_at", "origin_event_id", "origin_event_time",
			"origin_event_type", "payload_bytes", "payload_hash", "position_version", "product_id",
			"release_id", "snapshot", "status", "updated_at",
		},
		"delivery_attempts": {
			"attempt_no", "attempted_at", "error", "id", "intent_id", "ok",
		},
	} {
		got := columnsOf(t, pool, table)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s columns:\n got %v\nwant %v", table, got, want)
		}
		if schema := scalar(t, pool, `SELECT table_schema FROM information_schema.tables
			WHERE table_name = $1`, table); schema != "public" {
			t.Errorf("%s lives in schema %q, want public (database-per-context)", table, schema)
		}
	}
}

// columnsOf returns one table's column names, sorted, so the comparison does not depend on the
// order the migration happens to declare them in.
func columnsOf(t *testing.T, pool *pgxpool.Pool, table string) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT column_name FROM information_schema.columns
		 WHERE table_name = $1 ORDER BY column_name`, table)
	if err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatalf("scan column: %v", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("columns of %s: %v", table, err)
	}
	return out
}

func ids(intents []domain.DeliveryIntent) []string {
	out := make([]string, 0, len(intents))
	for _, in := range intents {
		out = append(out, in.ID())
	}
	return out
}
