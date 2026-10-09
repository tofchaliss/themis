//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// The pending release-evaluation queue against real Postgres (EDR-DELIVERY-01 N-M2b): the
// idempotent insert, the ladder over real `base_score` rows, and the atomicity of
// publish-and-mark — the three properties the worker's correctness rests on and the three a
// fake store can only assert about itself.

func TestEnqueuePendingReleaseEvaluation_IdempotentOnTheTriple(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := st.EnqueuePendingReleaseEvaluation(ctx, "rel-1", "ev-1", domain.CauseNewSBOM); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if got := count(t, pool, `SELECT count(*) FROM release_evaluations_pending`); got != 1 {
		t.Errorf("rows = %d, want 1 — a redelivered completion fact adds nothing", got)
	}

	// A different cause for the same SBOM is a DIFFERENT fact (M2-3), and so is a different SBOM.
	if err := st.EnqueuePendingReleaseEvaluation(ctx, "rel-1", "ev-1", domain.CauseRediscovery); err != nil {
		t.Fatalf("rediscovery: %v", err)
	}
	if err := st.EnqueuePendingReleaseEvaluation(ctx, "rel-1", "ev-2", domain.CauseNewSBOM); err != nil {
		t.Fatalf("second sbom: %v", err)
	}

	rows, err := st.ListPendingReleaseEvaluations(ctx, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("pending = %d, want 3", len(rows))
	}
	for _, r := range rows {
		if r.ID == 0 || r.ReleaseID != "rel-1" || r.ReceivedAt.IsZero() {
			t.Errorf("row = %+v", r)
		}
	}
	// Oldest first, and the limit bounds the pass.
	if one, err := st.ListPendingReleaseEvaluations(ctx, 1); err != nil || len(one) != 1 || one[0].ID != rows[0].ID {
		t.Errorf("limit 1 = %+v (err %v), want the oldest row only", one, err)
	}
	// A non-positive limit falls back to a sane batch rather than returning nothing (a limit of
	// 0 in SQL would drain the queue never).
	if all, err := st.ListPendingReleaseEvaluations(ctx, 0); err != nil || len(all) != 3 {
		t.Errorf("limit 0 = %d rows (err %v), want the default batch", len(all), err)
	}
}

// The M1b-5 ladder over real rows, at its edges — including a SUPPRESSED Finding, which is
// counted all the same (M1b-4), and a 0 score, which is counted nowhere.
func TestCountFindingsByBaseScoreBuckets_LadderOverRealRows(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	// One Finding per ladder edge, each on its own Faultline (SetBaseScore keys on the card).
	for i, score := range []int{90, 70, 40, 1, 0} {
		fl := faultlineID(i)
		f := newFinding(t, string(findingID(i)), "rel-1", fl, "CVE-2024-"+fl)
		if err := st.Save(ctx, f, true, 0, nil); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
		if err := st.SetBaseScore(ctx, fl, score); err != nil {
			t.Fatalf("score %d: %v", i, err)
		}
	}
	// A Finding on ANOTHER release must not leak into the count.
	other := newFinding(t, "fnd-other", "rel-2", "fl-other", "CVE-2024-999")
	if err := st.Save(ctx, other, true, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.SetBaseScore(ctx, "fl-other", 95); err != nil {
		t.Fatal(err)
	}

	// SUPPRESS the Critical one. The count must not move: a Position is a decision about a
	// Finding, not evidence that the flaw left the inventory.
	suppress(t, st, findingID(0))

	got, err := st.CountFindingsByBaseScoreBuckets(ctx, "rel-1")
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	want := domain.SeverityCounts{Critical: 1, High: 1, Medium: 1, Low: 1}
	if got != want {
		t.Errorf("counts = %+v, want %+v (suppressed included, 0 counted nowhere)", got, want)
	}

	// A release with no Findings counts all zero — the success case, not an error.
	zero, err := st.CountFindingsByBaseScoreBuckets(ctx, "rel-empty")
	if err != nil || zero != (domain.SeverityCounts{}) {
		t.Errorf("empty release = %+v (err %v), want all zero", zero, err)
	}
}

// Publish-and-mark is ONE transaction, and it is guarded: a second call for the same row
// appends no second outbox note. Appending without marking would republish on every pass;
// marking without appending would lose the only trigger the rebuild loop runs on.
func TestPublishEvaluatedAndMark_OneGuardedTransaction(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	if err := st.EnqueuePendingReleaseEvaluation(ctx, "rel-1", "ev-1", domain.CauseNewSBOM); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rows, err := st.ListPendingReleaseEvaluations(ctx, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list = %+v (err %v)", rows, err)
	}
	row := rows[0]

	ev := domain.NewReleaseEvaluated("prod-1", "prj-1", "rel-1", "ev-1", domain.CauseNewSBOM,
		domain.SeverityCounts{Critical: 1, High: 2})
	if err := st.PublishEvaluatedAndMark(ctx, row, ev, epoch); err != nil {
		t.Fatalf("publish: %v", err)
	}

	if got := count(t, pool, `SELECT count(*) FROM release_evaluations_pending WHERE published_at IS NOT NULL`); got != 1 {
		t.Errorf("published rows = %d, want 1", got)
	}
	if left, err := st.ListPendingReleaseEvaluations(ctx, 10); err != nil || len(left) != 0 {
		t.Errorf("pending after publish = %+v (err %v), want none", left, err)
	}

	// The outbox row: the subject is the RELEASE, the schema_ref is the frozen contract, and
	// the payload is the snake_case body.
	var subject, eventType, schemaRef, correlationID string
	var payload []byte
	if err := pool.QueryRow(ctx, `
		SELECT subject, event_type, schema_ref, correlation_id, payload
		FROM governance_outbox`).Scan(&subject, &eventType, &schemaRef, &correlationID, &payload); err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	if subject != "rel-1" || correlationID != "rel-1" {
		t.Errorf("subject/correlation = %q/%q, want the release id", subject, correlationID)
	}
	if eventType != app.EventReleaseEvaluated || schemaRef != "governance.release_evaluated.v1" {
		t.Errorf("type/schema = %q/%q", eventType, schemaRef)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("payload: %v", err)
	}
	for _, key := range []string{"product_id", "project_id", "release_id", "sbom_id", "severity_counts", "cause"} {
		if _, ok := body[key]; !ok {
			t.Errorf("payload missing %s: %s", key, payload)
		}
	}
	if body["cause"] != domain.CauseNewSBOM {
		t.Errorf("cause = %v", body["cause"])
	}

	// The guard: the same row again appends nothing and is not an error — another worker (or
	// another node) having published it first is a race with one right outcome.
	if err := st.PublishEvaluatedAndMark(ctx, row, ev, epoch); err != nil {
		t.Fatalf("second publish: %v", err)
	}
	if got := count(t, pool, `SELECT count(*) FROM governance_outbox`); got != 1 {
		t.Errorf("outbox rows = %d, want exactly 1", got)
	}

	// Purge clears the queue too (dev reset must not leave a to-do behind for Findings that are
	// gone).
	if err := st.Purge(ctx); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := count(t, pool, `SELECT count(*) FROM release_evaluations_pending`); got != 0 {
		t.Errorf("queue rows after purge = %d", got)
	}
}

func findingID(i int) domain.FindingID { return domain.FindingID("fnd-" + string(rune('a'+i))) }

func faultlineID(i int) string { return "fl-" + string(rune('a'+i)) }

// suppress establishes a not_affected Position on a Finding, through the domain, so the count
// is asserted against a genuinely decided row rather than a hand-written column.
func suppress(t *testing.T, st *store.Store, id domain.FindingID) {
	t.Helper()
	ctx := context.Background()
	f, err := st.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("load %s: %v", id, err)
	}
	p, err := domain.NewGovernanceProposal("prop-1", domain.Actor{Kind: domain.ActorSystem, ID: "vex"},
		domain.StanceNotAffected, "vendor states not affected", epoch, value.TrustObserved)
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if _, err := f.AcceptProposal("prop-1", human, epoch); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if err := st.Save(ctx, f, false, 0, nil); err != nil {
		t.Fatalf("save suppressed: %v", err)
	}
}
