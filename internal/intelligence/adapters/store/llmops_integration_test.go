//go:build integration

package store_test

// Δ4a LLMOps store round-trips against embedded Postgres, reusing this package's TestMain +
// newStore harness. Covers: invocation append/get (idempotent), retention prune leaving the
// golden set untouched, golden promote/list, eval report write, and the prompt-version stamp.

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/adapters/store"
)

func TestInvocationLogAppendGetPruneAndGoldenSurvives(t *testing.T) {
	st, pool := newStore(t)
	ctx := context.Background()

	in := store.LoggedInvocation{
		CorrelationID: "corr-1", Capability: "compare_releases", PromptVersion: "ab12cd",
		Model: "cyberpal20b", Tier: "primary",
		ContextJSON: []byte(`{"baseline":"rel-a"}`), OutputJSON: []byte(`{"reasoning":"x"}`),
		Reason: "ok", Tokens: 3212,
	}
	if err := st.AppendInvocation(ctx, in); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Idempotent on correlation id — a redelivery is a no-op, not a duplicate.
	if err := st.AppendInvocation(ctx, in); err != nil {
		t.Fatalf("append again: %v", err)
	}
	got, ok, err := st.GetInvocation(ctx, "corr-1")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Tokens != 3212 || got.Capability != "compare_releases" || string(got.OutputJSON) == "" {
		t.Errorf("round-trip = %+v", got)
	}

	// Promote a golden entry FROM the log, then prune the whole log — the golden set survives.
	if err := st.PromoteGolden(ctx, store.GoldenEntry{
		ID: "g-1", Label: "merged-module-stream plan", Capability: "plan_remediation",
		SourceCorrelationID: "corr-1",
		ContextJSON:         []byte(`{"release":"rel-a"}`), ExpectedJSON: []byte(`{"grounded":true}`),
	}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	removed, err := st.PruneInvocations(ctx, time.Now().Add(time.Hour)) // everything older than now+1h = all
	if err != nil || removed != 1 {
		t.Fatalf("prune removed=%d err=%v", removed, err)
	}
	if _, ok, _ := st.GetInvocation(ctx, "corr-1"); ok {
		t.Error("pruned invocation should be gone")
	}
	golden, err := st.ListGolden(ctx)
	if err != nil || len(golden) != 1 || golden[0].ID != "g-1" {
		t.Fatalf("golden set must survive the prune: %+v err=%v", golden, err)
	}
	_ = pool
}

func TestEvalReportAndPromptVersion(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	if err := st.WriteEvalReport(ctx, "run-1", "44026ef", 4, 3, []byte(`{"compare_releases":{"pass":3,"total":4}}`)); err != nil {
		t.Fatalf("write report: %v", err)
	}

	// Prompt-version stamp is idempotent per (capability, hash).
	if err := st.UpsertPromptVersion(ctx, "compare_releases", "hash-abc"); err != nil {
		t.Fatalf("upsert version: %v", err)
	}
	if err := st.UpsertPromptVersion(ctx, "compare_releases", "hash-abc"); err != nil {
		t.Fatalf("upsert version again: %v", err)
	}
}

// Δ4b D-Δ4b-5: the analyst records pushes and skips already-proposed pairs; a CHANGED precedent
// key (a new precedent version) re-proposes.
func TestAutonomousProposalIdempotence(t *testing.T) {
	st, _ := newStore(t)
	ctx := context.Background()

	if has, err := st.HasProposed(ctx, "f-1", "prec-v1"); err != nil || has {
		t.Fatalf("fresh pair: has=%v err=%v", has, err)
	}
	if err := st.RecordProposed(ctx, "f-1", "prec-v1"); err != nil {
		t.Fatal(err)
	}
	// Same pair → skip.
	if has, _ := st.HasProposed(ctx, "f-1", "prec-v1"); !has {
		t.Error("recorded pair must read as already-proposed (skip)")
	}
	// Re-record is idempotent (no error, no duplicate).
	if err := st.RecordProposed(ctx, "f-1", "prec-v1"); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	// A CHANGED precedent (new key) → NOT yet proposed → re-proposes.
	if has, _ := st.HasProposed(ctx, "f-1", "prec-v2"); has {
		t.Error("a changed precedent key must read as not-yet-proposed (re-propose)")
	}
}
