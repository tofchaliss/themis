//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// recordingApply is an inbox inner handler that counts invocations and runs fn on the
// ctx-carried transaction — so the Save/RecordMatch it calls join the inbox unit of work.
type recordingApply struct {
	calls int
	fn    func(ctx context.Context) error
}

func (r *recordingApply) Handle(ctx context.Context, _ event.Envelope) error {
	r.calls++
	return r.fn(ctx)
}

// TestInboxJoinsWritesAndDedups proves EB-06 for Knowledge: the correlation writes (Save +
// RecordMatch, the fan-out path) join the inbox transaction and commit atomically with the
// envelope claim, and a redelivery of the same envelope id is a no-op (the inner apply is not
// re-run).
func TestInboxJoinsWritesAndDedups(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	id := domain.FaultlineID("fl-inbox")
	f, err := domain.NewFaultline(id, cveID(t, "CVE-2024-100"))
	if err != nil {
		t.Fatalf("new faultline: %v", err)
	}

	inner := &recordingApply{fn: func(ctx context.Context) error {
		if err := st.Save(ctx, f, true, 0, nil); err != nil {
			return err
		}
		_, err := st.RecordMatch(ctx, app.Match{
			ReleaseID: "rel-1", FaultlineID: id, CVE: "CVE-2024-100",
			Component: app.InventoryComponent{PURL: "pkg:deb/debian/openssl@3.0"}, OccurredAt: time.Now().UTC(),
		})
		return err
	}}
	inbox := store.NewInboxConsumer(pool, inner)

	env := event.Envelope{ID: "evt-ev1", Type: "EvidenceRegistered"}
	if err := inbox.Handle(ctx, env); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// The Faultline, the match, and the claim all committed together.
	if got := count(t, pool, "SELECT count(*) FROM faultlines"); got != 1 {
		t.Fatalf("faultlines = %d, want 1", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM faultline_matches"); got != 1 {
		t.Fatalf("matches = %d, want 1", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM processed_events"); got != 1 {
		t.Fatalf("processed_events = %d, want 1", got)
	}
	// RecordMatch read its own in-tx write: the just-created card advanced to correlated.
	var stage string
	if err := pool.QueryRow(ctx, "SELECT stage FROM faultlines WHERE id=$1", string(id)).Scan(&stage); err != nil {
		t.Fatalf("read stage: %v", err)
	}
	if stage != "correlated" {
		t.Errorf("stage = %s, want correlated", stage)
	}

	// Redelivery: the claim conflicts, so the inner apply is NOT run again.
	if err := inbox.Handle(ctx, env); err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("inner apply ran %d times, want 1 (redelivery skipped)", inner.calls)
	}
	if got := count(t, pool, "SELECT count(*) FROM faultline_matches"); got != 1 {
		t.Errorf("matches after redelivery = %d, want 1", got)
	}
}

// TestInboxRollsBackOnApplyError proves the claim is atomic with the apply: if the inner
// Handle writes then fails, the claim AND the writes roll back, so the envelope is retry-able.
func TestInboxRollsBackOnApplyError(t *testing.T) {
	pool := newPool(t)
	st := store.New(pool)
	ctx := context.Background()

	id := domain.FaultlineID("fl-boom")
	f, err := domain.NewFaultline(id, cveID(t, "CVE-2024-101"))
	if err != nil {
		t.Fatalf("new faultline: %v", err)
	}

	inner := &recordingApply{fn: func(ctx context.Context) error {
		if err := st.Save(ctx, f, true, 0, nil); err != nil {
			return err
		}
		return errors.New("apply boom")
	}}
	inbox := store.NewInboxConsumer(pool, inner)

	if err := inbox.Handle(ctx, event.Envelope{ID: "evt-bad", Type: "EvidenceRegistered"}); err == nil {
		t.Fatal("expected apply error, got nil")
	}
	if got := count(t, pool, "SELECT count(*) FROM faultlines"); got != 0 {
		t.Errorf("faultlines = %d, want 0 (rolled back)", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM processed_events"); got != 0 {
		t.Errorf("processed_events = %d, want 0 (claim rolled back)", got)
	}
}

// TestInboxCorrelatesSharedCVEWithoutHalt is the regression for the shared-CVE correlation
// halt: when two components in one SBOM resolve to the same CVE, the second fold — inside the
// same inbox transaction — must reuse the card the first fold just created (reading its own
// in-flight write) instead of re-inserting and colliding on faultlines_cve_key. Before the fix
// GetByCVE read the pool, not the joined tx, so the second fold could not see the uncommitted
// card, re-inserted it, hit 23505, poisoned the transaction (25P02), and the stream poison-halted.
func TestInboxCorrelatesSharedCVEWithoutHalt(t *testing.T) {
	pool := newPool(t)
	svc := service(pool)
	ctx := context.Background()

	cve := cveID(t, "CVE-2024-777")
	inner := &recordingApply{fn: func(ctx context.Context) error {
		// Two components in one SBOM both resolve to CVE-2024-777, folded within one inbox tx.
		if _, err := svc.FoldProposal(ctx, cve, vulnFacts(t, "nvd", value.SeverityHigh)); err != nil {
			return err
		}
		_, err := svc.FoldProposal(ctx, cve, vulnFacts(t, "osv", value.SeverityLow))
		return err
	}}
	inbox := store.NewInboxConsumer(pool, inner)

	if err := inbox.Handle(ctx, event.Envelope{ID: "evt-shared-cve", Type: "EvidenceRegistered"}); err != nil {
		t.Fatalf("correlating an SBOM with two components sharing a CVE must not halt: %v", err)
	}
	if got := count(t, pool, "SELECT count(*) FROM faultlines"); got != 1 {
		t.Fatalf("faultlines = %d, want 1 (both components reuse one card)", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM faultline_proposals"); got != 2 {
		t.Errorf("faultline_proposals = %d, want 2 (both source proposals folded into the one card)", got)
	}
}
