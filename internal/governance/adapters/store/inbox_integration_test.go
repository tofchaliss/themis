//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/adapters/wiring"
	"github.com/themis-project/themis/internal/kernel/event"
)

type noopPublisher struct{}

func (noopPublisher) Publish(context.Context, event.Envelope) error { return nil }

func envFor(t *testing.T, id, typ string, payload any) event.Envelope {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal %s: %v", id, err)
	}
	e, err := event.NewEnvelope(id, typ, "knowledge", "fl-1", typ+".v1", "fl-1",
		time.Unix(1_700_000_000, 0).UTC(), raw)
	if err != nil {
		t.Fatalf("envelope %s: %v", id, err)
	}
	return e
}

// TestInboxExactlyOnceApplication proves EB-06/D5: a redelivered envelope (the transport is
// at-least-once) applies exactly once. It uses a non-idempotent apply — a FaultlineEnriched
// raises a system proposal (append) — so a second delivery WITHOUT the inbox would create a
// duplicate proposal; with it, the redelivery is a no-op.
func TestInboxExactlyOnceApplication(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	gov := wiring.Wire(pool, noopPublisher{}, nil, "", "", 0, 0, 0)
	inbox := store.NewInboxConsumer(pool, gov.Consumer)

	// A ComponentMatched opens the (Release, Faultline) Finding the enrichment reacts to.
	match := envFor(t, "evt-match", "knowledge.component_matched", struct {
		FaultlineID string
		CVE         string
		ReleaseID   string
		Components  []struct{ PURL, Name, Version, Ecosystem string }
	}{
		FaultlineID: "fl-1", CVE: "CVE-2024-1", ReleaseID: "rel-1",
		Components: []struct{ PURL, Name, Version, Ecosystem string }{{"pkg:deb/debian/openssl@3", "openssl", "3", "deb"}},
	})
	if err := inbox.Handle(ctx, match); err != nil {
		t.Fatalf("apply match: %v", err)
	}
	if got := count(t, pool, "SELECT count(*) FROM findings"); got != 1 {
		t.Fatalf("findings after match = %d, want 1", got)
	}
	proposalsAfterMatch := count(t, pool, "SELECT count(*) FROM finding_proposals")

	// A high-severity FaultlineEnriched raises a re-prioritize proposal (non-idempotent).
	enrich := envFor(t, "evt-enrich", "knowledge.faultline_enriched", struct {
		FaultlineID   string
		CVE           string
		Severity      string
		KEV           bool
		ExploitPublic bool
	}{FaultlineID: "fl-1", CVE: "CVE-2024-1", Severity: "high"})
	if err := inbox.Handle(ctx, enrich); err != nil {
		t.Fatalf("apply enrich: %v", err)
	}
	proposalsAfterEnrich := count(t, pool, "SELECT count(*) FROM finding_proposals")
	if proposalsAfterEnrich <= proposalsAfterMatch {
		t.Fatalf("enrichment raised no proposal (%d -> %d)", proposalsAfterMatch, proposalsAfterEnrich)
	}
	if got := count(t, pool, "SELECT count(*) FROM processed_events"); got != 2 {
		t.Fatalf("processed_events = %d, want 2 (match + enrich)", got)
	}

	// Redeliver the SAME enrichment envelope: exactly-once application means no new proposal.
	if err := inbox.Handle(ctx, enrich); err != nil {
		t.Fatalf("redeliver enrich: %v", err)
	}
	if got := count(t, pool, "SELECT count(*) FROM finding_proposals"); got != proposalsAfterEnrich {
		t.Errorf("redelivery duplicated proposals: %d -> %d", proposalsAfterEnrich, got)
	}
	if got := count(t, pool, "SELECT count(*) FROM processed_events"); got != 2 {
		t.Errorf("processed_events after redelivery = %d, want 2", got)
	}
}

// TestInboxRolledBackOnApplyError proves the claim is atomic with the apply: if the inner
// Handle fails, the envelope id is NOT recorded, so a later redelivery retries rather than
// being wrongly treated as already-applied. A malformed payload for a recognized type is a
// real apply error.
func TestInboxRolledBackOnApplyError(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	gov := wiring.Wire(pool, noopPublisher{}, nil, "", "", 0, 0, 0)
	inbox := store.NewInboxConsumer(pool, gov.Consumer)

	bad := event.Envelope{ID: "evt-bad", Type: "knowledge.component_matched", Payload: json.RawMessage(`not json`)}
	if err := inbox.Handle(ctx, bad); err == nil {
		t.Fatal("expected apply error for malformed payload, got nil")
	}
	if got := count(t, pool, "SELECT count(*) FROM processed_events"); got != 0 {
		t.Errorf("failed apply left %d inbox rows, want 0 (claim rolled back)", got)
	}
}

// TestInboxTwoMutationsOnOneFindingConverge is the regression for BUG-1 (the Governance
// poison-halt): a single faultline_enriched that BOTH re-prioritizes (high severity) AND folds
// a not_affected VEX applicability mutates the SAME Finding twice within one inbox transaction.
// The aggregate reads must join that transaction (Store.querier) so the 2nd mutate's GetByID
// sees the 1st's in-flight version bump and Save converges. Before the fix the 2nd mutate read
// committed data on the pool, missed the uncommitted version, and ErrConcurrent never resolved
// across the retry budget — the reader poison-halted the whole stream (D8). Handle must return
// nil and both proposals (affected re-prioritize + not_affected suppression) must land.
func TestInboxTwoMutationsOnOneFindingConverge(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	gov := wiring.Wire(pool, noopPublisher{}, nil, "", "", 0, 0, 0)
	inbox := store.NewInboxConsumer(pool, gov.Consumer)

	// Open the Finding the enrichment will mutate twice.
	match := envFor(t, "evt-match", "knowledge.component_matched", struct {
		FaultlineID string
		CVE         string
		ReleaseID   string
		Components  []struct{ PURL, Name, Version, Ecosystem string }
	}{
		FaultlineID: "fl-1", CVE: "CVE-2024-1", ReleaseID: "rel-1",
		Components: []struct{ PURL, Name, Version, Ecosystem string }{{"pkg:deb/debian/openssl@3", "openssl", "3", "deb"}},
	})
	if err := inbox.Handle(ctx, match); err != nil {
		t.Fatalf("apply match: %v", err)
	}
	before := count(t, pool, "SELECT count(*) FROM finding_proposals")

	// One enrichment that triggers BOTH mutate paths on the one Finding: high severity raises a
	// re-prioritize proposal, and a not_affected applicability whose package covers the
	// component raises a system suppression proposal.
	enrich := envFor(t, "evt-enrich", "knowledge.faultline_enriched", struct {
		FaultlineID     string
		CVE             string
		Severity        string
		Score           int
		Applicabilities []struct{ Package, Status, Justification string }
	}{
		FaultlineID: "fl-1", CVE: "CVE-2024-1", Severity: "high", Score: 70,
		Applicabilities: []struct{ Package, Status, Justification string }{
			{"pkg:deb/debian/openssl", "not_affected", "vulnerable_code_not_present"},
		},
	})
	// The regression: before the fix this returned ErrConcurrent (D8 poison-halt); now it converges.
	if err := inbox.Handle(ctx, enrich); err != nil {
		t.Fatalf("enrichment with re-prioritize + applicability halted the stream (BUG-1): %v", err)
	}

	// Both mutate paths landed their proposals on the one Finding.
	if got := count(t, pool, "SELECT count(*) FROM finding_proposals") - before; got < 2 {
		t.Fatalf("expected 2 new proposals (affected re-prioritize + not_affected suppression), got %d", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM finding_proposals WHERE stance = 'not_affected'"); got != 1 {
		t.Fatalf("system not_affected proposal not raised (got %d)", got)
	}
	if got := count(t, pool, "SELECT count(*) FROM finding_proposals WHERE stance = 'affected'"); got != 1 {
		t.Fatalf("re-prioritize affected proposal not raised (got %d)", got)
	}
}

// TestInboxComponentMatchedStampsBaseScore is the regression for BUG-3: a component_matched
// carries the card's score, so Governance stamps base_score on the Finding at open — a Finding
// born on an already-enriched card is not stranded at 0 waiting for a faultline_enriched it may
// never receive. Before the fix the finding was created at base_score 0 and only SetBaseScore
// (on enrichment) could lift it.
func TestInboxComponentMatchedStampsBaseScore(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()

	gov := wiring.Wire(pool, noopPublisher{}, nil, "", "", 0, 0, 0)
	inbox := store.NewInboxConsumer(pool, gov.Consumer)

	match := envFor(t, "evt-match-scored", "knowledge.component_matched", struct {
		FaultlineID string
		CVE         string
		ReleaseID   string
		Score       int
		Components  []struct{ PURL, Name, Version, Ecosystem string }
	}{
		FaultlineID: "fl-9", CVE: "CVE-2024-9", ReleaseID: "rel-9", Score: 90,
		Components: []struct{ PURL, Name, Version, Ecosystem string }{{"pkg:deb/debian/x@1", "x", "1", "deb"}},
	})
	if err := inbox.Handle(ctx, match); err != nil {
		t.Fatalf("apply match: %v", err)
	}
	if got := count(t, pool, "SELECT coalesce(max(base_score),0) FROM findings WHERE faultline_id='fl-9'"); got != 90 {
		t.Fatalf("base_score at finding-open = %d, want 90 (BUG-3: the score must ride the match)", got)
	}
}
