package inbound_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// fakeInv records the evidence id correlation asks for and returns an empty inventory, so the
// correlation stops before touching discovery/fold/matches — enough to prove the consumer
// decoded and dispatched.
type fakeInv struct{ gotEvidenceID string }

func (f *fakeInv) GetInventory(_ context.Context, evidenceID string) (app.Inventory, error) {
	f.gotEvidenceID = evidenceID
	return app.Inventory{}, nil
}

type fakeClock struct{}

func (fakeClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func newConsumer(inv app.InventoryReader) *inbound.Consumer {
	// Empty inventory means discovery/fold/matches are never reached, so nil is safe there.
	corr := app.NewCorrelationService(inv, nil, nil, nil, fakeClock{})
	return inbound.NewConsumer(app.NewCoordinator(corr, nil))
}

func mkEnv(typ string, payload string) event.Envelope {
	return event.Envelope{Type: typ, Payload: []byte(payload)}
}

func TestConsumer_EvidenceRegistered_SBOM(t *testing.T) {
	inv := &fakeInv{}
	c := newConsumer(inv)
	env := mkEnv("EvidenceRegistered", `{"evidence_id":"ev-42","kind":"sbom","subject_release_id":"rel-42"}`)
	if err := c.Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if inv.gotEvidenceID != "ev-42" {
		t.Errorf("correlation asked for evidence %q, want ev-42 (decode of evidence_id)", inv.gotEvidenceID)
	}
}

func TestConsumer_NonSBOMIgnored(t *testing.T) {
	inv := &fakeInv{}
	c := newConsumer(inv)
	// A scanner-report is neither SBOM nor VEX — it does not correlate. (VEX now has its own
	// apply path, exercised at the app layer.)
	env := mkEnv("EvidenceRegistered", `{"evidence_id":"ev-9","kind":"scanner-report","subject_release_id":"rel-9"}`)
	if err := c.Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if inv.gotEvidenceID != "" {
		t.Errorf("a non-SBOM/non-VEX kind triggered correlation (%q)", inv.gotEvidenceID)
	}
}

func TestConsumer_UnknownTypeIgnored(t *testing.T) {
	inv := &fakeInv{}
	c := newConsumer(inv)
	if err := c.Handle(context.Background(), mkEnv("governance.finding_opened", `{}`)); err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if inv.gotEvidenceID != "" {
		t.Error("unknown type triggered correlation")
	}
}

func TestConsumer_MalformedPayload(t *testing.T) {
	c := newConsumer(&fakeInv{})
	if err := c.Handle(context.Background(), mkEnv("EvidenceRegistered", `not json`)); err == nil {
		t.Error("malformed payload for a recognized type should error (so it retries)")
	}
}

// TestConsumer_Prepare_SBOM proves the Preparer path runs the READ phase (inventory fetch)
// outside any transaction and returns a non-nil apply closure for the write phase — this is
// what keeps discovery I/O out of the inbox transaction (EDR-EVENTBUS-01 D7).
func TestConsumer_Prepare_SBOM(t *testing.T) {
	inv := &fakeInv{}
	c := newConsumer(inv)
	env := mkEnv("EvidenceRegistered", `{"evidence_id":"ev-42","kind":"sbom","subject_release_id":"rel-42"}`)
	apply, err := c.Prepare(context.Background(), env)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if apply == nil {
		t.Fatal("an SBOM must yield a non-nil apply func")
	}
	if inv.gotEvidenceID != "ev-42" {
		t.Errorf("read phase asked for evidence %q, want ev-42 (Prepare must do the read)", inv.gotEvidenceID)
	}
	// The write phase runs cleanly against an empty plan (empty inventory → no folds/matches).
	if err := apply(context.Background()); err != nil {
		t.Errorf("apply: %v", err)
	}
}

func TestConsumer_Prepare_UnknownTypeNoOp(t *testing.T) {
	c := newConsumer(&fakeInv{})
	apply, err := c.Prepare(context.Background(), mkEnv("governance.finding_opened", `{}`))
	if err != nil {
		t.Errorf("unknown type should be ignored, got %v", err)
	}
	if apply != nil {
		t.Error("an unconsumed type must yield a nil apply (no-op)")
	}
}

func TestConsumer_Prepare_MalformedPayload(t *testing.T) {
	c := newConsumer(&fakeInv{})
	if _, err := c.Prepare(context.Background(), mkEnv("EvidenceRegistered", `not json`)); err == nil {
		t.Error("malformed payload for a recognized type should error (so it retries)")
	}
}
