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
	return inbound.NewConsumer(app.NewCoordinator(corr))
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
	env := mkEnv("EvidenceRegistered", `{"evidence_id":"ev-9","kind":"vex","subject_release_id":"rel-9"}`)
	if err := c.Handle(context.Background(), env); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if inv.gotEvidenceID != "" {
		t.Errorf("non-SBOM evidence triggered correlation (%q)", inv.gotEvidenceID)
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
