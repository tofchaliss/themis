package wiring_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/wiring"
	"github.com/themis-project/themis/internal/kernel/event"
)

// The outward-delivery toggle, asserted at the composition root: with it off there is no
// worker AND the event reader records no intents (the consumer is left without the intake),
// so a node that will not send cannot accumulate a queue nobody drains.
func TestWireDeliveryDisabled(t *testing.T) {
	comm := wiring.Communication{Consumer: inbound.NewConsumer(nil)}
	if w := wiring.WireDelivery(comm, delivery.Config{Enabled: false}, nil); w != nil {
		t.Fatal("a disabled configuration must wire no worker")
	}
	// The consumer has no intake, so a delivery trigger is inert — not a panic, not a write.
	env := event.Envelope{ID: "env-1", Type: "governance.finding_opened", SourceContext: "governance",
		Payload: []byte(`{"FindingID":"fnd-1","ReleaseID":"rel-1"}`)}
	if err := comm.Consumer.Handle(context.Background(), env); err != nil {
		t.Errorf("handle with delivery off: %v", err)
	}
}

func TestWireDeliveryEnabled(t *testing.T) {
	comm := wiring.Communication{Consumer: inbound.NewConsumer(nil)}
	if w := wiring.WireDelivery(comm, delivery.Config{Enabled: true}, nil); w == nil {
		t.Fatal("an enabled configuration must wire a worker")
	}
}
