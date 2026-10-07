package wiring_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/wiring"
	"github.com/themis-project/themis/internal/communication/app"
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

// The N-M1b senders are selected here too: an enabled, completely-configured Jira still yields one
// worker (the selection itself is asserted in the delivery package, where it lives), and a posture
// read seam turns on payload materialization without changing the switch above.
func TestWireDeliveryWithTheRealSendersAndTheRenderer(t *testing.T) {
	cfg := delivery.Config{
		Enabled: true,
		Jira: delivery.JiraConfig{Enabled: true, BaseURL: "https://acme.atlassian.net",
			ProjectKey: "SEC", User: "bot@acme.example", APIToken: "token"},
		Mail: delivery.MailConfig{Enabled: true, Host: "relay.acme.example", From: "themis@acme.example",
			StartTLS: true, Audiences: map[string][]string{"operations": {"ops@acme.example"}}},
	}
	comm := wiring.Communication{Consumer: inbound.NewConsumer(nil), Posture: stubPosture{}}
	if w := wiring.WireDelivery(comm, cfg, nil); w == nil {
		t.Fatal("an enabled configuration with real senders must wire a worker")
	}
}

// stubPosture stands in for Governance's release-posture read seam.
type stubPosture struct{}

func (stubPosture) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	return nil, nil
}
