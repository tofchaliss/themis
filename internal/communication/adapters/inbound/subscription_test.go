package inbound_test

import (
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/inbound"
)

func TestSubscription(t *testing.T) {
	s := inbound.Subscription
	if s.Consumer != "communication" || s.Stream != "governance" {
		t.Errorf("subscription = %+v, want consumer=communication stream=governance", s)
	}
	// The two Position facts drive the publishable worklist (Positions only — DOM-0025); the
	// two delivery triggers drive outward-delivery intents (N-M1a).
	for _, want := range []string{
		"governance.position_established", "governance.position_revised",
		"governance.finding_opened", "governance.proposal_accepted",
	} {
		if !s.InInterest(want) {
			t.Errorf("interest set missing %s", want)
		}
	}
	if len(s.Interest) != 4 {
		t.Errorf("interest set = %v, want 4 types", s.Interest)
	}
	// A Governance lifecycle event Communication does not consume is out of interest.
	if s.InInterest("governance.finding_resolved") {
		t.Error("finding_resolved must be out of interest")
	}
}
