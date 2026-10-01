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
	// Two Position facts drive the publishable worklist (Positions only — DOM-0025); two
	// lifecycle facts drive the outward-action intents (N-M1a). Widening the interest set is
	// what made delivery possible at all: an event outside it never reaches Handle.
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
	// A Governance lifecycle event Communication still does not consume is out of interest.
	if s.InInterest("governance.proposal_rejected") {
		t.Error("proposal_rejected must be out of interest")
	}
}
