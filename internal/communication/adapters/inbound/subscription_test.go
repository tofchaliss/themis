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
	// Positions only (DOM-0025): the interest set is the two Position facts.
	for _, want := range []string{"governance.position_established", "governance.position_revised"} {
		if !s.InInterest(want) {
			t.Errorf("interest set missing %s", want)
		}
	}
	if len(s.Interest) != 2 {
		t.Errorf("interest set = %v, want 2 types", s.Interest)
	}
	// A Governance lifecycle event Communication does not consume is out of interest.
	if s.InInterest("governance.finding_opened") {
		t.Error("finding_opened must be out of interest")
	}
}
