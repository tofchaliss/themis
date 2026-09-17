package inbound_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/adapters/inbound"
)

func TestSubscription(t *testing.T) {
	s := inbound.Subscription
	if s.Consumer != "governance" || s.Stream != "knowledge" {
		t.Errorf("subscription = %+v, want consumer=governance stream=knowledge", s)
	}
	// The interest set is exactly the Faultline facts the Consumer dispatches on (the
	// per-type dispatch + UnknownTypeIgnored tests prove Handle matches this set).
	for _, want := range []string{
		"knowledge.component_matched", "knowledge.component_verdict_changed",
		"knowledge.component_retired", // KN-SCAN-4(b)
		"knowledge.faultline_enriched", "knowledge.faultline_superseded",
	} {
		if !s.InInterest(want) {
			t.Errorf("interest set missing %s", want)
		}
	}
	// The COUNT is asserted deliberately: adding a type to Handle without adding it here means
	// the stream reader filters the event out and the dispatch is dead code, which is silent.
	if len(s.Interest) != 5 {
		t.Errorf("interest set = %v, want 5 types", s.Interest)
	}
	// A Knowledge event Governance does not consume is out of interest.
	if s.InInterest("knowledge.faultline_created") {
		t.Error("faultline_created must be out of interest")
	}
}
