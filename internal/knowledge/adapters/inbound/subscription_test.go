package inbound_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/inbound"
)

func TestSubscription(t *testing.T) {
	s := inbound.Subscription
	if s.Consumer != "knowledge" || s.Stream != "evidence" {
		t.Errorf("subscription = %+v, want consumer=knowledge stream=evidence", s)
	}
	if !s.InInterest("EvidenceRegistered") {
		t.Error("interest set must include EvidenceRegistered")
	}
	if len(s.Interest) != 1 {
		t.Errorf("interest set = %v, want 1 type", s.Interest)
	}
	if s.InInterest("evidence.something_else") {
		t.Error("only EvidenceRegistered is in interest")
	}
}
