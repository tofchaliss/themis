package eventbus_test

import (
	"testing"

	"github.com/themis-project/themis/internal/platform/eventbus"
)

func TestSubscription_InInterest(t *testing.T) {
	s := eventbus.Subscription{Consumer: "c", Stream: "up", Interest: []string{"a.type", "b.type"}}
	if !s.InInterest("a.type") || !s.InInterest("b.type") {
		t.Error("declared interest types should be in-interest")
	}
	if s.InInterest("c.type") || s.InInterest("") {
		t.Error("undeclared types should be out-of-interest")
	}
	// An empty interest set matches nothing.
	if (eventbus.Subscription{}).InInterest("a.type") {
		t.Error("empty interest set should match nothing")
	}
}
