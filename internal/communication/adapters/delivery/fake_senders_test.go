package delivery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

func fakeIntent(t *testing.T, id string) domain.DeliveryIntent {
	t.Helper()
	in, err := domain.NewDeliveryIntent(id, domain.DeliveryEmail, "default", domain.DeliveryOrigin{
		EventID: "env-1", EventType: "governance.proposal_accepted", EventTime: workerEpoch, FindingID: "fnd-1",
	}, 3, workerEpoch)
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	return in
}

// A typo in a mode must not turn a node's outward actions into silent failures, so anything
// unrecognized reads as `success` rather than as `fail`.
func TestParseFakeMode(t *testing.T) {
	for in, want := range map[string]delivery.FakeMode{
		"success":  delivery.FakeSuccess,
		"fail":     delivery.FakeFail,
		"flaky":    delivery.FakeFlaky,
		"":         delivery.FakeSuccess,
		"FAIL":     delivery.FakeSuccess, // not the documented spelling — not a refusal either
		"nonsense": delivery.FakeSuccess,
	} {
		if got := delivery.ParseFakeMode(in); got != want {
			t.Errorf("ParseFakeMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFakeSender_Modes(t *testing.T) {
	ctx := context.Background()
	intent := fakeIntent(t, "int-1")

	ok := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, observability.Nop())
	if err := ok.Send(ctx, intent); err != nil {
		t.Errorf("success mode returned %v", err)
	}
	if got := ok.Sent(); len(got) != 1 || got[0] != "int-1" {
		t.Errorf("sent = %v", got)
	}

	bad := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeFail, nil)
	if err := bad.Send(ctx, intent); !errors.Is(err, delivery.ErrFakeSend) {
		t.Errorf("fail mode returned %v, want ErrFakeSend", err)
	}
	if got := bad.Sent(); len(got) != 0 {
		t.Errorf("fail mode recorded a send: %v", got)
	}
	if bad.Calls("int-1") != 1 {
		t.Errorf("calls = %d, want 1", bad.Calls("int-1"))
	}
}

// Flaky counts per INTENT, not globally: two intents against one recovering channel must
// each get their own run of failures, or a test would pass for the wrong reason.
func TestFakeSender_FlakyIsPerIntent(t *testing.T) {
	ctx := context.Background()
	s := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeFlaky, nil).WithFlakyFailures(1)
	a, b := fakeIntent(t, "int-a"), fakeIntent(t, "int-b")

	if err := s.Send(ctx, a); err == nil {
		t.Error("first call for int-a should fail")
	}
	if err := s.Send(ctx, b); err == nil {
		t.Error("first call for int-b should fail — the counter is per intent")
	}
	if err := s.Send(ctx, a); err != nil {
		t.Errorf("second call for int-a = %v, want success", err)
	}
	if got := s.Sent(); len(got) != 1 || got[0] != "int-a" {
		t.Errorf("sent = %v, want [int-a]", got)
	}
}

// The fakes touch no network at all, which is what makes them usable in the unit gate: a
// send is over the moment it is asked for.
func TestFakeSender_IsInstant(t *testing.T) {
	start := time.Now()
	s := delivery.NewFakeSender(domain.DeliveryCIBuild, delivery.FakeSuccess, nil)
	for i := 0; i < 100; i++ {
		if err := s.Send(context.Background(), fakeIntent(t, "int-1")); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("100 fake sends took %v — something is doing I/O", elapsed)
	}
}
