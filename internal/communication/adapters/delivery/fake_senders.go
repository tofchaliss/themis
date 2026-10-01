package delivery

import (
	"context"
	"errors"
	"sync"

	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// FakeMode is how a fake sender behaves, chosen per kind from the environment
// (THEMIS_DELIVERY_FAKE_{JIRA,EMAIL,CI}_MODE).
type FakeMode string

// The three fake behaviours. `flaky` fails a fixed number of times per intent and then
// succeeds — the shape a transient outage actually has, and the only one that exercises
// retry-then-recover rather than just the two endpoints.
const (
	FakeSuccess FakeMode = "success"
	FakeFail    FakeMode = "fail"
	FakeFlaky   FakeMode = "flaky"
)

// ParseFakeMode reads a configured mode, defaulting to `success` for anything unrecognized
// (including empty). A typo must not turn a node's outward actions into silent failures.
func ParseFakeMode(s string) FakeMode {
	switch FakeMode(s) {
	case FakeFail:
		return FakeFail
	case FakeFlaky:
		return FakeFlaky
	default:
		return FakeSuccess
	}
}

// defaultFlakyFailures is how many times `flaky` fails before it succeeds.
const defaultFlakyFailures = 2

// ErrFakeSend is what a fake sender returns when its configured mode says to fail. It is a
// sentinel so a test can assert the failure came from the fake and not from the plumbing.
var ErrFakeSend = errors.New("communication: fake sender refused (configured mode)")

// FakeSender stands in for the real Jira / mail / CI clients until M2 and M3 land. It
// touches no network at all, which is the point: N-M1a is about the INTENT record, the
// worker lifecycle and the operator's ability to see and re-drive a failure — all of which
// are fully exercisable, and much better exercised, without a real endpoint's flakiness in
// the loop.
//
// It is safe for concurrent use: one instance is shared by a worker and, in tests, by the
// assertions that read its call log.
type FakeSender struct {
	kind          domain.DeliveryKind
	mode          FakeMode
	flakyFailures int
	logger        *observability.Logger

	mu    sync.Mutex
	calls map[string]int
	sent  []string
}

// NewFakeSender builds a fake sender for one kind. A nil logger falls back to a no-op.
func NewFakeSender(kind domain.DeliveryKind, mode FakeMode, logger *observability.Logger) *FakeSender {
	if logger == nil {
		logger = observability.Nop()
	}
	return &FakeSender{
		kind: kind, mode: mode, flakyFailures: defaultFlakyFailures,
		logger: logger, calls: map[string]int{},
	}
}

// WithFlakyFailures sets how many times `flaky` fails per intent before succeeding, and
// returns the sender for chaining.
func (f *FakeSender) WithFlakyFailures(n int) *FakeSender {
	f.flakyFailures = n
	return f
}

// Send applies the configured behaviour and records the call. Every outcome is logged
// through the shared logger (R1 — console + OTel from one call), because "the fake refused"
// and "the channel is misconfigured" must not look the same in an operator's log.
func (f *FakeSender) Send(_ context.Context, intent domain.DeliveryIntent) error {
	f.mu.Lock()
	f.calls[intent.ID()]++
	n := f.calls[intent.ID()]
	fail := f.mode == FakeFail || (f.mode == FakeFlaky && n <= f.flakyFailures)
	if !fail {
		f.sent = append(f.sent, intent.ID())
	}
	f.mu.Unlock()

	fields := []observability.Field{
		observability.String("intent_id", intent.ID()),
		observability.String("kind", string(intent.Kind())),
		observability.String("destination", intent.Destination()),
		observability.String("mode", string(f.mode)),
		observability.Int("call", n),
	}
	if fail {
		f.logger.Warn("FAKE sender refused delivery (no real channel is wired yet)", fields...)
		return ErrFakeSend
	}
	f.logger.Info("FAKE sender accepted delivery (no real channel is wired yet)", fields...)
	return nil
}

// Calls returns how many times this sender was asked to send the given intent.
func (f *FakeSender) Calls(intentID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[intentID]
}

// Sent returns the intent ids this sender accepted, in order.
func (f *FakeSender) Sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sent...)
}
