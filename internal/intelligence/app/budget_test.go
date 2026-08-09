package app_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/app"
)

var t0 = time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)

// Unlimited is the DEFAULT and must stay the default. A budget switched on by accident refuses
// recommendations, and a refusal is indistinguishable from the AI being unavailable to everyone
// downstream (D13) — so enforcement is opt-in, and a half-configured deployment enforces nothing
// rather than something nobody asked for.
func TestBudgetDisabledByDefault(t *testing.T) {
	for _, b := range []*app.Budget{
		app.NewBudget(0, time.Hour),    // no limit
		app.NewBudget(100, 0),          // no window
		app.NewBudget(-1, time.Hour),   // nonsense limit
		app.NewBudget(100, -time.Hour), // nonsense window
		nil,                            // never wired
	} {
		if b.Enabled() {
			t.Errorf("budget %+v reports enabled, want disabled", b)
		}
		if !b.Allow(t0) {
			t.Error("a disabled budget must admit everything")
		}
		if got := b.Remaining(t0); got != -1 {
			t.Errorf("Remaining = %d, want -1 (unlimited)", got)
		}
		b.Debit(t0, 5_000) // must not panic or start enforcing
		if !b.Allow(t0) {
			t.Error("a disabled budget must stay unlimited after a debit")
		}
	}
}

func TestBudgetAdmitsUntilExhausted(t *testing.T) {
	b := app.NewBudget(1000, time.Hour)
	if !b.Enabled() {
		t.Fatal("a configured budget must be enabled")
	}
	if !b.Allow(t0) || b.Remaining(t0) != 1000 {
		t.Fatalf("fresh budget: allow=%v remaining=%d", b.Allow(t0), b.Remaining(t0))
	}
	b.Debit(t0, 400)
	if !b.Allow(t0) || b.Remaining(t0) != 600 {
		t.Errorf("after 400: allow=%v remaining=%d, want true/600", b.Allow(t0), b.Remaining(t0))
	}
	// Admission is on REMAINING > 0, not on remaining >= an estimate: a call's cost is unknowable
	// until it returns. The last admitted call may overshoot by one invocation, which is a far
	// better failure than refusing work on a number we invented.
	b.Debit(t0, 900) // total 1300, past the ceiling
	if b.Allow(t0) {
		t.Error("an exhausted budget must refuse")
	}
	if got := b.Remaining(t0); got != 0 {
		t.Errorf("Remaining = %d, want 0 — never negative", got)
	}
}

func TestBudgetRollsOnAFixedWindow(t *testing.T) {
	b := app.NewBudget(1000, time.Hour)
	b.Debit(t0, 1200)
	if b.Allow(t0.Add(59 * time.Minute)) {
		t.Error("the window must not roll early")
	}
	if !b.Allow(t0.Add(time.Hour)) {
		t.Error("the window must roll at its duration")
	}
	if got := b.Remaining(t0.Add(time.Hour)); got != 1000 {
		t.Errorf("Remaining after roll = %d, want a full window", got)
	}
}

// The window is anchored to the FIRST call, not to a wall-clock boundary. Anchoring to the clock
// would give a node restarted at 13:59 a full budget twice in two minutes, turning a restart loop
// into a budget bypass.
func TestBudgetWindowAnchorsToFirstUse(t *testing.T) {
	b := app.NewBudget(1000, time.Hour)
	late := t0.Add(55 * time.Minute) // first ever call, well into the wall-clock hour
	b.Debit(late, 1200)
	if b.Allow(late.Add(5 * time.Minute)) {
		t.Error("rolled at the wall-clock hour rather than one window after first use")
	}
	if !b.Allow(late.Add(time.Hour)) {
		t.Error("must roll one full window after first use")
	}
}

// A zero-cost debit is a no-op: some providers report no token count, and that must not silently
// consume budget nor reset anything.
func TestBudgetIgnoresZeroCost(t *testing.T) {
	b := app.NewBudget(100, time.Hour)
	b.Debit(t0, 0)
	b.Debit(t0, -5)
	if got := b.Remaining(t0); got != 100 {
		t.Errorf("Remaining = %d, want 100 — a zero/negative cost must not debit", got)
	}
}
