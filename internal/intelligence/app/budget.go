package app

import (
	"sync"
	"time"
)

// Budget enforces D4's per-capability spend ceiling over a fixed window.
//
// Δ2 shipped the METER only: every call records its tokens, and the per-run runaway guard caps a
// single prompt. Nothing capped the AGGREGATE, so a loop of invocations — a retrying script, a
// scheduled job, an autonomous engine when Δ4 lands — could consume the model indefinitely. On a
// local model the currency is GPU time rather than money, which makes exhaustion a denial of the
// pipeline rather than a bill.
//
// A FIXED window, not a sliding one, because D4 asks for predictability first: an operator can
// answer "how much can this spend by 14:00" without simulating request arrival. A sliding window
// is smoother and strictly harder to reason about, and nothing here needs smooth.
//
// Zero limit means UNLIMITED, which is the default. Enforcement must be opt-in: a budget switched
// on by accident would refuse recommendations, and a refusal is indistinguishable from the AI
// being unavailable to everyone downstream (D13). Off is the safe default; on is a decision.
type Budget struct {
	mu     sync.Mutex
	limit  int           // tokens per window; 0 = unlimited
	window time.Duration // 0 = unlimited
	spent  int
	start  time.Time // beginning of the current window
}

// NewBudget builds a per-capability budget. A non-positive limit or window disables enforcement
// entirely, so a partially-configured deployment behaves exactly as an unconfigured one rather
// than half-enforcing something nobody asked for.
func NewBudget(limit int, window time.Duration) *Budget {
	if limit <= 0 || window <= 0 {
		return &Budget{}
	}
	return &Budget{limit: limit, window: window}
}

// Enabled reports whether this budget enforces anything.
func (b *Budget) Enabled() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.limit > 0
}

// Allow reports whether a call may proceed, rolling the window over first when it has expired.
//
// It admits on REMAINING > 0 rather than on remaining >= an estimate, because the cost of a call
// is not knowable until it returns. The consequence is deliberate: the last admitted call may
// overshoot the ceiling by up to one invocation. Overshooting once is a far better failure than
// refusing work on a guess, and the alternative — estimating tokens from prompt length — would
// reject calls for a number it invented.
func (b *Budget) Allow(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		return true
	}
	b.rollLocked(now)
	return b.spent < b.limit
}

// Debit records what a completed call actually cost. Called post-invocation with the provider's
// reported tokens, so the ledger reflects real consumption rather than an estimate.
func (b *Budget) Debit(now time.Time, tokens int) {
	if b == nil || tokens <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		return
	}
	b.rollLocked(now)
	b.spent += tokens
}

// Remaining reports the tokens left in the current window; -1 when unlimited. Exposed so the
// operator-facing reason can say how long the pause lasts instead of only that it happened.
func (b *Budget) Remaining(now time.Time) int {
	if b == nil {
		return -1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.limit <= 0 {
		return -1
	}
	b.rollLocked(now)
	if rem := b.limit - b.spent; rem > 0 {
		return rem
	}
	return 0
}

// rollLocked starts a fresh window when the current one has elapsed. The caller holds the lock.
//
// The window is anchored to the FIRST call, not to a wall-clock boundary: a node restarted at
// 13:59 would otherwise get a full budget twice in two minutes, which turns a restart loop into a
// budget bypass.
func (b *Budget) rollLocked(now time.Time) {
	if b.start.IsZero() {
		b.start = now
		return
	}
	if now.Sub(b.start) >= b.window {
		b.start = now
		b.spent = 0
	}
}
