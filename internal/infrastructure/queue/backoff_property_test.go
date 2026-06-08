package queue_test

import (
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/infrastructure/queue"
)

func TestBackoffDelayProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Bound base at the cap: BackoffDelay returns base uncapped for attempt<=1,
		// so a base above the cap would legitimately exceed it.
		baseNanos := rapid.Int64Range(1, int64(time.Hour)).Draw(t, "base_nanos")
		base := time.Duration(baseNanos)
		attempt := rapid.IntRange(-5, 40).Draw(t, "attempt")

		delay := queue.BackoffDelay(base, attempt)
		if delay < 0 {
			t.Fatalf("negative delay %v (base=%v attempt=%d)", delay, base, attempt)
		}
		if delay > time.Hour {
			t.Fatalf("delay %v exceeds cap (base=%v attempt=%d)", delay, base, attempt)
		}
		if attempt <= 1 && delay != base {
			t.Fatalf("attempt<=1 delay=%v want base=%v", delay, base)
		}
	})
}

func TestBackoffDelayMonotonicProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		baseNanos := rapid.Int64Range(1, int64(time.Minute)).Draw(t, "base_nanos")
		base := time.Duration(baseNanos)
		a := rapid.IntRange(1, 40).Draw(t, "attempt_a")
		b := rapid.IntRange(a, 40).Draw(t, "attempt_b")

		da := queue.BackoffDelay(base, a)
		db := queue.BackoffDelay(base, b)
		if da > db {
			t.Fatalf("non-monotonic: attempt %d=%v > attempt %d=%v (base=%v)", a, da, b, db, base)
		}
	})
}

func TestBackoffDelayNonPositiveBaseProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		baseNanos := rapid.Int64Range(int64(-time.Hour), 0).Draw(t, "base_nanos")
		attempt := rapid.IntRange(-5, 40).Draw(t, "attempt")
		if got := queue.BackoffDelay(time.Duration(baseNanos), attempt); got != 0 {
			t.Fatalf("non-positive base should yield 0, got %v", got)
		}
	})
}
