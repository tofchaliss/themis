package nvd

import (
	"context"
	"sync"
	"time"
)

// TokenBucket limits request rate using a classic token-bucket algorithm.
type TokenBucket struct {
	rate      float64
	capacity  float64
	tokens    float64
	last      time.Time
	mu        sync.Mutex
	now       func() time.Time
	sleep     func(context.Context, time.Duration) error
}

// NewTokenBucket creates a limiter allowing rate tokens per second up to capacity.
func NewTokenBucket(rate float64, capacity float64) *TokenBucket {
	if rate <= 0 {
		rate = 1
	}
	if capacity <= 0 {
		capacity = rate
	}
	return &TokenBucket{
		rate:     rate,
		capacity: capacity,
		tokens:   capacity,
		last:     time.Now(),
		now:      time.Now,
		sleep:    sleepContext,
	}
}

// Wait blocks until a token is available or the context is cancelled.
func (tb *TokenBucket) Wait(ctx context.Context) error {
	for {
		wait, ok := tb.reserve()
		if ok {
			return nil
		}
		if err := tb.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

func (tb *TokenBucket) reserve() (time.Duration, bool) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := tb.now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.last = now

	if tb.tokens >= 1 {
		tb.tokens--
		return 0, true
	}

	deficit := 1 - tb.tokens
	wait := time.Duration(deficit/tb.rate*float64(time.Second)) + time.Millisecond
	return wait, false
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
