package eventbus

import (
	"context"
	"testing"
	"time"
)

func TestNewReader_AppliesDefaults(t *testing.T) {
	r := NewReader(nil, nil, ReaderConfig{Consumer: "c", Stream: "s"}, nil)
	if r.batchSize != defaultReaderBatch || r.maxAttempts != defaultMaxAttempts || r.baseBackoff != defaultBaseBackoff {
		t.Errorf("defaults not applied: batch=%d attempts=%d backoff=%s",
			r.batchSize, r.maxAttempts, r.baseBackoff)
	}
	// Explicit values are preserved.
	r2 := NewReader(nil, nil, ReaderConfig{BatchSize: 7, MaxAttempts: 2, BaseBackoff: time.Second}, nil)
	if r2.batchSize != 7 || r2.maxAttempts != 2 || r2.baseBackoff != time.Second {
		t.Errorf("explicit config overridden: batch=%d attempts=%d backoff=%s",
			r2.batchSize, r2.maxAttempts, r2.baseBackoff)
	}
}

func TestBackoffFor_DoublesAndCaps(t *testing.T) {
	r := &Reader{baseBackoff: 100 * time.Millisecond}
	for attempt, want := range map[int]time.Duration{
		1: 100 * time.Millisecond,
		2: 200 * time.Millisecond,
		3: 400 * time.Millisecond,
	} {
		if got := r.backoffFor(attempt); got != want {
			t.Errorf("backoffFor(%d) = %s, want %s", attempt, got, want)
		}
	}
	// A large base × shift overflows/exceeds the cap → clamped to maxBackoff.
	big := &Reader{baseBackoff: 20 * time.Second}
	if got := big.backoffFor(5); got != maxBackoff {
		t.Errorf("backoffFor(5) with 20s base = %s, want cap %s", got, maxBackoff)
	}
}

func TestSleepCtx(t *testing.T) {
	// Non-positive duration does not sleep and returns the context's (nil) error.
	if err := sleepCtx(context.Background(), 0); err != nil {
		t.Errorf("sleepCtx(0) = %v, want nil", err)
	}
	// A short positive sleep completes.
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleepCtx(1ms) = %v, want nil", err)
	}
	// A cancelled context returns its error without waiting out the duration.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err == nil {
		t.Error("sleepCtx with cancelled ctx = nil, want context error")
	}
}
