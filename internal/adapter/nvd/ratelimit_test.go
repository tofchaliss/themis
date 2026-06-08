package nvd_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/nvd"
)

func TestTokenBucketWaitsWhenEmpty(t *testing.T) {
	tb := nvd.NewTokenBucket(1, 1)
	_ = tb.Wait(context.Background())

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tb.Wait(ctx); err != nil {
		t.Fatalf("Wait() error = %v", err)
	}
	if elapsed := time.Since(start); elapsed < 50*time.Millisecond {
		t.Fatalf("expected rate limit delay, elapsed = %v", elapsed)
	}
}

func TestTokenBucketContextCancel(t *testing.T) {
	tb := nvd.NewTokenBucket(1, 1)
	_ = tb.Wait(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := tb.Wait(ctx); err == nil {
		t.Fatal("expected context error")
	}
}
