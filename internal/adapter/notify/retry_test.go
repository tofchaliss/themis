package notify

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	if backoffDelay(0, 2) != 0 {
		t.Fatal("zero base")
	}
	if backoffDelay(-time.Second, 3) != 0 {
		t.Fatal("negative base")
	}
	if backoffDelay(15*time.Second, 3) != 60*time.Second {
		t.Fatal("uncapped delay return")
	}
	if backoffDelay(10*time.Minute, 3) != 40*time.Minute {
		t.Fatal("single loop multiply")
	}
	if backoffDelay(time.Second, 1) != time.Second {
		t.Fatal("first attempt")
	}
	if backoffDelay(time.Second, 2) != 2*time.Second {
		t.Fatal("second attempt")
	}
	if backoffDelay(time.Second, 3) != 4*time.Second {
		t.Fatal("exponential growth")
	}
	if backoffDelay(45*time.Minute, 3) != time.Hour {
		t.Fatal("cap inside loop")
	}
	if backoffDelay(90*time.Minute, 2) != time.Hour {
		t.Fatal("cap after multiply")
	}
	if backoffDelay(30*time.Minute, 4) != time.Hour {
		t.Fatal("cap after multiple multiplies")
	}
	if backoffDelay(2*time.Hour, 2) != time.Hour {
		t.Fatal("cap when doubled base exceeds one hour")
	}
	if backoffDelay(time.Second, 0) != time.Second {
		t.Fatal("non-positive attempt uses base delay")
	}
	if backoffDelay(40*time.Minute, 4) != time.Hour {
		t.Fatal("final delay cap after multiple doublings")
	}
	if backoffDelay(2*time.Hour, 5) != time.Hour {
		t.Fatal("cap at one hour")
	}
}

func TestWithRetrySuccess(t *testing.T) {
	calls := 0
	err := withRetry(context.Background(), 2, time.Millisecond, func(time.Duration) {}, nil, func() error {
		calls++
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestWithRetryFailure(t *testing.T) {
	retries := 0
	err := withRetry(context.Background(), 2, time.Millisecond, func(time.Duration) {}, func(int) { retries++ }, func() error {
		return errors.New("fail")
	})
	if err == nil || retries != 2 {
		t.Fatalf("retries=%d err=%v", retries, err)
	}
}

func TestWithRetryContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := withRetry(ctx, 2, time.Millisecond, func(time.Duration) {}, nil, func() error {
		return errors.New("fail")
	})
	if err == nil {
		t.Fatal("expected context error")
	}
}

func TestWithRetryZeroAttempts(t *testing.T) {
	err := withRetry(context.Background(), -1, time.Millisecond, nil, nil, func() error { return errors.New("x") })
	if err == nil {
		t.Fatal("expected error")
	}
}
