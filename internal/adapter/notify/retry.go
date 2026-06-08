package notify

import (
	"context"
	"time"
)

func backoffDelay(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	if attempt <= 1 {
		return base
	}
	delay := base
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay > time.Hour {
			return time.Hour
		}
	}
	return delay
}

func withRetry(
	ctx context.Context,
	maxRetry int,
	baseDelay time.Duration,
	sleep func(time.Duration),
	onRetry func(attempt int),
	deliver func() error,
) error {
	attempts := maxRetry + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		lastErr = deliver()
		if lastErr == nil {
			return nil
		}
		if attempt == attempts {
			break
		}
		if onRetry != nil {
			onRetry(attempt)
		}
		delay := backoffDelay(baseDelay, attempt)
		if delay > 0 && sleep != nil {
			sleep(delay)
		}
	}
	return lastErr
}
