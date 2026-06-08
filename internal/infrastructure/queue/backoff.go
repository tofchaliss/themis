package queue

import "time"

// BackoffDelay returns exponential backoff for the given attempt (1-based).
func BackoffDelay(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	if attempt <= 1 {
		return base
	}

	delay := base
	for i := 1; i < attempt; i++ {
		if delay > time.Hour {
			return time.Hour
		}
		delay *= 2
	}
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}
