package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/usecase/watch"
)

const defaultWatchPollInterval = 6 * time.Hour

// StartWatchScheduler runs periodic CVE watch cycles.
func StartWatchScheduler(ctx context.Context, svc *watch.Service, interval time.Duration) {
	if svc == nil {
		return
	}
	if interval <= 0 {
		interval = defaultWatchPollInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		_ = svc.RunCycle(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = svc.RunCycle(ctx)
			}
		}
	}()
}
