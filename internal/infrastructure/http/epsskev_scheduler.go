package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/adapter/epsskev"
)

const defaultEPSSKevPollInterval = 24 * time.Hour

// StartEPSSKevScheduler runs periodic EPSS/KEV sync cycles.
func StartEPSSKevScheduler(ctx context.Context, svc *epsskev.Service, interval time.Duration) {
	if svc == nil {
		return
	}
	if interval <= 0 {
		interval = defaultEPSSKevPollInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		_, _ = svc.RunSync(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = svc.RunSync(ctx)
				_ = svc.RefreshStaleFlags(ctx)
			}
		}
	}()
}
