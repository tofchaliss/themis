package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/usecase/triage"
)

const defaultTriageExpiryInterval = time.Hour

// StartTriageExpiryScheduler runs periodic accepted_risk expiry checks.
func StartTriageExpiryScheduler(ctx context.Context, svc triage.Service, interval time.Duration) {
	if svc == nil {
		return
	}
	if interval <= 0 {
		interval = defaultTriageExpiryInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_ = svc.ProcessExpiredAcceptedRisk(ctx, now.UTC())
			}
		}
	}()
}
