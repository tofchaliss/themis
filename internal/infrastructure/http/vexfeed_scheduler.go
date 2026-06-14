package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
)

const defaultVEXFeedPollInterval = 24 * time.Hour

// StartVEXFeedScheduler runs periodic upstream vendor VEX sync cycles.
func StartVEXFeedScheduler(ctx context.Context, svc *vexfeed.Service, interval time.Duration) {
	if svc == nil {
		return
	}
	if interval <= 0 {
		interval = defaultVEXFeedPollInterval
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
			}
		}
	}()
}
