package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
)

// StartCorrelationFeedScheduler periodically reloads the distro correlation
// source index from its feeds (CR-4), logging the outcome and recording feed
// health under "distro_correlation".
func StartCorrelationFeedScheduler(ctx context.Context, loader *vexfeed.CorrelationLoader, interval time.Duration, log domain.Logger, health domain.FeedHealthRecorder) {
	if loader == nil || loader.Source == nil {
		return
	}
	log = domain.LoggerOrNop(log)
	health = domain.FeedHealthRecorderOrNop(health)
	if interval <= 0 {
		interval = defaultVEXFeedPollInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		runCorrelationFeedCycle(ctx, loader, log, health)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCorrelationFeedCycle(ctx, loader, log, health)
			}
		}
	}()
}

func runCorrelationFeedCycle(ctx context.Context, loader *vexfeed.CorrelationLoader, log domain.Logger, health domain.FeedHealthRecorder) {
	if err := loader.Refresh(ctx); err != nil {
		log.Error("distro correlation feed refresh failed", domain.LogString("feed", "distro_correlation"), domain.LogErr(err))
		_ = health.RecordFeedFailure(ctx, "distro_correlation", err)
		return
	}
	_ = health.RecordFeedSuccess(ctx, "distro_correlation")
}
