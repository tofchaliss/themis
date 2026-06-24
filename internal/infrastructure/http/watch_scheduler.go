package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/watch"
)

const defaultWatchPollInterval = 6 * time.Hour

// StartWatchScheduler runs periodic CVE watch cycles, logging the outcome of each
// cycle (CR-7) and recording feed health (CR-8) instead of silently discarding
// the error.
func StartWatchScheduler(ctx context.Context, svc *watch.Service, interval time.Duration, log domain.Logger, health domain.FeedHealthRecorder) {
	if svc == nil {
		return
	}
	log = domain.LoggerOrNop(log)
	health = domain.FeedHealthRecorderOrNop(health)
	if interval <= 0 {
		interval = defaultWatchPollInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		runWatchCycle(ctx, svc, log, health)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runWatchCycle(ctx, svc, log, health)
			}
		}
	}()
}

func runWatchCycle(ctx context.Context, svc *watch.Service, log domain.Logger, health domain.FeedHealthRecorder) {
	if err := svc.RunCycle(ctx); err != nil {
		log.Error("cve watch cycle failed", domain.LogString("feed", "cve_watch"), domain.LogErr(err))
		_ = health.RecordFeedFailure(ctx, "cve_watch", err)
		return
	}
	log.Info("cve watch cycle completed", domain.LogString("feed", "cve_watch"))
	_ = health.RecordFeedSuccess(ctx, "cve_watch")
}
