package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
)

const defaultVEXFeedPollInterval = 24 * time.Hour

// StartVEXFeedScheduler runs periodic upstream vendor VEX sync cycles, logging
// the outcome of each cycle (CR-7) and recording feed health (CR-8). Per-feed-line
// warnings surface via the service's wired SyncLogger.
func StartVEXFeedScheduler(ctx context.Context, svc *vexfeed.Service, interval time.Duration, log domain.Logger, health domain.FeedHealthRecorder) {
	if svc == nil {
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
		runVEXFeedCycle(ctx, svc, log, health)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runVEXFeedCycle(ctx, svc, log, health)
			}
		}
	}()
}

func runVEXFeedCycle(ctx context.Context, svc *vexfeed.Service, log domain.Logger, health domain.FeedHealthRecorder) {
	result, err := svc.RunSync(ctx)
	if err != nil {
		log.Error("vendor vex feed sync failed", domain.LogString("feed", "vendor_vex"), domain.LogErr(err))
		_ = health.RecordFeedFailure(ctx, "vendor_vex", err)
		return
	}
	log.Info("vendor vex feed sync completed",
		domain.LogString("feed", "vendor_vex"),
		domain.LogInt("assertions_upserted", result.AssertionsUpserted),
		domain.LogInt("sboms_scheduled", result.SBOMsScheduled))
	_ = health.RecordFeedSuccess(ctx, "vendor_vex")
}
