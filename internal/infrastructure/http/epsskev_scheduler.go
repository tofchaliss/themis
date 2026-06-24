package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/adapter/epsskev"
	"github.com/themis-project/themis/internal/domain"
)

const defaultEPSSKevPollInterval = 24 * time.Hour

// StartEPSSKevScheduler runs periodic EPSS/KEV sync cycles, logging the outcome
// of each cycle (CR-7) and recording feed health (CR-8) instead of silently
// discarding the result.
func StartEPSSKevScheduler(ctx context.Context, svc *epsskev.Service, interval time.Duration, log domain.Logger, health domain.FeedHealthRecorder) {
	if svc == nil {
		return
	}
	log = domain.LoggerOrNop(log)
	health = domain.FeedHealthRecorderOrNop(health)
	if interval <= 0 {
		interval = defaultEPSSKevPollInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		runEPSSKevCycle(ctx, svc, log, health)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runEPSSKevCycle(ctx, svc, log, health)
				if err := svc.RefreshStaleFlags(ctx); err != nil {
					log.Warn("epss/kev refresh stale flags failed", domain.LogString("feed", "epss_kev"), domain.LogErr(err))
				}
			}
		}
	}()
}

func runEPSSKevCycle(ctx context.Context, svc *epsskev.Service, log domain.Logger, health domain.FeedHealthRecorder) {
	result, err := svc.RunSync(ctx)
	if err != nil {
		log.Error("epss/kev feed sync failed", domain.LogString("feed", "epss_kev"), domain.LogErr(err))
		_ = health.RecordFeedFailure(ctx, "epss_kev", err)
		return
	}
	log.Info("epss/kev feed sync completed", domain.LogString("feed", "epss_kev"), domain.LogAny("result", result))
	_ = health.RecordFeedSuccess(ctx, "epss_kev")
}
