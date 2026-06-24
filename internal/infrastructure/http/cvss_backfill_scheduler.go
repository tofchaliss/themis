package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// StartCVSSBackfillScheduler periodically backfills CVSS for catalog rows that
// lack it from the NVD by-CVE endpoint (CR-5), logging the outcome and recording
// feed health under "cvss_backfill".
func StartCVSSBackfillScheduler(ctx context.Context, svc *enrichment.CVSSBackfillService, interval time.Duration, log domain.Logger, health domain.FeedHealthRecorder) {
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
		runCVSSBackfillCycle(ctx, svc, log, health)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCVSSBackfillCycle(ctx, svc, log, health)
			}
		}
	}()
}

func runCVSSBackfillCycle(ctx context.Context, svc *enrichment.CVSSBackfillService, log domain.Logger, health domain.FeedHealthRecorder) {
	result, err := svc.RunBackfill(ctx)
	if err != nil {
		log.Error("cvss backfill failed", domain.LogString("feed", "cvss_backfill"), domain.LogErr(err))
		_ = health.RecordFeedFailure(ctx, "cvss_backfill", err)
		return
	}
	log.Info("cvss backfill cycle completed",
		domain.LogString("feed", "cvss_backfill"),
		domain.LogInt("updated", result.Updated),
		domain.LogInt("checked", result.Checked))
	_ = health.RecordFeedSuccess(ctx, "cvss_backfill")
}
