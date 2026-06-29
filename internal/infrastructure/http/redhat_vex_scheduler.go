package httpserver

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// StartRedHatVEXScheduler periodically applies Red Hat Security Data API verdicts
// as a VEX overlay for open RPM findings (Option B — the on-demand alternative to
// the unusable CSAF directory crawler), logging the outcome and recording feed
// health under "redhat_vex".
func StartRedHatVEXScheduler(ctx context.Context, svc *enrichment.RedHatVEXService, interval time.Duration, log domain.Logger, health domain.FeedHealthRecorder) {
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
		runRedHatVEXCycle(ctx, svc, log, health)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runRedHatVEXCycle(ctx, svc, log, health)
			}
		}
	}()
}

func runRedHatVEXCycle(ctx context.Context, svc *enrichment.RedHatVEXService, log domain.Logger, health domain.FeedHealthRecorder) {
	result, err := svc.RunCycle(ctx)
	if err != nil {
		log.Error("redhat vex cycle failed", domain.LogString("feed", "redhat_vex"), domain.LogErr(err))
		_ = health.RecordFeedFailure(ctx, "redhat_vex", err)
		return
	}
	log.Info("redhat vex cycle completed",
		domain.LogString("feed", "redhat_vex"),
		domain.LogInt("not_affected", result.NotAffected),
		domain.LogInt("fixed", result.Fixed),
		domain.LogInt("affected", result.Affected))
	_ = health.RecordFeedSuccess(ctx, "redhat_vex")
}
