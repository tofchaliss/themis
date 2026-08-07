package feed

import (
	"context"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// HealthRecorder is the slice of the app's FeedHealthService this decorator needs
// (*app.FeedHealthService satisfies it).
type HealthRecorder interface {
	RecordSuccess(ctx context.Context, source string, tier domain.Tier) error
	RecordFailure(ctx context.Context, source string, tier domain.Tier) error
}

// HealthRecordingSource wraps a discovery source so its calls land in feed health (B1).
//
// Feed health was recorded only by the SCHEDULED workers — the NVD watch, the exploit-signal
// sweep, the vendor feeds — because those are the ones with a poll loop to hang it off. OSV has
// no loop: it is queried per component at correlation time and is always on, so the one feed
// that runs on every single SBOM upload was the one feed with no health record at all. An OSV
// outage showed up as "correlation found nothing", indistinguishable from "nothing to find".
//
// The tier comes from the same taxonomy the scheduled feeds use, so `GET /feeds` evaluates OSV
// against the staleness rules for its tier rather than a special case.
type HealthRecordingSource struct {
	source string
	tier   domain.Tier
	raw    app.PackageVulnSource
	health HealthRecorder
}

// NewHealthRecordingSource wraps raw so every discovery call records feed health under source.
// A nil recorder returns raw unchanged, so a caller without health wiring is unaffected.
func NewHealthRecordingSource(source string, raw app.PackageVulnSource, health HealthRecorder) app.PackageVulnSource {
	if health == nil {
		return raw
	}
	return &HealthRecordingSource{source: source, tier: TierFor(source), raw: raw, health: health}
}

// VulnsForPackage delegates and records the outcome.
//
// A health-write failure is deliberately swallowed: health is an observation ABOUT the pipeline
// and must never be able to fail the pipeline. Losing one health stamp costs an operator a
// slightly stale timestamp; failing correlation because a bookkeeping row would not write costs
// the enterprise its vulnerability discovery.
func (s *HealthRecordingSource) VulnsForPackage(ctx context.Context, c app.InventoryComponent) ([]app.ProposalFor, error) {
	out, err := s.raw.VulnsForPackage(ctx, c)
	if err != nil {
		_ = s.health.RecordFailure(ctx, s.source, s.tier)
		observability.Default().RecordFeedPoll(s.source, observability.FeedPollFailed)
		return out, err
	}
	_ = s.health.RecordSuccess(ctx, s.source, s.tier)
	observability.Default().RecordFeedPoll(s.source, observability.FeedPollComplete)
	observability.Default().RecordFeedRecords(s.source, observability.FeedRecordsDiscovered, len(out))
	return out, nil
}
