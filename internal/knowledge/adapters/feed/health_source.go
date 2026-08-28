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
//
// A distro component additionally records under "<source>/<distro>" (e.g. osv/alpine) at
// Tier3Enrichment. One aggregate row cannot distinguish "Alpine data flowing" from "Alpine data
// quietly absent" when rocky uploads keep the row green; the per-distro row can. Tier 3 is
// deliberate: its StaleThreshold is zero, so a distro nobody has uploaded lately reads as an old
// timestamp — a fact — and never as a degraded feed, which would be a false alarm. The aggregate
// row keeps the tier-2 verdict: it answers "is the feed up?", the sub-rows answer "for whom?".
func (s *HealthRecordingSource) VulnsForPackage(ctx context.Context, c app.InventoryComponent) ([]app.ProposalFor, error) {
	distroSource := ""
	if d := healthDistro(c.PURL); d != "" {
		distroSource = s.source + "/" + d
	}
	out, err := s.raw.VulnsForPackage(ctx, c)
	if err != nil {
		_ = s.health.RecordFailure(ctx, s.source, s.tier)
		if distroSource != "" {
			_ = s.health.RecordFailure(ctx, distroSource, domain.Tier3Enrichment)
		}
		observability.Default().RecordFeedPoll(s.source, observability.FeedPollFailed)
		return out, err
	}
	_ = s.health.RecordSuccess(ctx, s.source, s.tier)
	if distroSource != "" {
		_ = s.health.RecordSuccess(ctx, distroSource, domain.Tier3Enrichment)
	}
	observability.Default().RecordFeedPoll(s.source, observability.FeedPollComplete)
	observability.Default().RecordFeedRecords(s.source, observability.FeedRecordsDiscovered, len(out))
	return out, nil
}

// healthDistro names the distro a package query belongs to, for the per-distro health row:
// the PURL "distro=" qualifier's name token, with the same synonym folding the OSV ecosystem
// mapping applies (rockylinux→rocky, almalinux→alma, redhat→rhel). Empty for non-distro
// components and for distro PURLs that carry no distro qualifier — those stay on the
// aggregate row only.
func healthDistro(purl string) string {
	switch purlType(purl) {
	case "apk", "deb", "rpm":
	default:
		return ""
	}
	// Both qualifier dialects resolve here (KN-DISTRO-1): "alpine-3.20.2" and Trivy's
	// bare-version "3.20.2" (name from the PURL namespace) yield the same per-distro row.
	name, _ := distroNameVersion(purl)
	if name == "" {
		return ""
	}
	switch name {
	case "rockylinux":
		return "rocky"
	case "almalinux":
		return "alma"
	case "redhat":
		return "rhel"
	}
	return name
}
