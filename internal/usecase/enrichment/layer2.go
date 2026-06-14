package enrichment

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// Layer2Enricher applies graph blast-radius scoring (Phase 2a).
type Layer2Enricher interface {
	Enrich(ctx context.Context, finding domain.EnrichmentFinding) (domain.BlastRadiusResult, error)
}

// NoOpLayer2 returns baseline blast-radius when graph is unavailable.
type NoOpLayer2 struct{}

func (NoOpLayer2) Enrich(context.Context, domain.EnrichmentFinding) (domain.BlastRadiusResult, error) {
	return domain.BlastRadiusResult{Score: domain.RiskScoreBlastRadiusMin}, nil
}

// TeamNotifier enqueues deterministic team notifications for blast-radius events.
type TeamNotifier interface {
	NotifyTeam(ctx context.Context, event domain.NotificationEvent) error
}

// ComputeBlastRadiusScore maps unique Customer count to a 1.0–2.0 multiplier.
func ComputeBlastRadiusScore(uniqueCustomers int) float64 {
	return domain.ComputeBlastRadiusScore(uniqueCustomers)
}

func layer2Enricher(h *Handler) Layer2Enricher {
	if h.Layer2 != nil {
		return h.Layer2
	}
	return NoOpLayer2{}
}
