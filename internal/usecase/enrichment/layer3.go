package enrichment

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// Layer3Enricher applies optional AI enrichment (Phase 2b).
type Layer3Enricher interface {
	Enrich(ctx context.Context, finding domain.EnrichmentFinding) error
}

// NoOpLayer3 is the Phase 2a default Layer 3 implementation.
type NoOpLayer3 struct{}

func (NoOpLayer3) Enrich(context.Context, domain.EnrichmentFinding) error {
	return nil
}
