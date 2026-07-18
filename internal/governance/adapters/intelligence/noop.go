package intelligence

import (
	"context"

	"github.com/themis-project/themis/internal/governance/app"
)

// NoopAdvisor is the disable-gate alternative to Client (D13): it produces no proposal
// with no network call. Wiring selects the real Client or this no-op from one config
// flag — the single-seam disable gate. "Disabled" and "unavailable" collapse to the
// same safe outcome.
type NoopAdvisor struct{}

// RecommendPosition always declines (no proposal).
func (NoopAdvisor) RecommendPosition(_ context.Context, _ string) (app.Recommendation, bool, error) {
	return app.Recommendation{}, false, nil
}
