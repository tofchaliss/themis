package trust

import (
	"context"

	"github.com/themis-project/themis/internal/domain"
)

// GateEvaluator adapts Gate to domain.TrustGateEvaluator.
type GateEvaluator struct {
	Gate *Gate
}

// Evaluate runs the trust gate.
func (e GateEvaluator) Evaluate(ctx context.Context, artifact domain.RawArtifact, policy domain.TrustPolicy) domain.GateOutcome {
	if e.Gate == nil {
		return domain.GateOutcome{Accepted: false, HTTPStatus: 500, Message: "trust gate unavailable"}
	}
	return e.Gate.Evaluate(ctx, artifact, policy)
}
