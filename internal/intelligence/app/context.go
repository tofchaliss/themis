package app

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// AssembleContext runs the deterministic Context Construction pipeline (D5): given
// only the subject identifier, it pulls exactly the grounding the capability declared
// it needs via the read-API Knowledge Providers and normalizes it into an
// AssembledContext. Same identifiers + same upstream state → same context.
//
// The caller passes an identifier, never assembled data — the Gateway owns the
// grounding, which is what makes stage-2 anti-hallucination validation authoritative.
// Missing grounding returns ErrIncompleteGrounding (a graceful no-proposal, not a
// hard error).
func AssembleContext(
	ctx context.Context,
	fr FindingReader,
	flr FaultlineReader,
	needs []domain.ContextNeed,
	findingID string,
) (domain.AssembledContext, error) {
	finding, err := fr.GetFinding(ctx, findingID)
	if err != nil {
		return domain.AssembledContext{}, fmt.Errorf("assemble finding: %w", err)
	}
	if finding.ID == "" {
		return domain.AssembledContext{}, ErrIncompleteGrounding
	}
	out := domain.AssembledContext{Finding: finding}

	if needs2(needs, domain.NeedFaultline) {
		if finding.FaultlineID == "" {
			return domain.AssembledContext{}, ErrIncompleteGrounding
		}
		fl, err := flr.GetFaultline(ctx, finding.FaultlineID)
		if err != nil {
			return domain.AssembledContext{}, fmt.Errorf("assemble faultline: %w", err)
		}
		if fl.ID == "" {
			return domain.AssembledContext{}, ErrIncompleteGrounding
		}
		out.Faultline = fl
	}
	return out, nil
}

func needs2(needs []domain.ContextNeed, want domain.ContextNeed) bool {
	for _, n := range needs {
		if n == want {
			return true
		}
	}
	return false
}
