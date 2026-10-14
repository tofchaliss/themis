package app

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/kernel/value"
)

// UndecidedFaultlineLister names the Faultlines that still have at least one undecided
// Finding — the population a range re-judge has any business touching. A decided Finding is
// never revisited here: a Position is a human's or a policy's record, and re-reading the version
// does not reopen it (the disposition watcher owns that question, GOV-14b).
type UndecidedFaultlineLister interface {
	UndecidedFaultlines(ctx context.Context) ([]string, error)
}

// RangeRejudgeResult counts what one pass did. Raised is proposals newly raised, which the
// configured policy may already have accepted inside the same mutation; Skipped is Faultlines
// whose card carries no reconciled range (nothing to judge against) or could not be read.
type RangeRejudgeResult struct {
	Faultlines int
	Raised     int
	Skipped    int
}

// RangeRejudge is the ONE-TIME pass that re-applies the deterministic version-range rule to
// every undecided Finding (KN-GO-2, 2026-10-14).
//
// Why it exists: `reactToVersionRange` runs only when a Faultline is enriched, so a Finding
// whose verdict changed because THEMIS's own reading of a version changed — KN-GO-1 taught
// `go1.27.1` to compare as 1.27.1 — has no trigger. Measured on the estate: 330 stdlib matches
// over 165 long-fixed CVEs stayed open after the comparator was corrected, because the cards
// did not change and re-discovery no longer returned the false CVEs to revisit. This pass is
// the trigger, run on demand (THEMIS_GOVERNANCE_REJUDGE_RANGES=1) and never on a schedule.
//
// It is the SAME rule, not a second one: per Faultline it reads the card's reconciled ranges and
// their trust class over the Knowledge read seam and hands them to the service's own
// version-range reaction, which raises the deterministic `range:<finding>` proposal only where
// every matched component is provably out of range, and lets the configured policy decide
// (Observed evidence may auto-accept; anything weaker waits for a human). Idempotent through
// the proposal id: a second pass raises nothing new.
type RangeRejudge struct {
	svc       *FindingService
	undecided UndecidedFaultlineLister
	knowledge FaultlineKnowledgeReader
}

// NewRangeRejudge builds the pass over the write service, the lister and the Knowledge read seam.
func NewRangeRejudge(svc *FindingService, undecided UndecidedFaultlineLister, knowledge FaultlineKnowledgeReader) *RangeRejudge {
	return &RangeRejudge{svc: svc, undecided: undecided, knowledge: knowledge}
}

// Run performs one pass. A Faultline whose card cannot be read is skipped, not fatal: the pass
// is a best-effort sweep over an estate, and one unreadable card must not stop the other
// hundred from being judged. A write failure IS fatal — it means the service is unhealthy.
func (r *RangeRejudge) Run(ctx context.Context) (RangeRejudgeResult, error) {
	var res RangeRejudgeResult
	ids, err := r.undecided.UndecidedFaultlines(ctx)
	if err != nil {
		return res, fmt.Errorf("list undecided faultlines: %w", err)
	}
	res.Faultlines = len(ids)
	for _, fl := range ids {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		k, kerr := r.knowledge.GetFaultline(ctx, fl)
		if kerr != nil || len(k.AffectedRanges) == 0 {
			res.Skipped++
			continue
		}
		n, err := r.svc.RejudgeVersionRange(ctx, fl, k.AffectedRanges, k.RangeTrust)
		if err != nil {
			return res, fmt.Errorf("rejudge %s: %w", fl, err)
		}
		res.Raised += n
	}
	return res, nil
}

// RejudgeVersionRange re-applies the version-range rule to every Finding of one Faultline
// against the given reconciled ranges, exactly as an enrichment would, and returns how many
// proposals it raised. It is the narrow entry the one-time pass needs: ReactToEnrichment also
// stamps the base score, signals and band from its signal, and a pass that carries none of
// those must not zero them.
func (s *FindingService) RejudgeVersionRange(ctx context.Context, faultlineID string, ranges []string, trust value.TrustClass) (int, error) {
	if len(ranges) == 0 {
		return 0, nil
	}
	return s.reactToVersionRangeCounted(ctx, EnrichmentSignal{FaultlineID: faultlineID, AffectedRanges: ranges, RangeTrust: trust})
}
