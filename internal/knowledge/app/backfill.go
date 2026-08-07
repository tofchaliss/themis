package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
)

// CVEVulnSource fetches the authoritative facts for ONE CVE by id — the per-subject shape every
// other feed in this context already uses (OSV by package, Red Hat and CSAF-VEX by CVE).
type CVEVulnSource interface {
	// VulnsForCVE returns the source Proposals for a single CVE. found=false when the source
	// has no record of it, which is not an error.
	VulnsForCVE(ctx context.Context, cve value.CVEID) (ProposalFor, bool, error)
}

// KnownCVEs returns the canonical CVEs that already have a card. It is the relevance bound of
// D5 in its simplest form: the enrichment sweeps ask their feeds only about these, so nothing is
// fetched that could be irrelevant. Shared by the Red Hat, exploit-signal and CSAF-VEX sweeps.
type KnownCVEs interface {
	KnownCVEs(ctx context.Context) (map[string]struct{}, error)
}

// EnrichmentQueue supplies the carded CVEs still missing a given source's Proposal.
type EnrichmentQueue interface {
	CVEsMissingSource(ctx context.Context, source string, limit int) ([]string, error)
}

// BackfillService enriches carded CVEs one at a time from a per-CVE source (EDR-KNOWLEDGE-01
// D5a). It replaces the modified-since window walk for NVD.
//
// The difference is not an optimization, it is the relevance bound made STRUCTURAL. The walk
// asked "what changed everywhere?" and discarded what did not apply — measured 2026-08-07, 3,207
// records fetched to apply 18, at ~84 seconds per day of window. This asks only about CVEs the
// enterprise already holds, so nothing is fetched that could be discarded, and cost is
// proportional to the estate rather than to the feed's churn.
//
// It also covers MORE: a card whose CVE last changed before the window began was unreachable by
// the walk at any budget, and is enriched here on the first sweep.
type BackfillService struct {
	source string
	src    CVEVulnSource
	queue  EnrichmentQueue
	fold   *FaultlineService
	limit  int
}

// NewBackfillService wires the sweep. `limit` caps how many CVEs one run enriches, so a large
// estate drains over successive runs instead of one run taking unbounded time; a value <= 0
// falls back to the default.
func NewBackfillService(source string, src CVEVulnSource, queue EnrichmentQueue, fold *FaultlineService, limit int) *BackfillService {
	if limit <= 0 {
		limit = DefaultBackfillLimit
	}
	return &BackfillService{source: source, src: src, queue: queue, fold: fold, limit: limit}
}

// DefaultBackfillLimit is how many CVEs one sweep enriches when the caller sets no cap. Sized so
// a run stays well inside a poll interval at roughly one request per CVE.
const DefaultBackfillLimit = 200

// Enrich runs one sweep and returns how many cards were folded.
//
// A per-CVE failure is skipped rather than fatal: one unreadable record must not stall the whole
// queue, and the card simply stays in it for the next run. Only a queue-read failure aborts,
// because without the queue there is no work to do.
func (s *BackfillService) Enrich(ctx context.Context) (int, error) {
	cves, err := s.queue.CVEsMissingSource(ctx, s.source, s.limit)
	if err != nil {
		return 0, err
	}
	folded := 0
	for _, raw := range cves {
		cve, err := value.NewCVEID(raw)
		if err != nil {
			continue // an unparseable stored CVE is a data problem, not a reason to stop
		}
		pf, found, err := s.src.VulnsForCVE(ctx, cve)
		if err != nil || !found {
			continue
		}
		if _, err := s.fold.FoldProposal(ctx, pf.CVE, pf.Proposal); err != nil {
			return folded, err // a store failure is not per-record; stop and retry the sweep
		}
		folded++
	}
	return folded, nil
}
