package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// CVEFacts is one source's complete answer about a single CVE. Three outcomes, not two:
// the source has scored facts, has no usable record, or reports the CVE **withdrawn**.
//
// Withdrawal is its own outcome rather than an absence because it means something opposite:
// "we have no data on this" leaves the card alone, while "this CVE was rejected upstream"
// retires it. Collapsing them — the shape a (Proposal, found, error) signature forces — is what
// left withdrawn CVEs demanding triage forever (KN-WITHDRAW-1).
type CVEFacts struct {
	Proposal ProposalFor
	// Found reports usable, scored facts. False for an absent record, and also for one the
	// source has never scored: a Proposal with no severity would add a source to the card
	// without adding a fact.
	Found bool
	// Withdrawn reports the CVE rejected or withdrawn upstream. It takes precedence over Found.
	Withdrawn bool
}

// CVEVulnSource fetches the authoritative facts for ONE CVE by id — the per-subject shape every
// other feed in this context already uses (OSV by package, Red Hat and CSAF-VEX by CVE).
type CVEVulnSource interface {
	VulnsForCVE(ctx context.Context, cve value.CVEID) (CVEFacts, error)
}

// KnownCVEs returns the canonical CVEs that already have a card. It is the relevance bound of
// D5 in its simplest form: the enrichment sweeps ask their feeds only about these, so nothing is
// fetched that could be irrelevant. Shared by the Red Hat, exploit-signal and CSAF-VEX sweeps.
type KnownCVEs interface {
	KnownCVEs(ctx context.Context) (map[string]struct{}, error)
}

// EnrichmentQueue supplies the carded CVEs due a visit from a source.
type EnrichmentQueue interface {
	// CVEsNeedingRefresh returns never-enriched cards first, then those whose newest Proposal
	// from the source is older than staleAfter.
	CVEsNeedingRefresh(ctx context.Context, source string, staleAfter time.Duration, limit int) ([]string, error)
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
	source     string
	src        CVEVulnSource
	queue      EnrichmentQueue
	fold       *FaultlineService
	limit      int
	staleAfter time.Duration
}

// NewBackfillService wires the sweep. `limit` caps how many CVEs one run enriches, so a large
// estate drains over successive runs instead of one run taking unbounded time; a value <= 0
// falls back to the default.
func NewBackfillService(
	source string, src CVEVulnSource, queue EnrichmentQueue, fold *FaultlineService,
	limit int, staleAfter time.Duration,
) *BackfillService {
	if limit <= 0 {
		limit = DefaultBackfillLimit
	}
	if staleAfter <= 0 {
		staleAfter = DefaultStaleAfter
	}
	return &BackfillService{source: source, src: src, queue: queue, fold: fold, limit: limit, staleAfter: staleAfter}
}

// DefaultBackfillLimit is how many CVEs one sweep enriches when the caller sets no cap. Sized so
// a run stays well inside a poll interval at roughly one request per CVE.
const DefaultBackfillLimit = 200

// DefaultStaleAfter is how long a card's facts from a source stay fresh before the sweep
// revisits it.
//
// Revisiting matters because upstream data CHANGES: scores get revised, severities corrected,
// and CVEs rejected outright. An enrich-once sweep is complete on the day it runs and quietly
// wrong three months later — it would report an empty queue while carrying stale scores and
// live cards for withdrawn CVEs. 7 days keeps a settled estate cheap (a card is fetched ~52
// times a year, not once per poll) while bounding how long a correction can go unseen.
const DefaultStaleAfter = 7 * 24 * time.Hour

// Enrich runs one sweep and returns how many cards were folded.
//
// A per-CVE failure is skipped rather than fatal: one unreadable record must not stall the whole
// queue, and the card simply stays in it for the next run. Only a queue-read failure aborts,
// because without the queue there is no work to do.
func (s *BackfillService) Enrich(ctx context.Context) (int, error) {
	cves, err := s.queue.CVEsNeedingRefresh(ctx, s.source, s.staleAfter, s.limit)
	if err != nil {
		return 0, err
	}
	folded := 0
	for _, raw := range cves {
		cve, err := value.NewCVEID(raw)
		if err != nil {
			continue // an unparseable stored CVE is a data problem, not a reason to stop
		}
		facts, err := s.src.VulnsForCVE(ctx, cve)
		if err != nil {
			continue // one unreadable record must not stall the queue
		}
		// Withdrawal is checked FIRST and short-circuits: a rejected CVE is not enriched with
		// whatever stale facts the record still carries, it is retired. Folding first and
		// superseding after would leave a moment where a dead card looks freshly authoritative.
		if facts.Withdrawn {
			changed, serr := s.fold.SupersedeFaultline(ctx, cve)
			if serr != nil {
				return folded, serr
			}
			if changed {
				folded++
			}
			continue
		}
		if !facts.Found {
			continue
		}
		if _, err := s.fold.FoldProposal(ctx, facts.Proposal.CVE, facts.Proposal.Proposal); err != nil {
			return folded, err // a store failure is not per-record; stop and retry the sweep
		}
		folded++
	}
	return folded, nil
}
