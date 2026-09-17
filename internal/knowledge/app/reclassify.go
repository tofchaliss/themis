package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The re-classification sweep (EDR-CORRELATION-01 D3/D4, KN-CLAIM-1).
//
// A component's claim class is decided when its match is recorded, from the card's carrier
// products. Two things make that decision go stale, and neither one re-runs correlation:
//
//   - the EVIDENCE arrives later. NVD's CPE products land on NVD's own cadence, usually after
//     the release was correlated. FoldProposal emits inline whenever a fold changes the carrier
//     set, which covers every card that keeps receiving folds.
//   - the RULES change. An edit to claimclass.go advances no card version and folds nothing, so
//     without this sweep a corrected rule would apply only to future matches while the existing
//     estate — which IS the estate — kept the old answer. Measured twice: both 2026-09 carrier
//     fixes shipped invisible behind current data.
//
// So the inline path handles new evidence and this handles history and rule changes, exactly
// the split the D6 re-verdict uses. Knowledge persists no claim class (it is computed when an
// event is built and only Governance stores it), which is why the stamps live on the CARD: the
// input that changes is the card's carrier set, not anything about the occurrence.
//
// Re-announcement goes through the same ComponentMatched note intake emits, and Governance's
// upsert is idempotent, so a redundant sweep costs events and changes nothing.

// DefaultReclassifyInterval is the catch-up cadence (THEMIS_RECLASSIFY_INTERVAL). The inline
// path carries real carrier news, so this is a backstop and a rule-change drain, not latency.
const DefaultReclassifyInterval = 6 * time.Hour

// DefaultReclassifyBatch bounds one sweep (THEMIS_RECLASSIFY_BATCH). A large estate drains
// across consecutive sweeps; the loop keeps going while a sweep comes back full.
const DefaultReclassifyBatch = 100

// StaleCard is one card whose classification stamps lag either its version or the current
// rule generation.
type StaleCard struct {
	ID      domain.FaultlineID
	Version int
}

// StaleClassificationSource lists cards needing re-classification, stalest first, bounded.
// Cards with no recorded matches are excluded — there is nothing to re-announce.
type StaleClassificationSource interface {
	StaleClassificationCards(ctx context.Context, generation, limit int) ([]StaleCard, error)
}

// ClassificationStamper queues re-announcement notes AND advances the card's stamps in ONE
// transaction. Atomicity is the whole point: a card stamped current with nothing emitted would
// be permanently skipped, which is the one outcome that turns a safety net into a false
// negative. It must not touch `version` — that stamp belongs to the aggregate, and bumping it
// here would make every sweep look like a card change to the re-verdict sweep.
type ClassificationStamper interface {
	StampReclassified(ctx context.Context, id domain.FaultlineID, version, generation int, notes []OutboxNote) error
}

// ReclassifyService re-announces the recorded matches of cards whose classification is stale.
type ReclassifyService struct {
	stale   StaleClassificationSource
	stamp   ClassificationStamper
	repo    Repository
	matches MatchReader
	clock   Clock
	batch   int
}

// NewReclassifyService wires the sweep. batch <= 0 falls back to the default — a misconfigured
// knob must not turn the sweep into an unbounded pass, or a zero one.
func NewReclassifyService(stale StaleClassificationSource, stamp ClassificationStamper,
	repo Repository, matches MatchReader, clock Clock, batch int) *ReclassifyService {
	if batch <= 0 {
		batch = DefaultReclassifyBatch
	}
	return &ReclassifyService{stale: stale, stamp: stamp, repo: repo, matches: matches, clock: clock, batch: batch}
}

// Generation reports the classification rule generation this service applies — the value a
// swept card is stamped with. Exposed so the composition root can log it without importing the
// domain ring, which it otherwise never does.
func (s *ReclassifyService) Generation() int { return domain.ClassifierGeneration }

// Sweep re-announces one bounded batch of stale cards. Returns the number of cards stamped and
// the number of occurrences re-announced; full == true means the batch filled, so more remain
// and the caller should sweep again rather than wait out the interval (that is what drains
// history after a rule change).
//
// A card with no occurrences is still STAMPED. It has nothing to announce, and leaving it
// unstamped would make every future sweep re-read the same rows forever.
func (s *ReclassifyService) Sweep(ctx context.Context) (cards, occurrences int, full bool, err error) {
	rows, err := s.stale.StaleClassificationCards(ctx, domain.ClassifierGeneration, s.batch)
	if err != nil || len(rows) == 0 {
		return 0, 0, false, err
	}
	now := s.clock.Now()
	for _, row := range rows {
		card, gerr := s.repo.GetByID(ctx, row.ID)
		if gerr != nil {
			return cards, occurrences, false, gerr
		}
		notes, nerr := reannounceNotes(ctx, s.matches, card, now)
		if nerr != nil {
			return cards, occurrences, false, nerr
		}
		// Stamp the version actually CLASSIFIED, not the one the listing reported: a concurrent
		// fold between the two reads means we classified the newer card, and stamping the older
		// version would re-sweep work already done. A fold AFTER this read leaves the stamp
		// behind, which is the fail-safe direction — it gets swept again.
		if serr := s.stamp.StampReclassified(ctx, row.ID, card.Version(), domain.ClassifierGeneration, notes); serr != nil {
			return cards, occurrences, false, serr
		}
		cards++
		occurrences += len(notes)
	}
	return cards, occurrences, len(rows) == s.batch, nil
}
