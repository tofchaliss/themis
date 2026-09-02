package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// The re-verdict (EDR-VERDICT-01 D6). A verdict fires when an occurrence is recorded — but
// vendor bounds arrive on later feed sweeps, and the rows that already exist ARE the estate
// (the motivating KN-VERDICT-1 finding predated its bounds by months). This service re-judges
// exactly the rows whose "judged against card version N" stamp lags their card:
//
//   - the CATCH-UP path: a bounded interval sweep drains history (every pre-feature row starts
//     at stamp 0) and anything the trigger missed while the process was down — the stamps make
//     it self-targeting, idempotent, and free once everything is current;
//   - the IMMEDIATE path: fix-folding feed loops call Nudge() after a tick that folded
//     something, so the sweep runs within seconds of real card news and finds precisely the
//     rows those folds made stale. The fold moment itself never re-judges inline — folding can
//     happen inside an inbox transaction, and the bridge needs an Evidence inventory read the
//     D7 read/write split forbids there.
//
// Re-judging goes through the SAME RecordMatch seam as intake: a semantic change updates the
// row and emits ComponentVerdictChanged; a confirming re-judgement advances the stamp
// silently; rows are never deleted.

// DefaultReverdictInterval is the catch-up cadence (THEMIS_REVERDICT_INTERVAL); the nudge
// path makes real news land much faster, so this is a backstop, not the latency.
const DefaultReverdictInterval = 12 * time.Hour

// DefaultReverdictBatch bounds one sweep (THEMIS_REVERDICT_BATCH); a large estate drains
// across nudges/ticks.
const DefaultReverdictBatch = 200

// StaleOccurrence is one match row whose verdict stamp lags its card, with everything a
// re-judgement needs: the component as recorded, and the currently recorded state (so the
// sweep can count real changes apart from silent stamp refreshes).
type StaleOccurrence struct {
	ReleaseID   string
	FaultlineID domain.FaultlineID
	CVE         string
	Component   InventoryComponent
	Current     domain.VerdictState
}

// StaleOccurrenceSource lists match rows needing re-judgement, oldest release first, bounded.
type StaleOccurrenceSource interface {
	StaleVerdictOccurrences(ctx context.Context, limit int) ([]StaleOccurrence, error)
}

// ReleaseEvidenceSource resolves a release to its latest correlated evidence id (the
// KN-RECOR-1 ledger) — how the sweep rebuilds the bridge context the intake path had in hand.
// found=false means the release never went through correlation (a scanner-only release).
type ReleaseEvidenceSource interface {
	EvidenceForRelease(ctx context.Context, releaseID string) (string, bool, error)
}

// ReleaseOccurrenceSource lists every component recorded on a release's matches — the
// fallback sibling set for a release with no correlated inventory: the scanner path recorded
// every examined component (D2), so its match rows ARE the same-inventory candidate set.
type ReleaseOccurrenceSource interface {
	MatchComponentsForRelease(ctx context.Context, releaseID string) ([]InventoryComponent, error)
}

// ReverdictService re-judges stale occurrences (D6).
type ReverdictService struct {
	stale     StaleOccurrenceSource
	ledger    ReleaseEvidenceSource
	relComps  ReleaseOccurrenceSource
	inventory InventoryReader
	repo      Repository
	matches   MatchRecorder
	clock     Clock

	batch          int
	inferredBridge bool
	nudge          chan struct{}
}

// NewReverdictService wires the re-verdict ports. batch <= 0 falls back to the default —
// a misconfigured knob must not turn the sweep into an unbounded pass (or a zero one).
func NewReverdictService(stale StaleOccurrenceSource, ledger ReleaseEvidenceSource, relComps ReleaseOccurrenceSource,
	inventory InventoryReader, repo Repository, matches MatchRecorder, clock Clock, batch int) *ReverdictService {
	if batch <= 0 {
		batch = DefaultReverdictBatch
	}
	return &ReverdictService{
		stale: stale, ledger: ledger, relComps: relComps, inventory: inventory,
		repo: repo, matches: matches, clock: clock,
		batch: batch, inferredBridge: true, nudge: make(chan struct{}, 1),
	}
}

// WithInferredBridge sets the D4 switch, mirroring the intake services — one switch, one
// meaning, every door.
func (s *ReverdictService) WithInferredBridge(enabled bool) *ReverdictService {
	s.inferredBridge = enabled
	return s
}

// Nudge asks the sweep loop to run now (the immediate path). Non-blocking and coalescing: a
// burst of folds while a sweep is already pending collapses to one wake-up, which is correct —
// the stamps, not the nudge count, decide what gets re-judged.
func (s *ReverdictService) Nudge() {
	select {
	case s.nudge <- struct{}{}:
	default:
	}
}

// NudgeC is the wake-up channel the composition root's loop selects on beside its ticker.
func (s *ReverdictService) NudgeC() <-chan struct{} { return s.nudge }

// Sweep re-judges one bounded batch of stale occurrences. Returns how many rows were
// re-judged (stamped current) and how many actually changed state.
//
// Per-release fail-safety: the bridge context is rebuilt per release — the correlated
// inventory where the ledger has one, the release's own recorded occurrences where it does not
// (a scanner-only release). When the inventory READ fails, the whole release is skipped and
// its rows stay stale for the next sweep: judging with a poorer context than the evidence
// actually offers, then stamping the result current, would silently downgrade the verdict —
// the one direction this arc exists to close.
func (s *ReverdictService) Sweep(ctx context.Context) (rejudged, changed int, err error) {
	rows, err := s.stale.StaleVerdictOccurrences(ctx, s.batch)
	if err != nil || len(rows) == 0 {
		return 0, 0, err
	}

	// One bridge context and one card read per distinct release/card in the batch, not per row.
	bridges := map[string]*BridgeContext{}
	cards := map[domain.FaultlineID]domain.Faultline{}
	now := s.clock.Now()

	for _, row := range rows {
		bridge, ok := bridges[row.ReleaseID]
		if !ok {
			bridge = s.bridgeFor(ctx, row.ReleaseID)
			bridges[row.ReleaseID] = bridge
		}
		if bridge == nil {
			continue // inventory read failed — the release's rows stay stale, retried next sweep
		}
		card, ok := cards[row.FaultlineID]
		if !ok {
			card, err = s.repo.GetByID(ctx, row.FaultlineID)
			if err != nil {
				return rejudged, changed, err // a store fault, not a feed gap — surface it
			}
			cards[row.FaultlineID] = card
		}
		verdict := judgeOccurrence(card.View(), row.Component, *bridge)
		if _, err := s.matches.RecordMatch(ctx, Match{
			ReleaseID: row.ReleaseID, FaultlineID: row.FaultlineID, CVE: row.CVE,
			Component: row.Component, Verdict: verdict, CardVersion: card.Version(),
			OccurredAt: now,
		}); err != nil {
			return rejudged, changed, err
		}
		rejudged++
		if verdict.State.IsOpen() != row.Current.IsOpen() {
			changed++
		}
	}
	return rejudged, changed, nil
}

// bridgeFor rebuilds the bridge context for one release, or nil when the evidence it needs is
// unreachable this sweep.
func (s *ReverdictService) bridgeFor(ctx context.Context, releaseID string) *BridgeContext {
	bridge := &BridgeContext{InferredBridge: s.inferredBridge}
	evidenceID, found, err := s.ledger.EvidenceForRelease(ctx, releaseID)
	if err != nil {
		return nil
	}
	if found {
		inv, ierr := s.inventory.GetInventory(ctx, evidenceID)
		if ierr != nil {
			return nil
		}
		bridge.Siblings, bridge.Owners = inv.Components, inv.Owners
		return bridge
	}
	comps, cerr := s.relComps.MatchComponentsForRelease(ctx, releaseID)
	if cerr != nil {
		return nil
	}
	bridge.Siblings = comps
	return bridge
}
