package app

import (
	"context"
	"time"
)

// DefaultRediscoveryStaleAfter is how old a release's last discovery may grow before the
// sweep revisits it. A day bounds how long a newly published CVE can stay invisible on a
// static estate, while keeping feed load far below the per-upload path's.
const DefaultRediscoveryStaleAfter = 24 * time.Hour

// DefaultRediscoveryLimit caps releases per sweep, so a large estate drains across ticks
// instead of one tick issuing every release's full discovery fan-out at once. Worst-case
// feed load per tick is limit × components-per-release queries — proportional to the
// estate, never to the feeds (D5).
const DefaultRediscoveryLimit = 3

// RediscoveryService closes the static-estate blind spot (KN-RECOR-1): discovery used to run
// only at upload time, so a CVE published after a release's last upload was invisible until
// the next one — while every dashboard stayed green. The sweep re-runs the EXISTING
// correlation (the same discovery fan-out, range gate, fixed-verdict and idempotent match
// recording) for the releases whose last discovery is stalest. Nothing here decides
// anything; it is a scheduler around machinery that already converges.
type RediscoveryService struct {
	ledger     ReleaseLedger
	correlate  *CorrelationService
	clock      Clock
	staleAfter time.Duration
	limit      int
}

// NewRediscoveryService wires the sweep. staleAfter/limit <= 0 fall back to the defaults.
func NewRediscoveryService(ledger ReleaseLedger, correlate *CorrelationService, clock Clock, staleAfter time.Duration, limit int) *RediscoveryService {
	if staleAfter <= 0 {
		staleAfter = DefaultRediscoveryStaleAfter
	}
	if limit <= 0 {
		limit = DefaultRediscoveryLimit
	}
	return &RediscoveryService{ledger: ledger, correlate: correlate, clock: clock, staleAfter: staleAfter, limit: limit}
}

// Sweep re-discovers the stalest releases once, returning how many releases were swept and
// how many NEW matches surfaced — a new match here is exactly the headline event: a CVE
// reaching inventory nobody re-uploaded.
//
// A per-release failure (Evidence unreachable for that evidence id, a feed hiccup) skips the
// release — it stays stale and the next sweep retries — because one broken release must not
// starve the rest. Only the ledger read aborts: without the queue there is no work.
func (s *RediscoveryService) Sweep(ctx context.Context) (swept, newMatches int, err error) {
	stale, err := s.ledger.StaleReleases(ctx, s.clock.Now().Add(-s.staleAfter), s.limit)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range stale {
		// Correlate re-runs discovery against the release's LATEST correlated inventory and
		// applies through the standard gates; ApplyCorrelation re-stamps the ledger, so a
		// swept release leaves the stale queue even when nothing new was found.
		n, cerr := s.correlate.Correlate(ctx, r.ReleaseID, r.EvidenceID)
		if cerr != nil {
			continue
		}
		swept++
		newMatches += n
	}
	return swept, newMatches, nil
}
