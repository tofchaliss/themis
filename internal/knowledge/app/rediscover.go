package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
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
	// scanner re-discovers the components only a scanner named (KN-SCAN-5); nil = SBOM only.
	scanner    *ScannerReportService
	scanLedger ScannerReleaseLedger
}

// WithScanner adds the scanner-only half of the sweep (KN-SCAN-5): after each stale release's
// SBOM re-correlation, its scanner-only components are re-discovered too, and a scanner-only
// release (ledger row with no evidence id) gets that step alone, then its stamp moved.
func (s *RediscoveryService) WithScanner(scanner *ScannerReportService, ledger ScannerReleaseLedger) *RediscoveryService {
	s.scanner, s.scanLedger = scanner, ledger
	return s
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
	// Scanner-only releases that predate KN-SCAN-5 have no ledger row and would never be swept;
	// row them, dated past the staleness bar, so they queue behind the genuinely stale ones.
	if s.scanLedger != nil {
		if _, err := s.scanLedger.BackfillScannerReleases(ctx, s.clock.Now().Add(-s.staleAfter).Add(-time.Second)); err != nil {
			return 0, 0, err
		}
	}
	stale, err := s.ledger.StaleReleases(ctx, s.clock.Now().Add(-s.staleAfter), s.limit)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range stale {
		if r.EvidenceID != "" {
			n, cerr := s.correlate.CorrelateCause(ctx, r.ReleaseID, r.EvidenceID, domain.CauseRediscovery)
			if cerr != nil {
				continue
			}
			newMatches += n
		}
		if s.scanner != nil {
			n, serr := s.scanner.RediscoverComponents(ctx, r.ReleaseID)
			if serr != nil {
				continue
			}
			newMatches += n
			// A scanner-only release has no SBOM correlation to move its stamp, so it is
			// moved here; an SBOM release's stamp was just moved by ApplyCorrelation.
			if r.EvidenceID == "" && s.scanLedger != nil {
				_ = s.scanLedger.StampDiscovered(ctx, r.ReleaseID, s.clock.Now())
			}
		}
		swept++
	}
	return swept, newMatches, nil
}
