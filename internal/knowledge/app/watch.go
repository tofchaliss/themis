package app

import (
	"context"
	"time"
)

// ChangedVulnSource returns source Proposals for CVEs changed since a watermark (D5) —
// the scheduled NVD modified-since watch.
type ChangedVulnSource interface {
	// ChangedSince returns the Proposals for CVEs changed since the watermark, AND the instant
	// through which it actually covered.
	//
	// coveredThrough exists because a source may legitimately cover less than "up to now": NVD
	// pages are large and slow (measured 2026-08-07: ~84s for one 24-hour slice), so a cold
	// start spanning months cannot be walked in one poll. Reporting coverage lets the caller
	// advance the watermark to what was really read, so catch-up is incremental and LOSSLESS —
	// advancing to "now" after a partial walk would skip everything in between, which is the
	// NVD-WATCH-1 defect in a new costume.
	ChangedSince(ctx context.Context, since time.Time) (proposals []ProposalFor, coveredThrough time.Time, err error)
}

// WatchState persists the watch watermark (last successful poll) so a restart resumes
// from durable state (D11; PoC: system_state.cve_watch_last_success).
type WatchState interface {
	LastSuccess(ctx context.Context) (time.Time, error)
	SetLastSuccess(ctx context.Context, t time.Time) error
}

// KnownCVEs returns the set of canonical CVEs that already have a card. It backs the
// relevance bound on the watch (D5): a modified-since feed is filtered to CVEs the
// enterprise already knows about, so the watch enriches existing cards rather than
// mirroring the whole feed.
type KnownCVEs interface {
	KnownCVEs(ctx context.Context) (map[string]struct{}, error)
}

// WatchService is the scheduled watch worker (D5/D11): it discovers CVEs changed since
// the last watermark, folds their Proposals into the cards, and advances the watermark.
// It is idempotent — re-folding a Proposal converges — and resumable from the watermark.
type WatchService struct {
	changed ChangedVulnSource
	state   WatchState
	fold    *FaultlineService
	clock   Clock
}

// NewWatchService wires the watch ports.
func NewWatchService(changed ChangedVulnSource, state WatchState, fold *FaultlineService, clock Clock) *WatchService {
	return &WatchService{changed: changed, state: state, fold: fold, clock: clock}
}

// Poll runs one watch cycle and returns how many Proposals were folded. The watermark
// advances only after a fully successful pass, so a mid-run failure re-processes the
// window on the next poll (at-least-once, converging via idempotent folds).
func (s *WatchService) Poll(ctx context.Context) (int, error) {
	since, err := s.state.LastSuccess(ctx)
	if err != nil {
		return 0, err
	}
	discovered, coveredThrough, err := s.changed.ChangedSince(ctx, since)
	if err != nil {
		return 0, err
	}
	folded := 0
	for _, d := range discovered {
		if _, err := s.fold.FoldProposal(ctx, d.CVE, d.Proposal); err != nil {
			return folded, err
		}
		folded++
	}
	// The watermark moves to what was COVERED, never to the wall clock. A source that walked
	// only part of the span leaves the rest for the next poll instead of stepping over it.
	if coveredThrough.IsZero() || coveredThrough.After(s.clock.Now()) {
		coveredThrough = s.clock.Now()
	}
	if err := s.state.SetLastSuccess(ctx, coveredThrough); err != nil {
		return folded, err
	}
	return folded, nil
}
