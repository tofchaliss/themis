package app

import (
	"context"
	"time"
)

// ChangedVulnSource returns source Proposals for CVEs changed since a watermark (D5) —
// the scheduled NVD modified-since watch.
type ChangedVulnSource interface {
	ChangedSince(ctx context.Context, since time.Time) ([]ProposalFor, error)
}

// WatchState persists the watch watermark (last successful poll) so a restart resumes
// from durable state (D11; PoC: system_state.cve_watch_last_success).
type WatchState interface {
	LastSuccess(ctx context.Context) (time.Time, error)
	SetLastSuccess(ctx context.Context, t time.Time) error
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
	start := s.clock.Now()

	discovered, err := s.changed.ChangedSince(ctx, since)
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
	if err := s.state.SetLastSuccess(ctx, start); err != nil {
		return folded, err
	}
	return folded, nil
}
