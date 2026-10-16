package app

import (
	"context"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// ExpiredReviewLister names the Findings whose current suppressing Position carries a review-by
// date already past and that have not been re-surfaced yet (RF-2).
type ExpiredReviewLister interface {
	SuppressedWithExpiredReview(ctx context.Context, now time.Time, limit int) ([]domain.FindingID, error)
}

// ReviewBySweepBatch bounds one sweep; a backlog drains over successive ticks.
const ReviewBySweepBatch = 200

// ReviewBySweep is the timer the disposition watcher never had (EDR-GOVERNANCE-01 D14, RF-2).
//
// The watcher runs on an enrichment of the Finding's CVE, so a suppressed Finding whose
// review-by date passed was re-surfaced only if its CVE happened to be enriched afterwards — a
// quiet CVE never came back, which made `review_by` a date nobody was held to. This sweep asks
// the one question the watcher asks on expiry, on a clock instead of an event: has anyone
// looked at this lately? It marks the Finding re-surfaced (the same mark, the same event) and
// decides nothing — the Position stands until a person re-answers.
type ReviewBySweep struct {
	svc    *FindingService
	lister ExpiredReviewLister
	clock  Clock
}

// NewReviewBySweep builds the sweep over the write service and the lister.
func NewReviewBySweep(svc *FindingService, lister ExpiredReviewLister, clock Clock) *ReviewBySweep {
	return &ReviewBySweep{svc: svc, lister: lister, clock: clock}
}

// Run performs one sweep and reports how many Findings it checked and how many it re-surfaced.
// A write failure is fatal; an expiry that no longer holds inside the transaction (somebody
// re-decided meanwhile) is skipped, not an error.
func (r *ReviewBySweep) Run(ctx context.Context) (checked, resurfaced int, err error) {
	ids, err := r.lister.SuppressedWithExpiredReview(ctx, r.clock.Now(), ReviewBySweepBatch)
	if err != nil {
		return 0, 0, fmt.Errorf("list expired reviews: %w", err)
	}
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return checked, resurfaced, err
		}
		checked++
		marked, err := r.svc.ResurfaceExpiredReview(ctx, id)
		if err != nil {
			return checked, resurfaced, fmt.Errorf("re-surface %s: %w", id, err)
		}
		if marked {
			resurfaced++
		}
	}
	return checked, resurfaced, nil
}

// RunEvery runs the sweep on a cadence until ctx is cancelled, reporting each pass through
// report (nil = silent).
func (r *ReviewBySweep) RunEvery(ctx context.Context, every time.Duration, report func(checked, resurfaced int, err error)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, n, err := r.Run(ctx)
			if report != nil {
				report(c, n, err)
			}
		}
	}
}

// ResurfaceExpiredReview re-checks ONE Finding under its transaction and marks it re-surfaced
// when its current suppressing Position's review-by date has passed (RF-2). Reports whether the
// mark was set; a Finding re-decided or already marked since it was listed is left alone.
func (s *FindingService) ResurfaceExpiredReview(ctx context.Context, id domain.FindingID) (bool, error) {
	marked := false
	err := s.mutate(ctx, id, func(f *domain.Finding, now time.Time) ([]OutboxNote, error) {
		pos, ok := f.CurrentPosition()
		if !ok || !domain.SuppressesTriage(pos.Stance()) || !domain.Expired(pos.Inputs().ReviewBy, now) {
			return nil, errNoop
		}
		if !f.MarkDispositionStale(reviewByExpiredReason, now) {
			return nil, errNoop
		}
		marked = true
		return []OutboxNote{{
			EventType:  EventDispositionStale,
			Event:      domain.NewDispositionStale(*f, pos, reviewByExpiredReason, now),
			OccurredAt: now,
		}}, nil
	})
	return marked, err
}
