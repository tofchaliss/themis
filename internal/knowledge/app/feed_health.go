package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// neverSucceeded is the "time since last success" used for a feed that has no recorded
// successful sync yet — far beyond any tier's stale threshold, so it always reads as overdue.
const neverSucceeded = 1_000_000 * time.Hour

// FeedHealthRow is one persisted feed-health record (the store's read shape).
type FeedHealthRow struct {
	Source              string
	Tier                int
	LastSuccessAt       *time.Time
	ConsecutiveFailures int
}

// FeedHealthStore persists and reads per-feed sync outcomes (B1). The scheduled workers record
// success/failure; Report reads the rows back to evaluate each against its tier policy.
type FeedHealthStore interface {
	RecordFeedSuccess(ctx context.Context, source string, tier int, now time.Time) error
	RecordFeedFailure(ctx context.Context, source string, tier int, now time.Time) error
	FeedHealthRows(ctx context.Context) ([]FeedHealthRow, error)
}

// FeedHealthEntry is one feed's evaluated health for the status report.
type FeedHealthEntry struct {
	Source              string
	Tier                int
	Status              string
	ConsecutiveFailures int
	LastSuccessAt       *time.Time
}

// FeedHealthReport is the tier-aware feed-health snapshot served at GET /feeds. SignalsStale is
// the Tier-1 escalation flag (any critical feed stale ⇒ the platform's signals are unreliable);
// DegradedFeeds lists the Tier-2 feeds currently failing. Both derive from domain policy.
type FeedHealthReport struct {
	SignalsStale  bool
	Feeds         []FeedHealthEntry
	DegradedFeeds []string
}

// FeedHealthService records feed sync outcomes and reports tier-aware health. It applies the
// domain's feed-tier policy (domain.FeedObservation.Evaluate) — the B1 wiring of D-FEED-2.
type FeedHealthService struct {
	store FeedHealthStore
	clock Clock
}

// NewFeedHealthService builds a FeedHealthService over the store and clock.
func NewFeedHealthService(store FeedHealthStore, clock Clock) *FeedHealthService {
	return &FeedHealthService{store: store, clock: clock}
}

// RecordSuccess marks a clean sync for a feed source at its tier.
func (s *FeedHealthService) RecordSuccess(ctx context.Context, source string, tier domain.Tier) error {
	return s.store.RecordFeedSuccess(ctx, source, int(tier), s.clock.Now())
}

// RecordFailure marks a failed sync for a feed source at its tier.
func (s *FeedHealthService) RecordFailure(ctx context.Context, source string, tier domain.Tier) error {
	return s.store.RecordFeedFailure(ctx, source, int(tier), s.clock.Now())
}

// Report evaluates every recorded feed against its tier's staleness policy and assembles the
// status snapshot: SignalsStale if any Tier-1 feed is stale, and the Tier-2 degraded list.
func (s *FeedHealthService) Report(ctx context.Context) (FeedHealthReport, error) {
	rows, err := s.store.FeedHealthRows(ctx)
	if err != nil {
		return FeedHealthReport{}, err
	}
	now := s.clock.Now()
	report := FeedHealthReport{Feeds: make([]FeedHealthEntry, 0, len(rows)), DegradedFeeds: []string{}}
	for _, r := range rows {
		since := neverSucceeded
		if r.LastSuccessAt != nil {
			since = now.Sub(*r.LastSuccessAt)
		}
		status := domain.FeedObservation{
			Tier:                domain.Tier(r.Tier),
			ConsecutiveFailures: r.ConsecutiveFailures,
			SinceLastSuccess:    since,
		}.Evaluate()

		report.Feeds = append(report.Feeds, FeedHealthEntry{
			Source:              r.Source,
			Tier:                r.Tier,
			Status:              string(status),
			ConsecutiveFailures: r.ConsecutiveFailures,
			LastSuccessAt:       r.LastSuccessAt,
		})
		if status.SetsSignalsStale() {
			report.SignalsStale = true
		}
		if status == domain.FeedDegraded {
			report.DegradedFeeds = append(report.DegradedFeeds, r.Source)
		}
	}
	return report, nil
}
