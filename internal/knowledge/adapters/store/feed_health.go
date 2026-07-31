package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// RecordFeedSuccess upserts a clean sync for a feed source: it stamps last_success_at and
// clears the failure streak (the workers call this after a successful poll — B1).
func (s *Store) RecordFeedSuccess(ctx context.Context, source string, tier int, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO feed_health (source, tier, last_success_at, consecutive_failures, updated_at)
		 VALUES ($1, $2, $3, 0, $3)
		 ON CONFLICT (source) DO UPDATE
		   SET tier = EXCLUDED.tier,
		       last_success_at = EXCLUDED.last_success_at,
		       consecutive_failures = 0,
		       updated_at = EXCLUDED.updated_at`,
		source, tier, now)
	return err
}

// RecordFeedFailure upserts a failed sync for a feed source: it stamps last_failure_at and
// increments the failure streak (the workers call this when a poll errors — B1).
func (s *Store) RecordFeedFailure(ctx context.Context, source string, tier int, now time.Time) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO feed_health (source, tier, last_failure_at, consecutive_failures, updated_at)
		 VALUES ($1, $2, $3, 1, $3)
		 ON CONFLICT (source) DO UPDATE
		   SET tier = EXCLUDED.tier,
		       last_failure_at = EXCLUDED.last_failure_at,
		       consecutive_failures = feed_health.consecutive_failures + 1,
		       updated_at = EXCLUDED.updated_at`,
		source, tier, now)
	return err
}

// FeedHealthRows returns every feed's recorded health, ordered by source, for the read side to
// evaluate against each tier's staleness policy (app.FeedHealthService.Report).
func (s *Store) FeedHealthRows(ctx context.Context) ([]app.FeedHealthRow, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT source, tier, last_success_at, consecutive_failures
		   FROM feed_health
		  ORDER BY source`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.FeedHealthRow
	for rows.Next() {
		var r app.FeedHealthRow
		if err := rows.Scan(&r.Source, &r.Tier, &r.LastSuccessAt, &r.ConsecutiveFailures); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
