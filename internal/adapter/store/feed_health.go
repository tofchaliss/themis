package store

import (
	"context"
	"fmt"

	"github.com/themis-project/themis/internal/domain"
)

// PostgresFeedHealthStore persists per-feed health (CR-8) and answers the
// degraded-feeds query for the status API.
type PostgresFeedHealthStore struct {
	pool pgQueryPool
}

var (
	_ domain.FeedHealthRecorder = (*PostgresFeedHealthStore)(nil)
	_ domain.FeedHealthReader   = (*PostgresFeedHealthStore)(nil)
)

// NewPostgresFeedHealthStore creates a PostgreSQL feed-health store.
func NewPostgresFeedHealthStore(pool pgQueryPool) *PostgresFeedHealthStore {
	return &PostgresFeedHealthStore{pool: pool}
}

// RecordFeedSuccess marks a feed healthy: records the attempt and success times
// and clears the failure streak.
func (s *PostgresFeedHealthStore) RecordFeedSuccess(ctx context.Context, feed string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_health (feed, last_success_at, last_attempt_at, consecutive_failures, last_error)
		VALUES ($1, NOW(), NOW(), 0, '')
		ON CONFLICT (feed) DO UPDATE SET
			last_success_at = NOW(),
			last_attempt_at = NOW(),
			consecutive_failures = 0,
			last_error = ''
	`, feed)
	if err != nil {
		return fmt.Errorf("record feed success: %w", err)
	}
	return nil
}

// RecordFeedFailure records the attempt, increments the failure streak, and
// stores the error message.
func (s *PostgresFeedHealthStore) RecordFeedFailure(ctx context.Context, feed string, cause error) error {
	msg := ""
	if cause != nil {
		msg = cause.Error()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_health (feed, last_attempt_at, consecutive_failures, last_error)
		VALUES ($1, NOW(), 1, $2)
		ON CONFLICT (feed) DO UPDATE SET
			last_attempt_at = NOW(),
			consecutive_failures = feed_health.consecutive_failures + 1,
			last_error = $2
	`, feed, msg)
	if err != nil {
		return fmt.Errorf("record feed failure: %w", err)
	}
	return nil
}

// DegradedFeeds lists feeds with an active failure streak, ordered by name.
func (s *PostgresFeedHealthStore) DegradedFeeds(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT feed FROM feed_health WHERE consecutive_failures > 0 ORDER BY feed
	`)
	if err != nil {
		return nil, fmt.Errorf("list degraded feeds: %w", err)
	}
	defer rows.Close()

	var feeds []string
	for rows.Next() {
		var feed string
		if err := rows.Scan(&feed); err != nil {
			return nil, fmt.Errorf("scan degraded feed: %w", err)
		}
		feeds = append(feeds, feed)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate degraded feeds: %w", err)
	}
	return feeds, nil
}
