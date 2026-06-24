package domain

import (
	"context"
	"time"
)

// CR-8 — operator-facing feed health.
//
// Logs (CR-7) say what happened in the moment; feed_health persists the rolling
// status of every feed line so operators can answer "is my feeder working" from
// one API call (degraded_feeds[] on /status), not just EPSS/KEV staleness.

// FeedHealth is the persisted health of one feed line.
type FeedHealth struct {
	Feed                string
	LastSuccessAt       *time.Time
	LastAttemptAt       *time.Time
	ConsecutiveFailures int
	LastError           string
}

// FeedHealthRecorder records the outcome of a feed sync cycle. Each scheduler
// calls it on success (resets the failure streak) or failure (increments it).
type FeedHealthRecorder interface {
	RecordFeedSuccess(ctx context.Context, feed string) error
	RecordFeedFailure(ctx context.Context, feed string, cause error) error
}

// FeedHealthReader exposes feed health to the status API.
type FeedHealthReader interface {
	// DegradedFeeds returns the names of feeds with at least one consecutive
	// failure since their last success.
	DegradedFeeds(ctx context.Context) ([]string, error)
}

// NopFeedHealthRecorder discards health updates (default when none is wired).
type NopFeedHealthRecorder struct{}

// RecordFeedSuccess discards the update.
func (NopFeedHealthRecorder) RecordFeedSuccess(context.Context, string) error { return nil }

// RecordFeedFailure discards the update.
func (NopFeedHealthRecorder) RecordFeedFailure(context.Context, string, error) error { return nil }

// FeedHealthRecorderOrNop returns rec when non-nil, otherwise a no-op recorder.
func FeedHealthRecorderOrNop(rec FeedHealthRecorder) FeedHealthRecorder {
	if rec == nil {
		return NopFeedHealthRecorder{}
	}
	return rec
}
