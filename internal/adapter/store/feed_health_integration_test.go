//go:build integration

package store_test

import (
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/adapter/store"
)

func TestFeedHealthStoreLifecycle(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15469)
	s := store.NewPostgresFeedHealthStore(pool)

	// No feeds recorded yet → none degraded.
	if degraded, err := s.DegradedFeeds(ctx); err != nil || len(degraded) != 0 {
		t.Fatalf("initial degraded = %v err=%v", degraded, err)
	}

	// A successful feed is healthy, not degraded.
	if err := s.RecordFeedSuccess(ctx, "epss_kev"); err != nil {
		t.Fatal(err)
	}
	if degraded, err := s.DegradedFeeds(ctx); err != nil || len(degraded) != 0 {
		t.Fatalf("after success degraded = %v err=%v", degraded, err)
	}

	// Two consecutive failures degrade the feed and increment the streak.
	if err := s.RecordFeedFailure(ctx, "alpine", errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordFeedFailure(ctx, "alpine", errors.New("again")); err != nil {
		t.Fatal(err)
	}
	var failures int
	var lastErr string
	if err := pool.QueryRow(ctx, `SELECT consecutive_failures, last_error FROM feed_health WHERE feed = 'alpine'`).Scan(&failures, &lastErr); err != nil {
		t.Fatal(err)
	}
	if failures != 2 || lastErr != "again" {
		t.Fatalf("failures=%d lastErr=%q, want 2/again", failures, lastErr)
	}
	degraded, err := s.DegradedFeeds(ctx)
	if err != nil || len(degraded) != 1 || degraded[0] != "alpine" {
		t.Fatalf("degraded = %v err=%v, want [alpine]", degraded, err)
	}

	// A later success clears the streak.
	if err := s.RecordFeedSuccess(ctx, "alpine"); err != nil {
		t.Fatal(err)
	}
	if degraded, err := s.DegradedFeeds(ctx); err != nil || len(degraded) != 0 {
		t.Fatalf("after recovery degraded = %v err=%v", degraded, err)
	}
}
