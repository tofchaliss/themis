//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/adapters/store"
)

func TestFeedHealthRecordAndRead(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))

	t0 := time.Unix(1_700_000_000, 0).UTC()

	// A failure then two more: the streak increments; a success resets it and stamps last_success.
	if err := s.RecordFeedFailure(ctx, "nvd", 1, t0); err != nil {
		t.Fatalf("failure 1: %v", err)
	}
	if err := s.RecordFeedFailure(ctx, "nvd", 1, t0.Add(time.Hour)); err != nil {
		t.Fatalf("failure 2: %v", err)
	}
	if err := s.RecordFeedSuccess(ctx, "osv", 2, t0); err != nil {
		t.Fatalf("osv success: %v", err)
	}

	rows, err := s.FeedHealthRows(ctx)
	if err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	byID := map[string]struct {
		tier    int
		fails   int
		hadSucc bool
	}{}
	for _, r := range rows {
		byID[r.Source] = struct {
			tier    int
			fails   int
			hadSucc bool
		}{r.Tier, r.ConsecutiveFailures, r.LastSuccessAt != nil}
	}
	if got := byID["nvd"]; got.tier != 1 || got.fails != 2 || got.hadSucc {
		t.Errorf("nvd = %+v, want tier1 fails=2 no-success", got)
	}
	if got := byID["osv"]; got.tier != 2 || got.fails != 0 || !got.hadSucc {
		t.Errorf("osv = %+v, want tier2 fails=0 with-success", got)
	}

	// A success on nvd resets its streak to 0.
	if err := s.RecordFeedSuccess(ctx, "nvd", 1, t0.Add(2*time.Hour)); err != nil {
		t.Fatalf("nvd success: %v", err)
	}
	rows, _ = s.FeedHealthRows(ctx)
	for _, r := range rows {
		if r.Source == "nvd" {
			if r.ConsecutiveFailures != 0 || r.LastSuccessAt == nil {
				t.Errorf("after success nvd = %+v, want fails=0 with-success", r)
			}
		}
	}
}
