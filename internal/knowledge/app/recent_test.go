package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
)

type fakeRecent struct {
	limit int
	out   []app.RecentFaultline
	err   error
}

func (f *fakeRecent) RecentFaultlines(_ context.Context, limit int) ([]app.RecentFaultline, error) {
	f.limit = limit
	return f.out, f.err
}

// GUI-16: the paging rules (default 50, cap 200 clamped) live here; an unwired lister is an
// error, not an empty page; a store failure surfaces.
func TestReadService_Recent(t *testing.T) {
	ctx := context.Background()
	rec := &fakeRecent{out: []app.RecentFaultline{{}, {}}}
	rs := app.NewReadService(newRepo(), fakeProjection{}).WithRecent(rec)
	out, err := rs.Recent(ctx, 0)
	if err != nil || len(out) != 2 || rec.limit != app.RecentDefaultLimit {
		t.Fatalf("default: %v / %d / limit %d", err, len(out), rec.limit)
	}
	if _, err := rs.Recent(ctx, 10_000); err != nil || rec.limit != app.RecentMaxLimit {
		t.Fatalf("clamp: %v / limit %d", err, rec.limit)
	}
	if _, err := rs.Recent(ctx, 7); err != nil || rec.limit != 7 {
		t.Fatalf("in range: %v / limit %d", err, rec.limit)
	}
	rec.err = errors.New("db down")
	if _, err := rs.Recent(ctx, 1); err == nil {
		t.Fatal("a store failure must surface")
	}
	if _, err := app.NewReadService(newRepo(), fakeProjection{}).Recent(ctx, 1); !errors.Is(err, app.ErrRecentUnavailable) {
		t.Fatalf("unwired: %v", err)
	}
}
