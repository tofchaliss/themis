package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
)

type fakeEventReader struct {
	calls []struct {
		after int64
		limit int
	}
	items []app.ReleaseEvaluatedEvent
	err   error
}

func (f *fakeEventReader) ListReleaseEvaluatedEvents(_ context.Context, after int64, limit int) ([]app.ReleaseEvaluatedEvent, error) {
	f.calls = append(f.calls, struct {
		after int64
		limit int
	}{after, limit})
	return f.items, f.err
}

// The feed's paging rules live here, not in the store or the handler: default 100, cap 500
// (clamped, never refused), a negative cursor reads from the start, and the next cursor is
// the last seq — or the caller's own cursor on an empty page (M2-4).
func TestReleaseEvaluatedEvents_PagingRules(t *testing.T) {
	ctx := context.Background()
	rd := &fakeEventReader{items: []app.ReleaseEvaluatedEvent{{Seq: 7, EventID: "e-7"}, {Seq: 9, EventID: "e-9"}}}
	svc := app.NewReadService(newRepo(), fakeProjection{}, nil, 0).WithReleaseEvaluatedEvents(rd)

	page, err := svc.ReleaseEvaluatedEvents(ctx, -5, 0)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if page.Next != 9 || len(page.Items) != 2 {
		t.Errorf("page = %+v, want next 9 over two items", page)
	}
	if c := rd.calls[0]; c.after != 0 || c.limit != app.ReleaseEvaluatedEventsDefaultLimit {
		t.Errorf("store asked with %+v, want after 0 (negative clamped) and the default limit", c)
	}

	if _, err := svc.ReleaseEvaluatedEvents(ctx, 3, 10_000); err != nil {
		t.Fatalf("read: %v", err)
	}
	if c := rd.calls[1]; c.after != 3 || c.limit != app.ReleaseEvaluatedEventsMaxLimit {
		t.Errorf("store asked with %+v, want the cap, not a refusal", c)
	}

	rd.items = nil
	page, err = svc.ReleaseEvaluatedEvents(ctx, 42, 5)
	if err != nil || page.Next != 42 || len(page.Items) != 0 {
		t.Errorf("empty page = %+v (err %v), want next = the caller's cursor 42", page, err)
	}
	if c := rd.calls[2]; c.limit != 5 {
		t.Errorf("an in-range limit must pass through, got %d", c.limit)
	}

	rd.err = errors.New("db down")
	if _, err := svc.ReleaseEvaluatedEvents(ctx, 0, 1); err == nil {
		t.Error("a store failure must surface, not read as an empty feed")
	}
}

// No reader wired is an error, never an empty page: "nothing happened" and "I cannot tell"
// must not look alike to a subscriber.
func TestReleaseEvaluatedEvents_UnwiredIsAnError(t *testing.T) {
	svc := app.NewReadService(newRepo(), fakeProjection{}, nil, 0)
	if _, err := svc.ReleaseEvaluatedEvents(context.Background(), 0, 1); !errors.Is(err, app.ErrEventFeedUnavailable) {
		t.Errorf("err = %v, want ErrEventFeedUnavailable", err)
	}
}
