package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// The release-evaluated event feed (EDR-DELIVERY-01 M2-4 / N-M2d): a subscriber — the
// runtime's poller, or anything else that wants to know when Themis finished judging a
// Release — reads it with a cursor instead of a bus subscription. The cursor is the SEQUENCE
// (ordered), the event id is the dedup key (identity); each does one job.

const (
	// ReleaseEvaluatedEventsDefaultLimit is the page size when the caller names none: a client
	// that omits it cannot ask for the table.
	ReleaseEvaluatedEventsDefaultLimit = 100
	// ReleaseEvaluatedEventsMaxLimit caps the page: a value above it is CLAMPED, not refused —
	// a paging hint is not a correctness claim.
	ReleaseEvaluatedEventsMaxLimit = 500
)

// ErrEventFeedUnavailable is returned when no event reader is wired: a feed that cannot be
// read must say so rather than answer an empty page a subscriber would read as "nothing
// happened".
var ErrEventFeedUnavailable = errors.New("release-evaluated event feed is not available on this node")

// ReleaseEvaluatedEvent is one stored governance.release_evaluated.v1 fact.
type ReleaseEvaluatedEvent struct {
	Seq        int64
	EventID    string
	Name       string
	OccurredAt time.Time
	// Body is the payload exactly as published; the app does not re-interpret it.
	Body json.RawMessage
}

// ReleaseEvaluatedEventsPage is one page of the feed. Next is the cursor to pass as `after` on
// the following call: the last item's seq, or the caller's own cursor when the page is empty,
// so a client can always store what it is handed.
type ReleaseEvaluatedEventsPage struct {
	Items []ReleaseEvaluatedEvent
	Next  int64
}

// ReleaseEvaluatedEventReader is the store port behind the feed.
type ReleaseEvaluatedEventReader interface {
	// ListReleaseEvaluatedEvents returns up to limit events with seq strictly greater than
	// after, in seq order.
	ListReleaseEvaluatedEvents(ctx context.Context, after int64, limit int) ([]ReleaseEvaluatedEvent, error)
}

// WithReleaseEvaluatedEvents attaches the feed's reader.
func (s *ReadService) WithReleaseEvaluatedEvents(r ReleaseEvaluatedEventReader) *ReadService {
	s.events = r
	return s
}

// ReleaseEvaluatedEvents serves one page of the feed. A negative cursor reads from the start;
// a non-positive limit takes the default and a limit above the cap is clamped.
func (s *ReadService) ReleaseEvaluatedEvents(ctx context.Context, after int64, limit int) (ReleaseEvaluatedEventsPage, error) {
	if s.events == nil {
		return ReleaseEvaluatedEventsPage{}, ErrEventFeedUnavailable
	}
	if after < 0 {
		after = 0
	}
	if limit <= 0 {
		limit = ReleaseEvaluatedEventsDefaultLimit
	}
	if limit > ReleaseEvaluatedEventsMaxLimit {
		limit = ReleaseEvaluatedEventsMaxLimit
	}
	items, err := s.events.ListReleaseEvaluatedEvents(ctx, after, limit)
	if err != nil {
		return ReleaseEvaluatedEventsPage{}, err
	}
	page := ReleaseEvaluatedEventsPage{Items: items, Next: after}
	if len(items) > 0 {
		page.Next = items[len(items)-1].Seq
	}
	return page, nil
}
