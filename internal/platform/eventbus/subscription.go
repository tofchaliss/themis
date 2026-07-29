package eventbus

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Subscription is a consumer's declared binding to the bus (EB-07 / D7): the single stream
// it consumes (the routing + ordering unit — one stream per producing context today) and its
// interest set (the event types it dispatches on). Stream and interest are opaque strings, so
// the platform stays business-agnostic — it carries no bounded-context knowledge.
//
// The three concerns D7 keeps separate map cleanly here: Stream is routing + ordering,
// Interest is pure dispatch (never routing/ordering), and the cursor (Reader-internal) is the
// read position. Narrowing Interest only changes which events are dispatched, never the order
// of the stream.
type Subscription struct {
	Consumer string   // the subscribing consumer id (owns the cursor + inbox)
	Stream   string   // the event_log.source_context this consumer reads
	Interest []string // the event types it acts on; other types in the stream are ignored
}

// InInterest reports whether eventType is in the interest set.
func (s Subscription) InInterest(eventType string) bool {
	for _, t := range s.Interest {
		if t == eventType {
			return true
		}
	}
	return false
}

// NewReader binds this subscription to a platform Reader over the bus pool, delivering the
// stream to handler (typically the context's inbox-wrapped Consumer). An interest filter sits
// in front of the handler so out-of-interest events are skipped as no-ops — before the inbox,
// so the consumer's processed_events records only events it actually applies. This is pure
// dispatch: the Reader still reads the whole stream in seq order, so skipping an out-of-
// interest event never reorders the rest (D7).
func (s Subscription) NewReader(busPool *pgxpool.Pool, logger *observability.Logger, handler Handler) *Reader {
	return NewReader(busPool, logger, ReaderConfig{Consumer: s.Consumer, Stream: s.Stream},
		interestFilter{sub: s, inner: handler})
}

// interestFilter drops events outside the subscription's interest set before they reach the
// inner handler.
type interestFilter struct {
	sub   Subscription
	inner Handler
}

func (f interestFilter) Handle(ctx context.Context, env event.Envelope) error {
	if !f.sub.InInterest(env.Type) {
		return nil // out of interest — a dispatch no-op, cursor advances past it
	}
	return f.inner.Handle(ctx, env)
}
