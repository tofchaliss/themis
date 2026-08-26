package store

// Capturer adapts the Store to the app's InvocationCapturer port (Δ4a D-Δ4a-5). It writes each
// completed invocation — already redacted by the Gateway — to invocation_log, best-effort: a
// write failure is logged-and-swallowed by the app contract, never surfaced. It exists only when
// the node has a Store (the stateless Gateway captures nothing, as it persists nothing).

import (
	"context"

	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Capturer implements app.InvocationCapturer over the Store.
type Capturer struct {
	store  *Store
	logger *observability.Logger // optional; a capture failure is LOGGED, never surfaced
}

// NewCapturer builds the capture adapter.
func NewCapturer(s *Store) *Capturer { return &Capturer{store: s} }

// WithLogger makes a capture failure VISIBLE (best-effort-but-logged) and returns the capturer.
// A silent best-effort once hid a TOTAL capture failure (a JSONB column rejected a redacted,
// non-JSON string, measured 2026-08-26). Swallowing the error is right — capture must never fail
// an invocation — but swallowing it SILENTLY hid the bug; a log line makes the next one visible.
func (c *Capturer) WithLogger(l *observability.Logger) *Capturer {
	c.logger = l
	return c
}

// Capture writes one redacted invocation to the log. A write failure is logged and swallowed:
// the app calls this best-effort and must never have an invocation affected by a capture failure.
func (c *Capturer) Capture(ctx context.Context, rec app.CapturedInvocation) {
	err := c.store.AppendInvocation(ctx, LoggedInvocation{
		CorrelationID: rec.CorrelationID,
		Capability:    rec.Capability,
		PromptVersion: rec.PromptVersion,
		Model:         rec.Model,
		Tier:          rec.Tier,
		ContextJSON:   rec.ContextJSON,
		OutputJSON:    rec.OutputJSON,
		Reason:        rec.Reason,
		DeclineClass:  rec.DeclineClass,
		Tokens:        rec.Tokens,
	})
	if err != nil && c.logger != nil {
		c.logger.Warn("Δ4a capture write failed (invocation unaffected)",
			observability.String("correlation_id", rec.CorrelationID), observability.Err(err))
	}
}

var _ app.InvocationCapturer = (*Capturer)(nil)
