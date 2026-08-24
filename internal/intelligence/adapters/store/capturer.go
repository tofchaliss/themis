package store

// Capturer adapts the Store to the app's InvocationCapturer port (Δ4a D-Δ4a-5). It writes each
// completed invocation — already redacted by the Gateway — to invocation_log, best-effort: a
// write failure is logged-and-swallowed by the app contract, never surfaced. It exists only when
// the node has a Store (the stateless Gateway captures nothing, as it persists nothing).

import (
	"context"

	"github.com/themis-project/themis/internal/intelligence/app"
)

// Capturer implements app.InvocationCapturer over the Store.
type Capturer struct{ store *Store }

// NewCapturer builds the capture adapter.
func NewCapturer(s *Store) *Capturer { return &Capturer{store: s} }

// Capture writes one redacted invocation to the log. Errors are dropped: the app calls this
// best-effort and must never have an invocation affected by a capture failure.
func (c *Capturer) Capture(ctx context.Context, rec app.CapturedInvocation) {
	_ = c.store.AppendInvocation(ctx, LoggedInvocation{
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
}

var _ app.InvocationCapturer = (*Capturer)(nil)
