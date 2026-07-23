package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// ErrConcurrent is returned when an optimistic-concurrency save loses the race; the
// caller (or the service's retry loop) reloads and retries.
var ErrConcurrent = errors.New("knowledge: concurrent modification")

// Knowledge integration-event types (D8). Thin payloads; consumers read detail via the
// read API.
const (
	EventFaultlineCreated    = "knowledge.faultline_created"
	EventFaultlineEnriched   = "knowledge.faultline_enriched"
	EventFaultlineMatured    = "knowledge.faultline_matured"
	EventFaultlineSuperseded = "knowledge.faultline_superseded"
	EventComponentMatched    = "knowledge.component_matched"
)

// OutboxNote is one integration event queued for delivery in the aggregate's own
// transaction (D8 · BCK-0041); the relay delivers it exactly-once-eventually. The
// store serializes Event to the persisted JSON payload.
type OutboxNote struct {
	EventType  string
	Event      any
	OccurredAt time.Time
}

// Repository is the Faultline aggregate-root store (BCK-0042), guarded by optimistic
// concurrency (BCK-0043).
type Repository interface {
	// GetByCVE loads the card for a canonical CVE; found=false if none exists.
	GetByCVE(ctx context.Context, cve string) (domain.Faultline, bool, error)
	// GetByID loads the card by its own identity.
	GetByID(ctx context.Context, id domain.FaultlineID) (domain.Faultline, error)
	// Save persists the aggregate + outbox notes atomically. created=true inserts a new
	// card; otherwise it updates guarded by prevVersion and returns ErrConcurrent on a
	// version mismatch. Newly-appended proposals are persisted idempotently by sequence.
	Save(ctx context.Context, f domain.Faultline, created bool, prevVersion int, notes []OutboxNote) error
}

// IDGenerator assigns new opaque Faultline identities.
type IDGenerator interface {
	NewID() string
}

// Clock supplies the current time (injectable for tests).
type Clock interface {
	Now() time.Time
}
