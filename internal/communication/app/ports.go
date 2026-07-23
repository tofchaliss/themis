package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// ErrConcurrent is returned when an optimistic-concurrency save loses the race (a concurrent
// re-publish superseded the same prior Publication first); the service retries.
var ErrConcurrent = errors.New("communication: concurrent modification")

// ErrPositionNotFound is returned when a publish is triggered for a Finding whose Enterprise
// Position cannot be fetched from Governance (no decision yet).
var ErrPositionNotFound = errors.New("communication: position not found")

// Communication integration/audit event types (D8) — thin, terminal completed facts.
const (
	EventPublicationCreated    = "communication.publication_created"
	EventPublicationDelivered  = "communication.publication_delivered"
	EventPublicationSuperseded = "communication.publication_superseded"
)

// OutboxNote is one terminal audit event queued for delivery in the aggregate's own
// transaction (D8 · BCK-0041); the relay delivers it exactly-once-eventually.
type OutboxNote struct {
	EventType  string
	Event      any
	OccurredAt time.Time
}

// PositionReader fetches an Enterprise Position (+ lineage) from Governance's read API (D2)
// — never Governance's tables. found=false when the Finding has no current Position.
type PositionReader interface {
	GetPosition(ctx context.Context, findingID string) (domain.PositionSnapshot, bool, error)
}

// Serializers renders an abstract artifact into bytes for a format (D7). The serializer
// registry implements it.
type Serializers interface {
	Render(format string, art domain.Artifact) ([]byte, error)
}

// QueueEntry is one row of the publishable-positions worklist projection (D4/D10): the
// latest Position version for a Finding, and whether it is a revision that has gone stale
// (needs re-publish).
type QueueEntry struct {
	FindingID   string
	ReleaseID   string
	FaultlineID string
	CVE         string
	Version     int
	Stance      domain.Stance
	Stale       bool
}

// Repository is the Publication aggregate-root store (BCK-0042). Content is immutable; only
// delivery status + the superseded-by link mutate, guarded by optimistic concurrency
// (BCK-0043). It also owns the publishable-positions queue projection.
type Repository interface {
	// CurrentPublication returns the latest non-superseded Publication for the identity
	// tuple (Release, Faultline, artifact-type, audience) — the one a re-publish supersedes
	// (D5); found=false if none.
	CurrentPublication(ctx context.Context, releaseID, faultlineID string, typ domain.ArtifactType, audience string) (domain.Publication, bool, error)
	// GetByID loads a Publication by its identity.
	GetByID(ctx context.Context, id domain.PublicationID) (domain.Publication, error)
	// Save records the new Publication, optionally supersedes a prior one (version-guarded by
	// priorPrevVersion → ErrConcurrent on mismatch), and writes the outbox notes — all
	// atomically (D6/D9).
	Save(ctx context.Context, pub domain.Publication, prior *domain.Publication, priorPrevVersion int, notes []OutboxNote) error
	// MarkPublishable upserts the publishable-positions queue projection (D4).
	MarkPublishable(ctx context.Context, entry QueueEntry) error
	// UndeliveredPublications returns Publications awaiting delivery (pending or failed) — the
	// durable delivery queue (D6) — up to limit, oldest first.
	UndeliveredPublications(ctx context.Context, limit int) ([]domain.Publication, error)
	// UpdateDelivery persists a delivery-status change (version-guarded) + outbox notes,
	// atomically. A version mismatch returns ErrConcurrent.
	UpdateDelivery(ctx context.Context, pub domain.Publication, prevVersion int, notes []OutboxNote) error
	// ListByRelease returns all Publications for a Release, newest first (D10).
	ListByRelease(ctx context.Context, releaseID string) ([]domain.Publication, error)
	// PublishableQueue returns the analyst worklist projection (D4/D10).
	PublishableQueue(ctx context.Context) ([]QueueEntry, error)
	// PrunePayloads drops the rendered payload bytes of delivered Publications recorded
	// before the cutoff (the retention cap — D1); the permanent lineage metadata is kept and
	// the payload stays regenerable. Returns how many were pruned.
	PrunePayloads(ctx context.Context, before time.Time) (int, error)
}

// Deliverer delivers a Publication's (redacted) artifact bytes on its channel (D6).
// Implementations are idempotent per (Publication, channel) so retries never double-send.
type Deliverer interface {
	Deliver(ctx context.Context, pub domain.Publication, payload []byte) error
}

// Redactor removes sensitive content before external delivery (D6).
type Redactor interface {
	Redact(payload []byte) []byte
}

// IDGenerator assigns new opaque Publication identities.
type IDGenerator interface {
	NewID() string
}

// Clock supplies the current time (injectable for tests).
type Clock interface {
	Now() time.Time
}
