package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// ErrConcurrent is returned when an optimistic-concurrency save loses the race; the
// service's retry loop reloads and retries (BCK-0043). Additive changes + idempotent
// find-or-create make retries converge (D9).
var ErrConcurrent = errors.New("governance: concurrent modification")

// ErrUnauthorized is returned when an actor without decision authority attempts to accept
// or reject a proposal. The authority line is ADR-fixed (D11 / CON-0009): only an
// authorized human or a Governance-owned policy may decide; AI and system may propose only.
var ErrUnauthorized = errors.New("governance: actor may not decide")

// ErrInvalidMatch is returned when an inbound ComponentMatched lacks a Release or Faultline.
var ErrInvalidMatch = errors.New("governance: match missing release or faultline")

// Governance integration/audit event types (D8). Position events are the only ones
// Communication consumes; the rest are Governance-internal (audit / metrics / workflow).
const (
	EventFindingOpened       = "governance.finding_opened"
	EventFindingResolved     = "governance.finding_resolved"
	EventFindingReopened     = "governance.finding_reopened"
	EventFindingArchived     = "governance.finding_archived"
	EventProposalRaised      = "governance.proposal_raised"
	EventProposalAccepted    = "governance.proposal_accepted"
	EventProposalRejected    = "governance.proposal_rejected"
	EventPositionEstablished = "governance.position_established"
	EventPositionRevised     = "governance.position_revised"
)

// OutboxNote is one integration event queued for delivery in the aggregate's own
// transaction (D8 · BCK-0041); the relay delivers it exactly-once-eventually. The store
// serializes Event to the persisted JSON payload.
type OutboxNote struct {
	EventType  string
	Event      any
	OccurredAt time.Time
}

// Repository is the Finding aggregate-root store (BCK-0042), guarded by optimistic
// concurrency (BCK-0043). The Finding is loaded and saved whole (D9).
type Repository interface {
	// GetByKey loads the Finding for a (Release, Faultline) business key; found=false if
	// none exists (the find-or-create birth check — D5).
	GetByKey(ctx context.Context, releaseID, faultlineID string) (domain.Finding, bool, error)
	// GetByID loads the Finding by its own identity (with proposals + position history).
	GetByID(ctx context.Context, id domain.FindingID) (domain.Finding, error)
	// FindingsByFaultline lists the ids of every Finding referencing a Faultline — the
	// FaultlineEnriched fan-out (D6/D9: many small per-aggregate transactions, never one).
	FindingsByFaultline(ctx context.Context, faultlineID string) ([]domain.FindingID, error)
	// Save persists the aggregate + outbox notes atomically. created=true inserts a new
	// Finding; otherwise it updates guarded by prevVersion and returns ErrConcurrent on a
	// version mismatch. Appended proposals/positions are persisted idempotently by key.
	Save(ctx context.Context, f domain.Finding, created bool, prevVersion int, notes []OutboxNote) error
}

// PositionAdvisor is the caller-side seam to the Intelligence Gateway (D8/D13,
// Revision 2): given a Finding id it returns an advisory position recommendation, or
// produced=false for "no proposal" (AI disabled, unavailable, or declined — a safe
// outcome that never blocks). The disable gate is a wiring choice: a real client vs a
// no-op advisor. Intelligence owns no truth — Governance records the advice as its own
// (advisory) Proposal.
type PositionAdvisor interface {
	RecommendPosition(ctx context.Context, findingID string) (Recommendation, bool, error)
}

// Recommendation is the advisory content Intelligence returns, mapped into Governance's
// own vocabulary at the adapter boundary (no cross-context import).
type Recommendation struct {
	Stance     string
	Confidence float64
	Reasoning  string
	Capability string // originating capability ref, e.g. "recommend_position@v1"
}

// IDGenerator assigns new opaque Finding / Governance-Proposal identities.
type IDGenerator interface {
	NewID() string
}

// Clock supplies the current time (injectable for tests).
type Clock interface {
	Now() time.Time
}
