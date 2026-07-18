package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// TrustGate fingerprints and validates a raw artifact (implemented by adapters/trust).
type TrustGate interface {
	Admit(input TrustInput) (TrustOutcome, error)
}

// TrustInput is a raw artifact presented to the trust gate.
type TrustInput struct {
	Raw              []byte
	Kind             domain.Kind
	ExpectedChecksum string
	Provenance       domain.Provenance
}

// TrustOutcome is the trust gate's verdict.
type TrustOutcome struct {
	Fingerprint value.ContentFingerprint
	Status      domain.TrustStatus
	Provenance  domain.Provenance
	Reason      string
}

// Parser translates a raw SBOM of a supported standard into the canonical inventory
// (implemented by adapters/parser).
type Parser interface {
	Parse(ctx context.Context, format, specVersion string, raw []byte) (domain.Inventory, []string, error)
}

// SubjectRefValidator checks that a referenced Release exists. It is backed by the
// Shared Kernel registry (ReleaseExists); a stub stands in until that lands.
type SubjectRefValidator interface {
	ReleaseExists(ctx context.Context, releaseID string) (bool, error)
}

// Repository persists and reads Evidence aggregates (implemented by adapters/store).
type Repository interface {
	Save(ctx context.Context, e domain.Evidence, raw []byte, event domain.EvidenceRegistered) (id domain.EvidenceID, created bool, err error)
	GetByID(ctx context.Context, id domain.EvidenceID) (domain.Evidence, error)
	GetInventory(ctx context.Context, id domain.EvidenceID) (domain.Inventory, error)
	ListByRelease(ctx context.Context, releaseID string) ([]EvidenceSummary, error)
}

// EvidenceSummary is a list-view row for evidence filed against a release.
type EvidenceSummary struct {
	ID          domain.EvidenceID
	Kind        domain.Kind
	Fingerprint string
	FiledAt     time.Time
}

// IDGenerator assigns new opaque Evidence identities (implemented by an adapter
// using, e.g., a UUID source — the app itself stays free of that dependency).
type IDGenerator interface {
	NewID() domain.EvidenceID
}

// Clock supplies the current time (injectable for tests).
type Clock interface {
	Now() time.Time
}
