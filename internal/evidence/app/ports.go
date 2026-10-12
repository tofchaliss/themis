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
	// GetRawDocument returns a document's kind + raw stored bytes (the read path Knowledge
	// uses to parse an uploaded VEX — EDR-VEX-01 D1; Evidence serves, never parses).
	GetRawDocument(ctx context.Context, id domain.EvidenceID) (kind string, doc []byte, err error)
}

// EvidenceSummary is a list-view row for evidence filed against a release.
type EvidenceSummary struct {
	ID               domain.EvidenceID
	Kind             domain.Kind
	Fingerprint      string
	ProvenanceSource string
	FiledAt          time.Time
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

// ReleaseResolver resolves the release an intake names — either directly by
// `release_id`, or by the {product, project, version} triple — and returns the
// canonical release id (EDR-INTAKE-01 D7).
//
// It is READ-ONLY, and that is the decision, not an implementation detail: intake
// never creates Registry identity. A write from Evidence into Registry is neither an
// event nor a read, and no convenience justifies punching through that — a
// create-if-missing flag would let one typo in a product name silently fork the
// estate graph, which is the thing Registry exists to prevent.
//
// An unresolvable release is reported with [domain.Reject] carrying
// [domain.ReasonUnknownRelease] and a detail naming which of the three was not found.
type ReleaseResolver interface {
	Resolve(ctx context.Context, product, project, version, releaseID string) (string, error)
}

// InventoryReader answers D6's precondition: does an Evidence document of
// `kind=sbom` exist whose subject release is this one?
//
// It is a single boolean because Evidence's own inventory has exactly two states.
// `Register` parses inline and `Save` writes the row and its canonical inventory in
// ONE transaction, and the domain refuses an SBOM that parsed to zero components —
// so "uploaded but not parsed" and "parsed but empty" do not exist here, and the
// five states a reviewer might distinguish collapse to two. The check is
// release-scoped by construction, so another release's inventory can never satisfy it.
type InventoryReader interface {
	HasInventory(ctx context.Context, releaseID string) (bool, error)
}

// ReportStats counts what a conversion saw: FindingsTotal source records considered,
// FindingsSkipped of them refused by the converter's row-level skip rule. Both are
// carried, never just the kept count — "427 of 427" and "427 of 500" must not look
// alike, which is the whole of the silent-skip class (KN-SCAN-OBS-1).
type ReportStats struct {
	FindingsTotal   int
	FindingsSkipped int
}

// ReportRegistry is the converter ACL as the app ring sees it (EDR-INTAKE-01
// D4/D5): identification and conversion of a submitted vendor dialect into the one
// curated document Themis files. It is implemented by `adapters/report`, which the
// app must not import — a vendor shape never reaches these rings, and neither does
// the package that understands one.
//
// Kind and dialect cross as plain strings for the same reason: they are the ACL's
// vocabulary (`sbom` / `vuln-report`, `spdx` / `cortex-csv` / …) echoed back to the
// client as `detected_kind` and `detected_format`, not Evidence's own kinds.
// [IntakeService] maps the former onto the latter and refuses a kind it cannot place.
//
// Both methods report a refusal with [domain.Reject], so the closed taxonomy is the
// only vocabulary that crosses the boundary. An error carrying no reason is an
// infrastructure fault, and the caller must not invent a reason for it.
type ReportRegistry interface {
	// Detect names the body: D5a's closed, ordered table, first match wins.
	// Identification is not admission — a named body has only earned the right to be
	// validated against its dialect's rules.
	Detect(contentType string, body []byte) (kind, dialect string, err error)

	// Convert produces the curated document plus the provenance of the conversion:
	// which converter version produced it, and the digest of the bytes that arrived
	// (which, for a converted submission, are not the bytes filed).
	//
	// It is pure in (body, suppliedObservedAt) — no clock. A supplied timestamp is
	// the caller's assertion about WHICH observation this is and wins over
	// derivation; with neither available the refusal is `observed_at_underivable`,
	// never the upload time (D3).
	Convert(dialect string, body []byte, suppliedObservedAt time.Time) (curated []byte, stats ReportStats, convertedBy, sourceDigest string, err error)
}

// EvidenceRegistrar is the one write intake performs, and it is deliberately the
// EXISTING Register use case rather than a second writer: the trust gate,
// fingerprinting, the aggregate's invariants and the outbox note in one transaction
// are what "filed" means, and a parallel path into the store would be a second
// definition of it. Satisfied by *EvidenceService as-is.
type EvidenceRegistrar interface {
	Register(ctx context.Context, cmd RegisterCommand) (RegisterResult, error)
}
