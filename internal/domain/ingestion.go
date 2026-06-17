package domain

import (
	"context"
	"errors"
	"time"
)

// Ingestion lifecycle states persisted through the pipeline.
type IngestionStatus string

const (
	IngestionStatusReceived   IngestionStatus = "RECEIVED"
	IngestionStatusValidating IngestionStatus = "VALIDATING"
	IngestionStatusCorrelating IngestionStatus = "CORRELATING"
	IngestionStatusEnriching   IngestionStatus = "ENRICHING"
	IngestionStatusCompleted  IngestionStatus = "COMPLETED"
	IngestionStatusNotified   IngestionStatus = "NOTIFIED"
	IngestionStatusRejected   IngestionStatus = "REJECTED"
	IngestionStatusFailed      IngestionStatus = "FAILED"
)

// IngestionInput is the domain input for SBOM and VEX ingestion.
type IngestionInput struct {
	RawArtifact
	IdempotencyKey string
	IngestionID    string
	TrustPolicy    TrustPolicy
	ProductID      string
	ProjectID      string
	ImageID        string
}

// IngestionRecord tracks persisted ingestion lifecycle metadata.
type IngestionRecord struct {
	ID             string
	JobType        JobType
	Status         IngestionStatus
	IdempotencyKey string
	ScanID         string
	StageDetail    string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// IngestionResult is returned to callers after ingestion completes or short-circuits.
type IngestionResult struct {
	IngestionID string
	ScanID      string
	Status      IngestionStatus
	Duplicate   bool
	Message     string
	Retryable   bool
}

// VulnerabilityRecord is a normalized CVE stored in the local cache.
type VulnerabilityRecord struct {
	ID               string
	CVEID            string
	Severity         string
	CVSSScore        float64
	CVSSVector       string
	Ecosystem        string
	PackageName      string
	AffectedVersions []string
	FixVersions      []string
}

// SaveSBOMInput persists a parsed SBOM document and related metadata.
type SaveSBOMInput struct {
	ImageID           string
	ProjectID         string
	ImageDigest       string
	ChecksumSHA256    string
	Format            string
	SpecVersion       string
	TrustResult       TrustResult
	RawDocument       []byte
	Canonical         CanonicalSBOM
	CIJobID           string
	CIPipelineURL     string
	SupplierIdentity  string
}

// SaveVEXInput persists a parsed VEX document.
type SaveVEXInput struct {
	SBOMDocumentID   string
	SBOMChecksum     string
	ChecksumSHA256   string
	Format           string
	SpecVersion      string
	TrustResult      TrustResult
	RawDocument      []byte
	SupplierIdentity string
}

// ErrRetryable marks pipeline failures that may be retried.
var ErrRetryable = errors.New("retryable ingestion failure")

// IngestionRepository persists ingestion lifecycle state and idempotency keys.
type IngestionRepository interface {
	FindByIdempotencyKey(ctx context.Context, key string) (IngestionRecord, bool, error)
	Create(ctx context.Context, record IngestionRecord) error
	UpdateStatus(ctx context.Context, id string, status IngestionStatus, detail, scanID string) error
	Get(ctx context.Context, id string) (IngestionRecord, error)
}

// TrustGateEvaluator runs artifact trust validation.
type TrustGateEvaluator interface {
	Evaluate(ctx context.Context, artifact RawArtifact, policy TrustPolicy) GateOutcome
}

// SBOMParserPort normalizes raw SBOM documents.
type SBOMParserPort interface {
	Parse(ctx context.Context, format, specVersion string, raw []byte) ParseOutcome
}

// SBOMStore persists SBOM and VEX documents.
type SBOMStore interface {
	SaveSBOM(ctx context.Context, input SaveSBOMInput) (documentID string, err error)
	SaveVEX(ctx context.Context, input SaveVEXInput) (documentID string, err error)
	FindDocumentIDByChecksum(ctx context.Context, checksum string) (string, error)
}

// ComponentStore upserts parsed components for an SBOM document.
type ComponentStore interface {
	UpsertFromCanonical(ctx context.Context, sbomDocumentID string, sbom CanonicalSBOM) (map[string]string, error)
}

// VulnerabilityCatalog reads CVE data from the local cache.
type VulnerabilityCatalog interface {
	FindMatches(ctx context.Context, ecosystem, name, version string) ([]VulnerabilityRecord, error)
	Upsert(ctx context.Context, record VulnerabilityRecord) (string, error)
}

// VulnerabilityFetcher retrieves CVE data from external feeds for cache population.
type VulnerabilityFetcher interface {
	FetchForComponent(ctx context.Context, component CanonicalComponent) ([]VulnerabilityRecord, error)
}

// CorrelationSummaryEmitter flushes deferred OSV correlation skip summaries.
type CorrelationSummaryEmitter interface {
	EmitCorrelationSummary()
}

// CorrelationRepository links components to vulnerabilities within an SBOM.
type CorrelationRepository interface {
	CreateFinding(ctx context.Context, componentVersionID, vulnerabilityID, sbomDocumentID string) (string, error)
	ListFindings(ctx context.Context, sbomDocumentID string) ([]ComponentFinding, error)
}

// ComponentFinding is a correlated vulnerability finding for enrichment.
type ComponentFinding struct {
	ID       string
	Severity string
}

// RiskContextRepository creates risk context records for findings.
type RiskContextRepository interface {
	CreateForFinding(ctx context.Context, componentVulnerabilityID, severity string) (string, error)
}

// IngestionNotifier dispatches ingestion completion notifications.
type IngestionNotifier interface {
	NotifyComplete(ctx context.Context, result IngestionResult) error
}

// IsRetryable reports whether an error should trigger job retry.
func IsRetryable(err error) bool {
	return errors.Is(err, ErrRetryable)
}
