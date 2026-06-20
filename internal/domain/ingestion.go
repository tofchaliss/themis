package domain

import (
	"context"
	"errors"
	"time"
)

// Ingestion lifecycle states persisted through the pipeline.
type IngestionStatus string

const (
	IngestionStatusReceived    IngestionStatus = "RECEIVED"
	IngestionStatusValidating  IngestionStatus = "VALIDATING"
	IngestionStatusCorrelating IngestionStatus = "CORRELATING"
	IngestionStatusEnriching   IngestionStatus = "ENRICHING"
	IngestionStatusCompleted   IngestionStatus = "COMPLETED"
	IngestionStatusNotified    IngestionStatus = "NOTIFIED"
	IngestionStatusRejected    IngestionStatus = "REJECTED"
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
	ArtifactID     string
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

// SaveSBOMInput persists a parsed SBOM composition (one `sboms` row keyed
// (artifact_id, sbom_checksum)) plus one `scan_reports` row for the correlation run.
type SaveSBOMInput struct {
	ArtifactID       string
	ImageDigest      string
	SBOMChecksum     string
	ScanChecksum     string
	Format           string
	SpecVersion      string
	Scanner          string
	TrustResult      TrustResult
	RawDocument      []byte
	Canonical        CanonicalSBOM
	CIJobID          string
	CIPipelineURL    string
	SupplierIdentity string
}

// SaveSBOMResult identifies the composition and scan rows written by SaveSBOM.
type SaveSBOMResult struct {
	SBOMID       string
	ScanReportID string
	// Duplicate is true when an idempotent re-submission matched an existing
	// (sbom_id, scan_checksum) scan; no new scan was appended (D12).
	Duplicate bool
}

// SaveVEXInput persists a parsed VEX document. VEX references the artifact, not a scan row.
type SaveVEXInput struct {
	ArtifactID       string
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

// SBOMStore persists SBOM and VEX documents. A single SBOM ingest writes one
// composition (`sboms`) row and one `scan_reports` row (D2); SaveSBOM returns both.
type SBOMStore interface {
	SaveSBOM(ctx context.Context, input SaveSBOMInput) (SaveSBOMResult, error)
	SaveVEX(ctx context.Context, input SaveVEXInput) (documentID string, err error)
	// FindArtifactBySBOMChecksum resolves the artifact owning an uploaded SBOM by its
	// checksum, used to link an ingested VEX document to its artifact.
	FindArtifactBySBOMChecksum(ctx context.Context, sbomChecksum string) (artifactID string, err error)
}

// ComponentStore upserts parsed components for an SBOM composition row.
type ComponentStore interface {
	UpsertFromCanonical(ctx context.Context, sbomID string, sbom CanonicalSBOM) (map[string]string, error)
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

// CreateFindingInput is one correlated finding written against a scan report. It
// carries the denormalized version-qualified component_purl and cve_id (D11) so the
// stable identity (artifact_id, component_purl, cve_id) can be formed downstream.
type CreateFindingInput struct {
	ComponentVersionID string
	VulnerabilityID    string
	ScanReportID       string
	ComponentPURL      string
	CVEID              string
}

// CorrelationRepository links components to vulnerabilities within a scan report.
type CorrelationRepository interface {
	CreateFinding(ctx context.Context, input CreateFindingInput) (string, error)
	ListFindings(ctx context.Context, scanReportID string) ([]ComponentFinding, error)
}

// ComponentFinding is a correlated vulnerability finding for enrichment.
type ComponentFinding struct {
	ID            string
	ArtifactID    string
	ComponentPURL string
	CVEID         string
	Severity      string
}

// RiskContextRepository creates risk context records keyed on the stable identity
// (artifact_id, component_purl, cve_id) so triage survives rescans (D3).
type RiskContextRepository interface {
	CreateForFinding(ctx context.Context, artifactID, componentPURL, cveID, severity string) error
}

// IngestionNotifier dispatches ingestion completion notifications.
type IngestionNotifier interface {
	NotifyComplete(ctx context.Context, result IngestionResult) error
}

// IsRetryable reports whether an error should trigger job retry.
func IsRetryable(err error) bool {
	return errors.Is(err, ErrRetryable)
}
