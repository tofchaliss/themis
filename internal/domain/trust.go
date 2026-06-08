package domain

import "context"

// TrustStatus records artifact trust evaluation outcome.
type TrustStatus string

const (
	TrustStatusVerified   TrustStatus = "verified"
	TrustStatusUnverified TrustStatus = "unverified"
	TrustStatusUnsigned   TrustStatus = "unsigned"
	TrustStatusFailed     TrustStatus = "failed"
)

// TrustPolicy governs signature, provenance, and supplier requirements.
type TrustPolicy string

const (
	TrustPolicyStrict     TrustPolicy = "strict"
	TrustPolicyStandard   TrustPolicy = "standard"
	TrustPolicyPermissive TrustPolicy = "permissive"
)

// ArtifactKind distinguishes SBOM and VEX ingestion paths.
type ArtifactKind string

const (
	ArtifactKindSBOM ArtifactKind = "sbom"
	ArtifactKindVEX  ArtifactKind = "vex"
)

// RawArtifact is the untrusted input evaluated by the trust gate.
type RawArtifact struct {
	Kind             ArtifactKind
	Format           string
	SpecVersion      string
	RawDocument      []byte
	ExpectedChecksum string
	Signature        string
	CIJobID          string
	CIPipelineURL    string
	SupplierIdentity string
	ImageDigest      string
	SBOMChecksum     string
	ProductOwner     string
	TrustedSuppliers []string
	Actor            string
	SourceIP         string
}

// TrustResult captures trust gate outputs persisted with the artifact.
type TrustResult struct {
	Status            TrustStatus
	SignatureVerified bool
	ChecksumSHA256    string
	Warnings          []string
}

// GateOutcome is the trust gate decision returned to callers.
type GateOutcome struct {
	Accepted    bool
	HTTPStatus  int
	Result      TrustResult
	DuplicateID string
	Message     string
}

// AuditEntry records a security-sensitive trust gate event.
type AuditEntry struct {
	Actor        string
	Action       string
	ResourceType string
	ResourceID   string
	Details      map[string]string
	SourceIP     string
}

const (
	AuditActionArtifactAccepted  = "ARTIFACT_ACCEPTED"
	AuditActionArtifactRejected  = "ARTIFACT_REJECTED"
	AuditActionArtifactWarning   = "ARTIFACT_WARNING"
	AuditActionSignatureFailure  = "SIGNATURE_FAILURE"
)

// SignatureVerifier validates artifact signatures. Phase 1 uses a stub implementation.
type SignatureVerifier interface {
	Verify(ctx context.Context, artifact RawArtifact) (TrustResult, error)
}

// TrustRepository supports deduplication and integrity chain checks.
type TrustRepository interface {
	FindSBOMByDedupKey(ctx context.Context, imageDigest, checksumSHA256 string) (documentID string, found bool, err error)
	FindVEXByDedupKey(ctx context.Context, sbomChecksum, checksumSHA256 string) (documentID string, found bool, err error)
	ImageDigestExists(ctx context.Context, digest string) (bool, error)
	SBOMChecksumExists(ctx context.Context, checksum string) (bool, error)
}

// AuditRecorder persists trust gate audit events.
type AuditRecorder interface {
	Record(ctx context.Context, entry AuditEntry) error
}
