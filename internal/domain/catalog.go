package domain

import (
	"context"
	"time"
)

// Product is a top-level tenant boundary.
type Product struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
}

// Project belongs to a product.
type Project struct {
	ID          string
	ProductID   string
	Name        string
	Description string
	CreatedAt   time.Time
}

// ProductVersion tracks release lines, parented by a project (versions table).
type ProductVersion struct {
	ID            string
	ProjectID     string
	Version       string
	ReleaseStatus string
	ReleasedAt    *time.Time
	CreatedAt     time.Time
}

// Artifact is a registered scan target identified by its globally-unique image
// digest (the merged artifacts+images entity). It belongs to exactly one version.
type Artifact struct {
	ID           string
	VersionID    string
	ArtifactType string
	ImageDigest  string
	Repository   string
	Tag          string
	CreatedAt    time.Time
}

// ScanSummary is an SBOM ingestion record exposed as a scan.
type ScanSummary struct {
	ID          string
	ProjectID   string
	ProductID   string
	ImageDigest string
	Format      string
	TrustStatus string
	IngestedAt  time.Time
	IngestionID string
}

// ScanDetail extends ScanSummary with vulnerability counts.
type ScanDetail struct {
	ScanSummary
	VulnerabilityCounts map[string]int
}

// ScanVulnerabilityEnrichment holds Phase 2a signal fields from risk_context.
type ScanVulnerabilityEnrichment struct {
	ExploitPublic       *bool
	RiskScore           *float64
	EPSSScore           *float64
	KEVListed           *bool
	DeterministicLevel  *string
	BlastRadiusScore    *float64
	UpstreamVEXCoverage *string
}

// ScanVulnerability is a correlated finding for a scan.
type ScanVulnerability struct {
	ID               string
	CVEID            string
	Severity         string
	EffectiveState   string
	ComponentPURL    string
	ProductID        string
	InstalledVersion string
	FixedVersion     string
	Enrichment       *ScanVulnerabilityEnrichment
}

// CatalogComponent is a component catalog entry.
type CatalogComponent struct {
	PURL      string
	Name      string
	Ecosystem string
	Version   string
	ProductID string
}

// CVEWatchFinding is a background CVE watch match.
type CVEWatchFinding struct {
	ID         string
	CVEID      string
	ProductID  string
	ProjectID  string
	Status     string
	DetectedAt time.Time
}

// NotificationRule configures outbound alerts.
type NotificationRule struct {
	ID          string
	Name        string
	EventType   string
	Channel     string
	Destination string
	Filter      NotificationRuleFilter
	Enabled     bool
}

// ScannerSettings controls parser limits exposed via the API.
type ScannerSettings struct {
	EnabledFormats      []string
	MaxComponents       int
	ParseTimeoutSeconds int
}

// TriageDecision records a human triage outcome.
type TriageDecision struct {
	FindingID      string
	Decision       string
	Justification  string
	AcceptedUntil  *time.Time
	AssignedTo     string
	Actor          string
	EffectiveState string
}

// TriageHistoryEntry is an append-only triage audit record.
type TriageHistoryEntry struct {
	Decision      string
	Justification string
	Actor         string
	AssignedTo    string
	RecordedAt    time.Time
}

// PageRequest controls cursor pagination.
type PageRequest struct {
	Cursor string
	Limit  int
}

// PageResult carries the next cursor when more rows exist.
type PageResult struct {
	NextCursor string
}

// APIKeyRecord is a stored API key metadata row.
type APIKeyRecord struct {
	ID        string
	Name      string
	KeyHash   string
	Scopes    []string
	ExpiresAt *time.Time
	RevokedAt *time.Time
}

// APIKeyCreateInput carries persisted API key metadata.
type APIKeyCreateInput struct {
	Name      string
	KeyHash   string
	Scopes    []string
	ExpiresAt *time.Time
}

// AuthPrincipal is resolved from a valid API key.
type AuthPrincipal struct {
	KeyID  string
	Scopes []string
}

// ScopeAdmin grants global access.
const ScopeAdmin = "admin"

// ScopeReadOnly restricts mutating configuration endpoints.
const ScopeReadOnly = "read"

// ProductScopePrefix prefixes product-scoped keys.
const ProductScopePrefix = "product:"

// ProductCatalogRepository manages products, projects, versions, and artifacts.
type ProductCatalogRepository interface {
	// CreateProduct creates a product and its auto-created default project.
	CreateProduct(ctx context.Context, name, description string) (Product, error)
	ListProducts(ctx context.Context, page PageRequest, productScope string) ([]Product, PageResult, error)
	GetProduct(ctx context.Context, id string) (Product, error)
	CreateProject(ctx context.Context, productID, name, description string) (Project, error)
	ListProjects(ctx context.Context, productID string, page PageRequest) ([]Project, PageResult, error)
	ListProductVersions(ctx context.Context, productID string, page PageRequest) ([]ProductVersion, PageResult, error)
	// CreateVersion creates a version under a project (ErrProjectNotFound /
	// ErrVersionConflict).
	CreateVersion(ctx context.Context, projectID, version string) (ProductVersion, error)
	// RegisterArtifact registers an artifact by image_digest under the product's
	// default project, resolving (or creating) the target version. A duplicate
	// digest returns the existing artifact (digest is globally unique).
	RegisterArtifact(ctx context.Context, productID, version, imageDigest, repository string) (Artifact, error)
}

// ScanQueryRepository reads scan and vulnerability data.
type ScanQueryRepository interface {
	ListProjectScans(ctx context.Context, projectID string, page PageRequest) ([]ScanSummary, PageResult, error)
	GetScan(ctx context.Context, id string) (ScanDetail, error)
	ListScanVulnerabilities(ctx context.Context, scanID string, filter ScanVulnerabilityFilter, page PageRequest) ([]ScanVulnerability, PageResult, error)
	// ListScopedVulnerabilities lists the current findings (latest scan per artifact,
	// via v_latest_findings) for a product, project, or product version.
	ListScopedVulnerabilities(ctx context.Context, scope FindingScope, filter ScanVulnerabilityFilter, page PageRequest) ([]ScanVulnerability, PageResult, error)
	GetProjectProductID(ctx context.Context, projectID string) (string, error)
}

// FindingScopeKind selects the level a scoped vulnerability query rolls findings up to.
type FindingScopeKind string

const (
	// FindingScopeProduct lists findings across every artifact under a product.
	FindingScopeProduct FindingScopeKind = "product"
	// FindingScopeProject lists findings across every artifact under a project.
	FindingScopeProject FindingScopeKind = "project"
	// FindingScopeVersion lists findings for one product version.
	FindingScopeVersion FindingScopeKind = "version"
)

// FindingScope identifies the set of latest-scan findings to list. ProductID is set
// for product and version scopes, ProjectID for project scope, and Version pins a
// product version. Findings are listed per-artifact (the risk_context identity), so
// the same CVE on the same component may appear once per artifact under a product.
type FindingScope struct {
	Kind      FindingScopeKind
	ProductID string
	ProjectID string
	Version   string
}

// ScanVulnerabilityFilter narrows vulnerability list queries.
type ScanVulnerabilityFilter struct {
	Severity       string
	EffectiveState string
	CVEID          string
}

// ComponentCatalogRepository queries normalized components.
type ComponentCatalogRepository interface {
	ListComponents(ctx context.Context, purl, productID string, page PageRequest) ([]CatalogComponent, PageResult, error)
}

// CVEWatchFindingRepository lists background watch findings.
type CVEWatchFindingRepository interface {
	ListFindings(ctx context.Context, productID, severity string, page PageRequest) ([]CVEWatchFinding, PageResult, error)
}

// NotificationConfigRepository reads and writes routing rules.
type NotificationConfigRepository interface {
	ListRules(ctx context.Context) ([]NotificationRule, error)
	ReplaceRules(ctx context.Context, rules []NotificationRule) error
}

// ScannerConfigRepository reads and writes scanner settings.
type ScannerConfigRepository interface {
	Get(ctx context.Context) (ScannerSettings, error)
	Save(ctx context.Context, settings ScannerSettings) error
}

// APIKeyRepository validates and manages caller credentials.
type APIKeyRepository interface {
	FindByHashPrefix(ctx context.Context) ([]APIKeyRecord, error)
	FindActiveKeys(ctx context.Context) ([]APIKeyRecord, error)
	Create(ctx context.Context, input APIKeyCreateInput) (APIKeyRecord, error)
	Revoke(ctx context.Context, keyID string) error
}

// IngestionAsyncDispatcher enqueues ingestion work for background processing.
type IngestionAsyncDispatcher interface {
	EnqueueIngestion(ctx context.Context, input IngestionInput, jobType JobType) (string, error)
}
