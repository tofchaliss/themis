package domain

import (
	"context"
	"time"
)

const (
	// SystemStateCVEWatchLastSuccess is the system_state key for the last successful CVE watch poll.
	SystemStateCVEWatchLastSuccess = "cve_watch_last_success"
)

// FeedVulnerability is a normalized CVE record from an external feed.
type FeedVulnerability struct {
	CVEID            string
	Severity         string
	CVSSScore        float64
	CVSSVector       string
	Ecosystem        string
	PackageName      string
	AffectedVersions []string
	FixVersions      []string
}

// WatchCatalogEntry is a component version (of an artifact's latest scan) tracked
// for CVE watch matching.
type WatchCatalogEntry struct {
	ComponentVersionID string
	PURL               string
	Name               string
	Ecosystem          string
	Version            string
	ProductID          string
	ProjectID          string
	ArtifactID         string
	ScanReportID       string
}

// CreateWatchFindingInput persists a CVE watch match against a scan report, using
// the version-qualified ComponentPURL for the stable risk_context identity.
type CreateWatchFindingInput struct {
	ComponentVersionID string
	VulnerabilityID    string
	ScanReportID       string
	ArtifactID         string
	CVEID              string
	Severity           string
	ProductID          string
	ProjectID          string
	ComponentPURL      string
}

// CreateWatchFindingResult reports whether a new finding row was created.
type CreateWatchFindingResult struct {
	ComponentVulnerabilityID string
	Created                  bool
}

// NVDCVEFeedClient fetches CVEs modified since a timestamp from NVD.
type NVDCVEFeedClient interface {
	FetchModifiedSince(ctx context.Context, since time.Time) ([]FeedVulnerability, error)
}

// OSVPackageQuery identifies a package for batched OSV lookups.
type OSVPackageQuery struct {
	Name string
}

// OSVCVEFeedClient queries OSV by ecosystem and package names.
type OSVCVEFeedClient interface {
	QueryByEcosystem(ctx context.Context, ecosystem string, packages []OSVPackageQuery) ([]FeedVulnerability, error)
}

// WatchRepository persists CVE watch state and findings.
type WatchRepository interface {
	ListWatchCatalog(ctx context.Context) ([]WatchCatalogEntry, error)
	ListVulnerabilityRecords(ctx context.Context) ([]VulnerabilityRecord, error)
	GetLastSuccessTimestamp(ctx context.Context) (time.Time, error)
	SetLastSuccessTimestamp(ctx context.Context, ts time.Time) error
	UpsertVulnerability(ctx context.Context, record VulnerabilityRecord) (string, error)
	HasFinding(ctx context.Context, componentVersionID, cveID string) (bool, error)
	CreateWatchFinding(ctx context.Context, input CreateWatchFindingInput) (CreateWatchFindingResult, error)
}

// WatchMetricsRecorder records CVE watch observability metrics.
type WatchMetricsRecorder interface {
	RecordCycle(status string, duration time.Duration)
	RecordNewFindings(ecosystem string, count int)
}
