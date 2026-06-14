package domain

import (
	"context"
	"time"
)

// SystemStatus is the live system-wide overview returned by GET /api/v1/status.
type SystemStatus struct {
	AsOf            time.Time
	Components      SystemComponentStats
	Vulnerabilities SystemVulnerabilityStats
	TopComponents   []TopComponentEntry
}

// SystemComponentStats counts registered components on active SBOMs.
type SystemComponentStats struct {
	TotalRegistered     int
	WithVulnerabilities int
	Clean               int
}

// SystemVulnerabilityStats aggregates finding counts on active SBOMs.
type SystemVulnerabilityStats struct {
	TotalFindings int
	UniqueCVEs    int
	BySeverity    map[string]int
	ByState       map[string]int
}

// TopComponentEntry ranks a component by active vulnerability count.
type TopComponentEntry struct {
	Name               string
	Version            string
	PURL               string
	ProductName        string
	VulnerabilityCount int
	HighestSeverity    string
	HighestCVSSScore   float64
	HighestCVEID       string
}

// SystemStatusRepository loads live system status from the database.
type SystemStatusRepository interface {
	GetSystemStatus(ctx context.Context, topN int) (SystemStatus, error)
}
