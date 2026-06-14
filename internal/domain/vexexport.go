package domain

import (
	"context"
	"errors"
)

// ErrProductNotFound indicates the product id does not exist.
var ErrProductNotFound = errors.New("product not found")

// ErrProductVersionNotFound indicates the product version does not exist.
var ErrProductVersionNotFound = errors.New("product version not found")

// VEXExportFormat selects the export serialiser.
type VEXExportFormat string

const (
	VEXExportFormatCycloneDX VEXExportFormat = "cyclonedx"
	VEXExportFormatOpenVEX   VEXExportFormat = "openvex"
)

// VEXExportEntry is one exported finding with winning VEX state.
type VEXExportEntry struct {
	BOMRef        string
	CVEID         string
	VEXStatus     string
	Justification string
	RiskScore     int
	EPSSScore     *float64
	KEVListed     bool
	BlastRadius   int
	Source        string
}

// VEXCoverageSummary counts upstream VEX coverage states for a product version.
type VEXCoverageSummary struct {
	Covered      int
	NotCovered   int
	PURLMismatch int
}

// VEXExportFinding is a correlated finding with persisted risk context.
type VEXExportFinding struct {
	EnrichmentFinding
	RiskContextSnapshot
}

// VEXExportRepository loads product version findings for VEX export.
type VEXExportRepository interface {
	ProductExists(ctx context.Context, productID string) (bool, error)
	GetProductVersion(ctx context.Context, productID, version string) (ProductVersion, error)
	ListFindingsForProductVersion(ctx context.Context, productVersionID string) ([]VEXExportFinding, error)
	ListAssertionsForSBOM(ctx context.Context, sbomDocumentID string) ([]VEXAssertionMatch, error)
}
