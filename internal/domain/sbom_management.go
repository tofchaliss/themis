package domain

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrSBOMNotFound indicates the SBOM does not exist or was soft-deleted.
	ErrSBOMNotFound = errors.New("sbom not found")
	// ErrCannotDeleteLatestSBOM indicates the target is the latest scan (by
	// scanned_at DESC) and force=true was not supplied.
	ErrCannotDeleteLatestSBOM = errors.New("cannot delete latest sbom without force")
)

const AuditActionSBOMDeleted = "SBOM_DELETED"

// SBOMListEntry is a row in SBOM list endpoints.
type SBOMListEntry struct {
	ID                 string
	ProductID          string
	ProductName        string
	ProductVersion     string
	ImageName          string
	ImageDigest        string
	Format             string
	ComponentCount     int
	VulnerabilityCount int
	UploadedAt         time.Time
	IsLatest           bool
}

// SBOMDeleteSummary describes archived data after soft-delete.
type SBOMDeleteSummary struct {
	SBOMID         string
	ComponentCount int
	FindingCount   int
}

// SBOMManagementRepository lists and soft-deletes SBOM documents.
type SBOMManagementRepository interface {
	ListSBOMs(ctx context.Context, page PageRequest) ([]SBOMListEntry, int, PageResult, error)
	ListProductSBOMs(ctx context.Context, productID string, page PageRequest) ([]SBOMListEntry, int, PageResult, error)
	SoftDeleteSBOM(ctx context.Context, id string, force bool) (SBOMDeleteSummary, error)
}
