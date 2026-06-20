package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresSBOMStore persists SBOM compositions, scan reports, and VEX documents.
type PostgresSBOMStore struct {
	pool       pgPool
	assertions domain.VEXAssertionWriter
}

// NewPostgresSBOMStore creates a PostgreSQL SBOM store.
func NewPostgresSBOMStore(pool pgPool) *PostgresSBOMStore {
	return &PostgresSBOMStore{
		pool:       pool,
		assertions: NewPostgresVEXAssertionWriter(pool),
	}
}

// SaveSBOM upserts one composition (`sboms`) row keyed (artifact_id, sbom_checksum)
// and appends one `scan_reports` row for the correlation run. An idempotent
// re-submission matching (sbom_id, scan_checksum) returns the existing scan with
// Duplicate=true and does not append a phantom scan (D12).
func (s *PostgresSBOMStore) SaveSBOM(ctx context.Context, input domain.SaveSBOMInput) (domain.SaveSBOMResult, error) {
	scanChecksum := input.ScanChecksum
	if scanChecksum == "" {
		scanChecksum = input.SBOMChecksum
	}

	sbomID := uuid.NewString()
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sboms (
			id, artifact_id, sbom_checksum, format, spec_version,
			supplier_identity, signature_verified, trust_status, raw_document
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb
		)
		ON CONFLICT (artifact_id, sbom_checksum)
		DO UPDATE SET ingested_at = sboms.ingested_at
		RETURNING id
	`, sbomID, input.ArtifactID, input.SBOMChecksum, input.Format, input.SpecVersion,
		input.SupplierIdentity, input.TrustResult.SignatureVerified,
		string(input.TrustResult.Status), input.RawDocument).Scan(&sbomID)
	if err != nil {
		return domain.SaveSBOMResult{}, fmt.Errorf("upsert sbom: %w", err)
	}

	scanID := uuid.NewString()
	err = s.pool.QueryRow(ctx, `
		INSERT INTO scan_reports (
			id, sbom_id, artifact_id, image_digest, scan_checksum,
			scanner, scanner_name, ci_job_id, ci_pipeline_url, trust_status
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
		ON CONFLICT (sbom_id, scan_checksum) DO NOTHING
		RETURNING id
	`, scanID, sbomID, input.ArtifactID, input.ImageDigest, scanChecksum,
		input.Scanner, input.Scanner, input.CIJobID, input.CIPipelineURL,
		string(input.TrustResult.Status)).Scan(&scanID)
	if errors.Is(err, pgx.ErrNoRows) {
		var existing string
		if selErr := s.pool.QueryRow(ctx, `
			SELECT id FROM scan_reports WHERE sbom_id = $1 AND scan_checksum = $2
		`, sbomID, scanChecksum).Scan(&existing); selErr != nil {
			return domain.SaveSBOMResult{}, fmt.Errorf("find existing scan report: %w", selErr)
		}
		return domain.SaveSBOMResult{SBOMID: sbomID, ScanReportID: existing, Duplicate: true}, nil
	}
	if err != nil {
		return domain.SaveSBOMResult{}, fmt.Errorf("insert scan report: %w", err)
	}
	return domain.SaveSBOMResult{SBOMID: sbomID, ScanReportID: scanID}, nil
}

// SaveVEX persists a VEX document against its artifact and syncs parsed assertions.
func (s *PostgresSBOMStore) SaveVEX(ctx context.Context, input domain.SaveVEXInput) (string, error) {
	id := uuid.NewString()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vex_documents (
			id, artifact_id, sbom_checksum, checksum_sha256, format, spec_version,
			supplier_identity, signature_verified, trust_status, raw_document
		) VALUES (
			$1, NULLIF($2, '')::uuid, $3, $4, $5, $6, $7, $8, $9, $10::jsonb
		)
	`, id, input.ArtifactID, input.SBOMChecksum, input.ChecksumSHA256, input.Format,
		input.SpecVersion, input.SupplierIdentity, input.TrustResult.SignatureVerified,
		string(input.TrustResult.Status), input.RawDocument)
	if err != nil {
		return "", fmt.Errorf("insert vex document: %w", err)
	}
	assertions, err := parseVEXAssertions(input.Format, input.RawDocument)
	if err != nil {
		return "", err
	}
	if s.assertions != nil {
		if err := s.assertions.SyncAssertions(ctx, id, input.ArtifactID, assertions); err != nil {
			return "", err
		}
	}
	return id, nil
}

// FindArtifactBySBOMChecksum resolves the artifact owning an uploaded SBOM by checksum.
func (s *PostgresSBOMStore) FindArtifactBySBOMChecksum(ctx context.Context, checksum string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		SELECT artifact_id FROM sboms WHERE sbom_checksum = $1 ORDER BY ingested_at DESC LIMIT 1
	`, checksum).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("artifact not found for sbom checksum")
		}
		return "", fmt.Errorf("find artifact by sbom checksum: %w", err)
	}
	return id, nil
}
