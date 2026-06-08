package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresSBOMStore persists SBOM and VEX documents.
type PostgresSBOMStore struct {
	pool      pgPool
	assertions domain.VEXAssertionWriter
}

// NewPostgresSBOMStore creates a PostgreSQL SBOM store.
func NewPostgresSBOMStore(pool pgPool) *PostgresSBOMStore {
	return &PostgresSBOMStore{
		pool:       pool,
		assertions: NewPostgresVEXAssertionWriter(pool),
	}
}

func (s *PostgresSBOMStore) SaveSBOM(ctx context.Context, input domain.SaveSBOMInput) (string, error) {
	id := uuid.NewString()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sbom_documents (
			id, image_id, project_id, image_digest, checksum_sha256, format, spec_version,
			ci_job_id, ci_pipeline_url, supplier_identity, signature_verified, trust_status, raw_document
		) VALUES (
			$1, $2, NULLIF($3, '')::uuid, $4, $5, $6, $7,
			$8, $9, $10, $11, $12, $13::jsonb
		)
	`, id, input.ImageID, input.ProjectID, input.ImageDigest, input.ChecksumSHA256, input.Format,
		input.SpecVersion, input.CIJobID, input.CIPipelineURL, input.SupplierIdentity,
		input.TrustResult.SignatureVerified, string(input.TrustResult.Status), input.RawDocument)
	if err != nil {
		return "", fmt.Errorf("insert sbom document: %w", err)
	}
	return id, nil
}

func (s *PostgresSBOMStore) SaveVEX(ctx context.Context, input domain.SaveVEXInput) (string, error) {
	id := uuid.NewString()
	_, err := s.pool.Exec(ctx, `
		INSERT INTO vex_documents (
			id, sbom_document_id, sbom_checksum, checksum_sha256, format, spec_version,
			supplier_identity, signature_verified, trust_status, raw_document
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb
		)
	`, id, input.SBOMDocumentID, input.SBOMChecksum, input.ChecksumSHA256, input.Format,
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
		if err := s.assertions.SyncAssertions(ctx, id, input.SBOMDocumentID, assertions); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (s *PostgresSBOMStore) FindDocumentIDByChecksum(ctx context.Context, checksum string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		SELECT id FROM sbom_documents WHERE checksum_sha256 = $1 ORDER BY ingested_at DESC LIMIT 1
	`, checksum).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("sbom not found for checksum")
		}
		return "", fmt.Errorf("find sbom by checksum: %w", err)
	}
	return id, nil
}
