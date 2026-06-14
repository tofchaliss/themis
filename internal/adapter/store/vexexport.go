package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/domain"
)

// PostgresVEXExportRepository loads product version data for VEX export.
type PostgresVEXExportRepository struct {
	pool pgQueryPool
}

// NewPostgresVEXExportRepository creates a VEX export repository.
func NewPostgresVEXExportRepository(pool pgQueryPool) *PostgresVEXExportRepository {
	return &PostgresVEXExportRepository{pool: pool}
}

func (r *PostgresVEXExportRepository) ProductExists(ctx context.Context, productID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM products WHERE id = $1)`, productID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("product exists: %w", err)
	}
	return exists, nil
}

func (r *PostgresVEXExportRepository) GetProductVersion(ctx context.Context, productID, version string) (domain.ProductVersion, error) {
	var pv domain.ProductVersion
	err := r.pool.QueryRow(ctx, `
		SELECT id, product_id, version, release_status, released_at, created_at
		FROM product_versions
		WHERE product_id = $1 AND version = $2
	`, productID, version).Scan(&pv.ID, &pv.ProductID, &pv.Version, &pv.ReleaseStatus, &pv.ReleasedAt, &pv.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ProductVersion{}, domain.ErrProductVersionNotFound
		}
		return domain.ProductVersion{}, fmt.Errorf("get product version: %w", err)
	}
	return pv, nil
}

func (r *PostgresVEXExportRepository) ListFindingsForProductVersion(ctx context.Context, productVersionID string) ([]domain.VEXExportFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT cv.id, c.purl, v.cve_id, COALESCE(v.severity, 'unknown'),
		       COALESCE(v.cvss_score, 0), v.id::text, i.product_id::text,
		       cv.sbom_document_id::text, c.id::text,
		       COALESCE(rc.id::text, ''), COALESCE(rc.effective_state, 'detected'),
		       COALESCE(rc.raw_severity, ''), COALESCE(rc.vex_status, ''),
		       COALESCE(rc.vex_assertion_id::text, ''), COALESCE(rc.suppression_reason, ''),
		       COALESCE(rc.risk_score, 0), rc.epss_score, COALESCE(rc.kev_listed, false),
		       COALESCE(rc.exploit_public, false), rc.deterministic_level,
		       COALESCE(rc.blast_radius_score, 1.0), COALESCE(rc.upstream_vex_coverage, 'not_covered')
		FROM product_versions pv
		JOIN artifacts a ON a.product_version_id = pv.id
		JOIN images i ON i.artifact_id = a.id
		JOIN sbom_documents sd ON sd.image_id = i.id AND sd.deleted_at IS NULL
		JOIN component_vulnerabilities cv ON cv.sbom_document_id = sd.id
		JOIN component_versions cvn ON cvn.id = cv.component_version_id
		JOIN components c ON c.id = cvn.component_id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cv.id
		WHERE pv.id = $1
		ORDER BY v.cve_id, c.purl
	`, productVersionID)
	if err != nil {
		return nil, fmt.Errorf("list vex export findings: %w", err)
	}
	defer rows.Close()

	var out []domain.VEXExportFinding
	for rows.Next() {
		var item domain.VEXExportFinding
		var score float64
		var level *string
		var coverage string
		if err := rows.Scan(
			&item.EnrichmentFinding.ComponentVulnerabilityID,
			&item.ComponentPURL,
			&item.CVEID,
			&item.EnrichmentFinding.RawSeverity,
			&item.CVSSScore,
			&item.VulnerabilityID,
			&item.ProductID,
			&item.SBOMDocumentID,
			&item.ComponentID,
			&item.ID,
			&item.EffectiveState,
			&item.RiskContextSnapshot.RawSeverity,
			&item.VEXStatus,
			&item.VEXAssertionID,
			&item.SuppressionReason,
			&score,
			&item.EPSSScore,
			&item.KEVListed,
			&item.ExploitPublic,
			&level,
			&item.BlastRadiusScore,
			&coverage,
		); err != nil {
			return nil, err
		}
		item.RiskContextSnapshot.ComponentVulnerabilityID = item.EnrichmentFinding.ComponentVulnerabilityID
		item.RiskScore = int(score)
		if level != nil && *level != "" {
			item.DeterministicLevel = domain.DeterministicLevel(*level)
		}
		item.UpstreamVEXCoverage = domain.UpstreamVEXCoverage(coverage)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *PostgresVEXExportRepository) ListAssertionsForSBOM(ctx context.Context, sbomDocumentID string) ([]domain.VEXAssertionMatch, error) {
	repo := &PostgresEnrichmentRepository{pool: r.pool}
	return repo.ListAssertionsForSBOM(ctx, sbomDocumentID)
}
