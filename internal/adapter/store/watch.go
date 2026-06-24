package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

const cveWatchLastSuccessKey = domain.SystemStateCVEWatchLastSuccess

// PostgresWatchRepository persists CVE watch catalog matches and poll state.
type PostgresWatchRepository struct {
	pool        pgQueryPool
	vulnCatalog *PostgresVulnerabilityCatalog
	correlate   *PostgresCorrelationRepository
	riskContext *PostgresRiskContextRepository
}

// NewPostgresWatchRepository creates a PostgreSQL watch repository.
func NewPostgresWatchRepository(pool pgQueryPool) *PostgresWatchRepository {
	return &PostgresWatchRepository{
		pool:        pool,
		vulnCatalog: NewPostgresVulnerabilityCatalog(pool),
		correlate:   NewPostgresCorrelationRepository(pool),
		riskContext: NewPostgresRiskContextRepository(pool),
	}
}

func (r *PostgresWatchRepository) ListVulnerabilityRecords(ctx context.Context) ([]domain.VulnerabilityRecord, error) {
	return r.vulnCatalog.ListForMatching(ctx)
}

func (r *PostgresWatchRepository) ListWatchCatalog(ctx context.Context) ([]domain.WatchCatalogEntry, error) {
	rows, err := r.pool.Query(ctx, `
		WITH latest_scans AS (
			SELECT DISTINCT ON (artifact_id) id, sbom_id, artifact_id
			FROM scan_reports WHERE deleted_at IS NULL
			ORDER BY artifact_id, scanned_at DESC, id DESC
		)
		SELECT cvn.id, c.purl, c.name, c.ecosystem, cvn.version,
		       proj.product_id::text, proj.id::text,
		       ls.artifact_id::text, ls.id::text
		FROM component_versions cvn
		JOIN latest_scans ls ON ls.sbom_id = cvn.sbom_id
		JOIN components c ON c.id = cvn.component_id
		JOIN artifacts a ON a.id = ls.artifact_id
		JOIN versions ver ON ver.id = a.version_id
		JOIN projects proj ON proj.id = ver.project_id
		ORDER BY c.purl ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("list watch catalog: %w", err)
	}
	defer rows.Close()

	var entries []domain.WatchCatalogEntry
	for rows.Next() {
		var entry domain.WatchCatalogEntry
		if err := rows.Scan(
			&entry.ComponentVersionID,
			&entry.PURL,
			&entry.Name,
			&entry.Ecosystem,
			&entry.Version,
			&entry.ProductID,
			&entry.ProjectID,
			&entry.ArtifactID,
			&entry.ScanReportID,
		); err != nil {
			return nil, fmt.Errorf("scan watch catalog entry: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate watch catalog: %w", err)
	}
	return entries, nil
}

func (r *PostgresWatchRepository) GetLastSuccessTimestamp(ctx context.Context) (time.Time, error) {
	var ts time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT value FROM system_state WHERE key = $1
	`, cveWatchLastSuccessKey).Scan(&ts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, nil
		}
		return time.Time{}, fmt.Errorf("get last success timestamp: %w", err)
	}
	return ts.UTC(), nil
}

func (r *PostgresWatchRepository) SetLastSuccessTimestamp(ctx context.Context, ts time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO system_state (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
	`, cveWatchLastSuccessKey, ts.UTC())
	if err != nil {
		return fmt.Errorf("set last success timestamp: %w", err)
	}
	return nil
}

func (r *PostgresWatchRepository) UpsertVulnerability(ctx context.Context, record domain.VulnerabilityRecord) (string, error) {
	return r.vulnCatalog.Upsert(ctx, record)
}

func (r *PostgresWatchRepository) HasFinding(ctx context.Context, componentVersionID, cveID string) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1
			FROM component_vulnerabilities cv
			JOIN vulnerabilities v ON v.id = cv.vulnerability_id
			WHERE cv.component_version_id = $1 AND v.cve_id = $2
		)
	`, componentVersionID, cveID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("has finding: %w", err)
	}
	return exists, nil
}

func (r *PostgresWatchRepository) CreateWatchFinding(ctx context.Context, input domain.CreateWatchFindingInput) (domain.CreateWatchFindingResult, error) {
	exists, err := r.HasFinding(ctx, input.ComponentVersionID, input.CVEID)
	if err != nil {
		return domain.CreateWatchFindingResult{}, err
	}
	if exists {
		return domain.CreateWatchFindingResult{Created: false}, nil
	}

	componentVulnID, err := r.correlate.CreateFinding(ctx, domain.CreateFindingInput{
		ComponentVersionID: input.ComponentVersionID,
		VulnerabilityID:    input.VulnerabilityID,
		ScanReportID:       input.ScanReportID,
		ComponentPURL:      input.ComponentPURL,
		CVEID:              input.CVEID,
		Source:             domain.DefaultFindingSource(input.Source),
		SourceSeverity:     input.Severity,
		SourceCVSSScore:    input.SourceCVSSScore,
		SourceCVSSVector:   input.SourceCVSSVector,
		SourceFixedVersion: input.SourceFixedVersion,
	})
	if err != nil {
		return domain.CreateWatchFindingResult{}, err
	}
	if err := r.riskContext.CreateForFinding(ctx, input.ArtifactID, input.ComponentPURL, input.CVEID, input.Severity); err != nil {
		return domain.CreateWatchFindingResult{}, err
	}

	details, err := json.Marshal(map[string]string{
		"severity":             input.Severity,
		"component_purl":       input.ComponentPURL,
		"component_version_id": input.ComponentVersionID,
		"source":               "cve_watch",
	})
	if err != nil {
		return domain.CreateWatchFindingResult{}, fmt.Errorf("marshal watch finding details: %w", err)
	}

	var productID any
	if input.ProductID != "" {
		productID = input.ProductID
	}
	var projectID any
	if input.ProjectID != "" {
		projectID = input.ProjectID
	}

	_, err = r.pool.Exec(ctx, `
		INSERT INTO cve_watch_findings (id, cve_id, product_id, project_id, status, details)
		VALUES ($1, $2, $3, $4, 'new', $5)
	`, uuid.NewString(), input.CVEID, productID, projectID, details)
	if err != nil {
		return domain.CreateWatchFindingResult{}, fmt.Errorf("insert cve watch finding: %w", err)
	}

	return domain.CreateWatchFindingResult{
		ComponentVulnerabilityID: componentVulnID,
		Created:                  true,
	}, nil
}
