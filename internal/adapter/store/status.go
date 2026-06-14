package store

import (
	"context"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

// PostgresSystemStatusRepository loads live system status from PostgreSQL.
type PostgresSystemStatusRepository struct {
	pool pgQueryPool
}

// NewPostgresSystemStatusRepository creates a system status repository.
func NewPostgresSystemStatusRepository(pool pgQueryPool) *PostgresSystemStatusRepository {
	return &PostgresSystemStatusRepository{pool: pool}
}

func (r *PostgresSystemStatusRepository) GetSystemStatus(ctx context.Context, topN int) (domain.SystemStatus, error) {
	if topN <= 0 {
		topN = 10
	}
	if topN > 50 {
		topN = 50
	}
	asOf := time.Now().UTC()

	var totalRegistered, withVuln int
	err := r.pool.QueryRow(ctx, `
		WITH active_sboms AS (
			SELECT id FROM sbom_documents WHERE deleted_at IS NULL
		),
		registered AS (
			SELECT DISTINCT cv.id
			FROM component_versions cv
			JOIN active_sboms s ON s.id = cv.sbom_document_id
		),
		with_vuln AS (
			SELECT DISTINCT cv.component_version_id
			FROM component_vulnerabilities cv
			JOIN active_sboms s ON s.id = cv.sbom_document_id
			LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cv.id
			WHERE COALESCE(rc.effective_state, 'detected') NOT IN ('not_affected', 'false_positive')
		)
		SELECT (SELECT COUNT(*) FROM registered), (SELECT COUNT(*) FROM with_vuln)
	`).Scan(&totalRegistered, &withVuln)
	if err != nil {
		return domain.SystemStatus{}, fmt.Errorf("component stats: %w", err)
	}
	clean := totalRegistered - withVuln
	if clean < 0 {
		clean = 0
	}

	var totalFindings, uniqueCVEs int
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(DISTINCT v.cve_id)
		FROM component_vulnerabilities cv
		JOIN sbom_documents s ON s.id = cv.sbom_document_id AND s.deleted_at IS NULL
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cv.id
		WHERE COALESCE(rc.effective_state, 'detected') NOT IN ('not_affected', 'false_positive')
	`).Scan(&totalFindings, &uniqueCVEs)
	if err != nil {
		return domain.SystemStatus{}, fmt.Errorf("finding stats: %w", err)
	}

	bySeverity, err := r.severityBreakdown(ctx)
	if err != nil {
		return domain.SystemStatus{}, err
	}
	byState, err := r.stateBreakdown(ctx)
	if err != nil {
		return domain.SystemStatus{}, err
	}
	top, err := r.topComponents(ctx, topN)
	if err != nil {
		return domain.SystemStatus{}, err
	}

	return domain.SystemStatus{
		AsOf: asOf,
		Components: domain.SystemComponentStats{
			TotalRegistered:     totalRegistered,
			WithVulnerabilities: withVuln,
			Clean:               clean,
		},
		Vulnerabilities: domain.SystemVulnerabilityStats{
			TotalFindings: totalFindings,
			UniqueCVEs:    uniqueCVEs,
			BySeverity:    bySeverity,
			ByState:       byState,
		},
		TopComponents: top,
	}, nil
}

func (r *PostgresSystemStatusRepository) severityBreakdown(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT LOWER(COALESCE(v.severity, 'unknown')), COUNT(*)
		FROM component_vulnerabilities cv
		JOIN sbom_documents s ON s.id = cv.sbom_document_id AND s.deleted_at IS NULL
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cv.id
		WHERE COALESCE(rc.effective_state, 'detected') NOT IN ('not_affected', 'false_positive')
		GROUP BY LOWER(COALESCE(v.severity, 'unknown'))
	`)
	if err != nil {
		return nil, fmt.Errorf("severity breakdown: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, err
		}
		out[severity] = count
	}
	return out, rows.Err()
}

func (r *PostgresSystemStatusRepository) stateBreakdown(ctx context.Context) (map[string]int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(rc.effective_state, 'detected'), COUNT(*)
		FROM component_vulnerabilities cv
		JOIN sbom_documents s ON s.id = cv.sbom_document_id AND s.deleted_at IS NULL
		LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cv.id
		GROUP BY COALESCE(rc.effective_state, 'detected')
	`)
	if err != nil {
		return nil, fmt.Errorf("state breakdown: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		out[state] = count
	}
	return out, rows.Err()
}

func (r *PostgresSystemStatusRepository) topComponents(ctx context.Context, topN int) ([]domain.TopComponentEntry, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT c.name, cv.version, c.purl, p.name,
		       COUNT(*) AS vuln_count,
		       MAX(CASE LOWER(COALESCE(v.severity, 'unknown'))
		           WHEN 'critical' THEN 4 WHEN 'high' THEN 3
		           WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS sev_rank,
		       MAX(COALESCE(v.cvss_score, 0)) AS max_cvss,
		       (ARRAY_AGG(v.cve_id ORDER BY COALESCE(v.cvss_score, 0) DESC, v.cve_id))[1] AS top_cve
		FROM component_vulnerabilities cvf
		JOIN sbom_documents s ON s.id = cvf.sbom_document_id AND s.deleted_at IS NULL
		JOIN component_versions cv ON cv.id = cvf.component_version_id
		JOIN components c ON c.id = cv.component_id
		JOIN images i ON i.id = s.image_id
		JOIN products p ON p.id = i.product_id
		JOIN vulnerabilities v ON v.id = cvf.vulnerability_id
		LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cvf.id
		WHERE COALESCE(rc.effective_state, 'detected') NOT IN ('not_affected', 'false_positive')
		GROUP BY c.name, cv.version, c.purl, p.name
		ORDER BY vuln_count DESC, max_cvss DESC, c.purl ASC
		LIMIT $1
	`, topN)
	if err != nil {
		return nil, fmt.Errorf("top components: %w", err)
	}
	defer rows.Close()

	severityFromRank := map[int]string{4: "critical", 3: "high", 2: "medium", 1: "low"}
	var items []domain.TopComponentEntry
	for rows.Next() {
		var item domain.TopComponentEntry
		var sevRank int
		if err := rows.Scan(
			&item.Name, &item.Version, &item.PURL, &item.ProductName,
			&item.VulnerabilityCount, &sevRank, &item.HighestCVSSScore, &item.HighestCVEID,
		); err != nil {
			return nil, err
		}
		item.HighestSeverity = severityFromRank[sevRank]
		if item.HighestSeverity == "" {
			item.HighestSeverity = "unknown"
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
