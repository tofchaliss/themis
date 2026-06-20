package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresCorrelationRepository persists component vulnerability findings.
type PostgresCorrelationRepository struct {
	pool pgQueryPool
}

// NewPostgresCorrelationRepository creates a PostgreSQL correlation repository.
func NewPostgresCorrelationRepository(pool pgQueryPool) *PostgresCorrelationRepository {
	return &PostgresCorrelationRepository{pool: pool}
}

func (r *PostgresCorrelationRepository) CreateFinding(ctx context.Context, input domain.CreateFindingInput) (string, error) {
	id := uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO component_vulnerabilities (
			id, component_version_id, vulnerability_id, scan_report_id, component_purl, cve_id
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (component_version_id, vulnerability_id, scan_report_id)
		DO UPDATE SET detected_at = component_vulnerabilities.detected_at
		RETURNING id
	`, id, input.ComponentVersionID, input.VulnerabilityID, input.ScanReportID,
		input.ComponentPURL, input.CVEID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert component vulnerability: %w", err)
	}
	return id, nil
}

func (r *PostgresCorrelationRepository) ListFindings(ctx context.Context, scanReportID string) ([]domain.ComponentFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT cv.id, sr.artifact_id, cv.component_purl, cv.cve_id, COALESCE(v.severity, 'unknown')
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.scan_report_id = $1
	`, scanReportID)
	if err != nil {
		return nil, fmt.Errorf("list component vulnerabilities: %w", err)
	}
	defer rows.Close()

	var findings []domain.ComponentFinding
	for rows.Next() {
		var finding domain.ComponentFinding
		if err := rows.Scan(&finding.ID, &finding.ArtifactID, &finding.ComponentPURL, &finding.CVEID, &finding.Severity); err != nil {
			return nil, fmt.Errorf("scan component vulnerability: %w", err)
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate component vulnerabilities: %w", err)
	}
	return findings, nil
}

// PostgresRiskContextRepository creates risk context rows for findings.
type PostgresRiskContextRepository struct {
	pool pgPool
}

// NewPostgresRiskContextRepository creates a PostgreSQL risk context repository.
func NewPostgresRiskContextRepository(pool pgPool) *PostgresRiskContextRepository {
	return &PostgresRiskContextRepository{pool: pool}
}

// CreateForFinding inserts a risk_context row keyed on the stable identity
// (artifact_id, component_purl, cve_id). A pre-existing row (e.g. prior triage) is
// preserved — DO NOTHING — so judgments survive rescans (D3).
func (r *PostgresRiskContextRepository) CreateForFinding(ctx context.Context, artifactID, componentPURL, cveID, severity string) error {
	priority := mapSeverityToPriority(severity)
	score := mapSeverityToScore(severity)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO risk_context (artifact_id, component_purl, cve_id, effective_state, priority, risk_score, raw_severity)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (artifact_id, component_purl, cve_id) DO NOTHING
	`, artifactID, componentPURL, cveID, domain.EffectiveStateDetected, priority, score, severity)
	if err != nil {
		return fmt.Errorf("insert risk context: %w", err)
	}
	return nil
}

func mapSeverityToPriority(severity string) string {
	switch severity {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func mapSeverityToScore(severity string) float64 {
	switch severity {
	case "critical":
		return 90
	case "high":
		return 70
	case "medium":
		return 50
	case "low":
		return 30
	default:
		return 40
	}
}
