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

func (r *PostgresCorrelationRepository) CreateFinding(ctx context.Context, componentVersionID, vulnerabilityID, sbomDocumentID string) (string, error) {
	id := uuid.NewString()
	err := r.pool.QueryRow(ctx, `
		INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, sbom_document_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (component_version_id, vulnerability_id, sbom_document_id)
		DO UPDATE SET detected_at = component_vulnerabilities.detected_at
		RETURNING id
	`, id, componentVersionID, vulnerabilityID, sbomDocumentID).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("insert component vulnerability: %w", err)
	}
	return id, nil
}

func (r *PostgresCorrelationRepository) ListFindings(ctx context.Context, sbomDocumentID string) ([]domain.ComponentFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT cv.id, COALESCE(v.severity, 'unknown')
		FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.sbom_document_id = $1
	`, sbomDocumentID)
	if err != nil {
		return nil, fmt.Errorf("list component vulnerabilities: %w", err)
	}
	defer rows.Close()

	var findings []domain.ComponentFinding
	for rows.Next() {
		var finding domain.ComponentFinding
		if err := rows.Scan(&finding.ID, &finding.Severity); err != nil {
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

func (r *PostgresRiskContextRepository) CreateForFinding(ctx context.Context, componentVulnerabilityID, severity string) (string, error) {
	id := uuid.NewString()
	priority := mapSeverityToPriority(severity)
	score := mapSeverityToScore(severity)
	_, err := r.pool.Exec(ctx, `
		INSERT INTO risk_context (id, component_vulnerability_id, effective_state, priority, risk_score, raw_severity)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (component_vulnerability_id) DO NOTHING
	`, id, componentVulnerabilityID, domain.EffectiveStateDetected, priority, score, severity)
	if err != nil {
		return "", fmt.Errorf("insert risk context: %w", err)
	}
	return id, nil
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
