package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresEnrichmentRepository applies VEX overlays to risk_context rows.
type PostgresEnrichmentRepository struct {
	pool pgQueryPool
}

// NewPostgresEnrichmentRepository creates an enrichment repository.
func NewPostgresEnrichmentRepository(pool pgQueryPool) *PostgresEnrichmentRepository {
	return &PostgresEnrichmentRepository{pool: pool}
}

func (r *PostgresEnrichmentRepository) ListFindingsForSBOM(ctx context.Context, sbomDocumentID string) ([]domain.EnrichmentFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT cv.id, c.purl, v.cve_id, COALESCE(v.severity, 'unknown')
		FROM component_vulnerabilities cv
		JOIN component_versions cvn ON cvn.id = cv.component_version_id
		JOIN components c ON c.id = cvn.component_id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.sbom_document_id = $1
	`, sbomDocumentID)
	if err != nil {
		return nil, fmt.Errorf("list enrichment findings: %w", err)
	}
	defer rows.Close()

	var findings []domain.EnrichmentFinding
	for rows.Next() {
		var finding domain.EnrichmentFinding
		if err := rows.Scan(&finding.ComponentVulnerabilityID, &finding.ComponentPURL, &finding.CVEID, &finding.RawSeverity); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

func (r *PostgresEnrichmentRepository) ListAssertionsForSBOM(ctx context.Context, sbomDocumentID string) ([]domain.VEXAssertionMatch, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT va.id, va.vex_document_id,
		       COALESCE(c.purl, va.component_purl), v.cve_id, va.status,
		       COALESCE(va.justification, ''), COALESCE(vd.ingested_at, va.created_at)
		FROM vex_assertions va
		JOIN vex_documents vd ON vd.id = va.vex_document_id
		JOIN vulnerabilities v ON v.id = va.vulnerability_id
		LEFT JOIN component_versions cvn ON cvn.id = va.component_version_id
		LEFT JOIN components c ON c.id = cvn.component_id
		WHERE vd.sbom_document_id = $1
		   OR (
		       vd.source = 'themis_generated'
		       AND COALESCE(va.component_purl, c.purl) IN (
		           SELECT c2.purl
		           FROM component_versions cvn2
		           JOIN components c2 ON c2.id = cvn2.component_id
		           WHERE cvn2.sbom_document_id = $1
		       )
		   )
	`, sbomDocumentID)
	if err != nil {
		return nil, fmt.Errorf("list vex assertions: %w", err)
	}
	defer rows.Close()

	var matches []domain.VEXAssertionMatch
	for rows.Next() {
		var match domain.VEXAssertionMatch
		if err := rows.Scan(&match.ID, &match.VEXDocumentID, &match.ComponentPURL, &match.CVEID,
			&match.Status, &match.Justification, &match.DocumentTime); err != nil {
			return nil, err
		}
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func (r *PostgresEnrichmentRepository) GetRiskContext(ctx context.Context, componentVulnerabilityID string) (domain.RiskContextSnapshot, error) {
	var snapshot domain.RiskContextSnapshot
	var score float64
	err := r.pool.QueryRow(ctx, `
		SELECT id, component_vulnerability_id, effective_state,
		       COALESCE(raw_severity, ''), COALESCE(vex_status, ''),
		       COALESCE(vex_assertion_id::text, ''), COALESCE(suppression_reason, ''),
		       COALESCE(risk_score, 0)
		FROM risk_context
		WHERE component_vulnerability_id = $1
	`, componentVulnerabilityID).Scan(
		&snapshot.ID,
		&snapshot.ComponentVulnerabilityID,
		&snapshot.EffectiveState,
		&snapshot.RawSeverity,
		&snapshot.VEXStatus,
		&snapshot.VEXAssertionID,
		&snapshot.SuppressionReason,
		&score,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.RiskContextSnapshot{}, nil
		}
		return domain.RiskContextSnapshot{}, fmt.Errorf("get risk context: %w", err)
	}
	snapshot.RiskScore = int(score)
	return snapshot, nil
}

func (r *PostgresEnrichmentRepository) UpsertRiskContext(ctx context.Context, finding domain.EnrichmentFinding, snapshot domain.RiskContextSnapshot) error {
	priority := mapSeverityToPriority(finding.RawSeverity)
	var vexAssertionID any
	if snapshot.VEXAssertionID != "" {
		vexAssertionID = snapshot.VEXAssertionID
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO risk_context (
			id, component_vulnerability_id, effective_state, priority, risk_score,
			raw_severity, vex_status, vex_assertion_id, suppression_reason, triage_notes
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10
		)
		ON CONFLICT (component_vulnerability_id) DO UPDATE SET
			effective_state = EXCLUDED.effective_state,
			priority = EXCLUDED.priority,
			risk_score = EXCLUDED.risk_score,
			raw_severity = EXCLUDED.raw_severity,
			vex_status = EXCLUDED.vex_status,
			vex_assertion_id = EXCLUDED.vex_assertion_id,
			suppression_reason = EXCLUDED.suppression_reason,
			updated_at = NOW()
	`, uuid.NewString(), finding.ComponentVulnerabilityID, snapshot.EffectiveState, priority, snapshot.RiskScore,
		snapshot.RawSeverity, nullIfEmpty(snapshot.VEXStatus), vexAssertionID, nullIfEmpty(snapshot.SuppressionReason),
		nullIfEmpty(snapshot.SuppressionReason))
	if err != nil {
		return fmt.Errorf("upsert risk context: %w", err)
	}
	return nil
}

func (r *PostgresEnrichmentRepository) SBOMDocumentForVEX(ctx context.Context, vexDocumentID string) (string, error) {
	var sbomDocumentID string
	err := r.pool.QueryRow(ctx, `
		SELECT sbom_document_id::text FROM vex_documents WHERE id = $1
	`, vexDocumentID).Scan(&sbomDocumentID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("vex document %q not found", vexDocumentID)
		}
		return "", fmt.Errorf("lookup vex document: %w", err)
	}
	return sbomDocumentID, nil
}

// PostgresVEXAssertionWriter persists parsed VEX assertions.
type PostgresVEXAssertionWriter struct {
	pool pgPool
}

// NewPostgresVEXAssertionWriter creates a VEX assertion writer.
func NewPostgresVEXAssertionWriter(pool pgPool) *PostgresVEXAssertionWriter {
	return &PostgresVEXAssertionWriter{pool: pool}
}

func (w *PostgresVEXAssertionWriter) SyncAssertions(ctx context.Context, vexDocumentID, sbomDocumentID string, assertions []domain.ParsedVEXAssertion) error {
	if _, err := w.pool.Exec(ctx, `DELETE FROM vex_assertions WHERE vex_document_id = $1`, vexDocumentID); err != nil {
		return fmt.Errorf("clear vex assertions: %w", err)
	}
	for _, assertion := range assertions {
		vulnID, err := w.lookupVulnerabilityID(ctx, assertion.CVEID)
		if err != nil {
			return err
		}
		componentVersionID, err := w.lookupComponentVersionID(ctx, sbomDocumentID, assertion.ComponentPURL)
		if err != nil {
			return err
		}
		if _, err := w.pool.Exec(ctx, `
			INSERT INTO vex_assertions (
				id, vex_document_id, vulnerability_id, component_version_id, status, justification
			) VALUES ($1, $2, $3, $4, $5, $6)
		`, uuid.NewString(), vexDocumentID, vulnID, componentVersionID, assertion.Status, assertion.Justification); err != nil {
			return fmt.Errorf("insert vex assertion: %w", err)
		}
	}
	return nil
}

func (w *PostgresVEXAssertionWriter) lookupVulnerabilityID(ctx context.Context, cveID string) (string, error) {
	var id string
	err := w.pool.QueryRow(ctx, `SELECT id::text FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("vulnerability %q not found for vex assertion", cveID)
		}
		return "", err
	}
	return id, nil
}

func (w *PostgresVEXAssertionWriter) lookupComponentVersionID(ctx context.Context, sbomDocumentID, purl string) (string, error) {
	var id string
	err := w.pool.QueryRow(ctx, `
		SELECT cvn.id::text
		FROM component_versions cvn
		JOIN components c ON c.id = cvn.component_id
		WHERE cvn.sbom_document_id = $1 AND c.purl = $2
		LIMIT 1
	`, sbomDocumentID, purl).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("component %q not found in sbom %q", purl, sbomDocumentID)
		}
		return "", err
	}
	return id, nil
}

func parseVEXAssertions(format string, raw []byte) ([]domain.ParsedVEXAssertion, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "openvex", "cyclonedx", "csaf":
		return parseOpenVEXAssertions(raw)
	default:
		return parseOpenVEXAssertions(raw)
	}
}

type openVEXDocument struct {
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability struct {
		Name string `json:"name"`
	} `json:"vulnerability"`
	Products []struct {
		ID string `json:"@id"`
	} `json:"products"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

func parseOpenVEXAssertions(raw []byte) ([]domain.ParsedVEXAssertion, error) {
	var doc openVEXDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse vex document: %w", err)
	}
	out := make([]domain.ParsedVEXAssertion, 0, len(doc.Statements))
	for _, statement := range doc.Statements {
		for _, product := range statement.Products {
			out = append(out, domain.ParsedVEXAssertion{
				CVEID:         statement.Vulnerability.Name,
				ComponentPURL: product.ID,
				Status:        statement.Status,
				Justification: statement.Justification,
			})
		}
	}
	return out, nil
}

func nullIfEmpty(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}
