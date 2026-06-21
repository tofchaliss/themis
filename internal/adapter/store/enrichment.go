package store

import (
	"context"
	"encoding/json"
	"errors"
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

// ListFindingsForArtifact returns the artifact's current findings — the
// component_vulnerabilities of its latest non-deleted scan (D10, via v_latest_findings).
func (r *PostgresEnrichmentRepository) ListFindingsForArtifact(ctx context.Context, artifactID string) ([]domain.EnrichmentFinding, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT lf.id, lf.component_purl, lf.cve_id, COALESCE(v.severity, 'unknown'),
		       COALESCE(v.cvss_score, 0), v.id::text, proj.product_id::text,
		       lf.scan_report_id::text, lf.artifact_id::text, c.id::text
		FROM v_latest_findings lf
		JOIN vulnerabilities v ON v.id = lf.vulnerability_id
		JOIN component_versions cvn ON cvn.id = lf.component_version_id
		JOIN components c ON c.id = cvn.component_id
		JOIN artifacts a ON a.id = lf.artifact_id
		JOIN versions ver ON ver.id = a.version_id
		JOIN projects proj ON proj.id = ver.project_id
		WHERE lf.artifact_id = $1
	`, artifactID)
	if err != nil {
		return nil, fmt.Errorf("list enrichment findings: %w", err)
	}
	defer rows.Close()

	var findings []domain.EnrichmentFinding
	for rows.Next() {
		var finding domain.EnrichmentFinding
		if err := rows.Scan(
			&finding.ComponentVulnerabilityID,
			&finding.ComponentPURL,
			&finding.CVEID,
			&finding.RawSeverity,
			&finding.CVSSScore,
			&finding.VulnerabilityID,
			&finding.ProductID,
			&finding.ScanReportID,
			&finding.ArtifactID,
			&finding.ComponentID,
		); err != nil {
			return nil, err
		}
		findings = append(findings, finding)
	}
	return findings, rows.Err()
}

// ListAssertionsForArtifact returns VEX assertions applicable to an artifact: those
// from VEX documents bound to the artifact, plus themis_generated assertions whose
// (version-qualified) purl matches one of the artifact's current findings.
func (r *PostgresEnrichmentRepository) ListAssertionsForArtifact(ctx context.Context, artifactID string) ([]domain.VEXAssertionMatch, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT va.id, va.vex_document_id,
		       COALESCE(
		           CASE WHEN cvn.version IS NULL OR cvn.version = '' OR c.purl LIKE '%@%' THEN c.purl
		                ELSE c.purl || '@' || cvn.version END,
		           va.component_purl), v.cve_id, va.status,
		       COALESCE(va.justification, ''), COALESCE(vd.ingested_at, va.created_at),
		       COALESCE(vd.source, 'manual')
		FROM vex_assertions va
		JOIN vex_documents vd ON vd.id = va.vex_document_id
		JOIN vulnerabilities v ON v.id = va.vulnerability_id
		LEFT JOIN component_versions cvn ON cvn.id = va.component_version_id
		LEFT JOIN components c ON c.id = cvn.component_id
		WHERE vd.artifact_id = $1
		   OR (
		       vd.source = 'themis_generated'
		       AND COALESCE(va.component_purl, c.purl) IN (
		           SELECT lf.component_purl FROM v_latest_findings lf WHERE lf.artifact_id = $1
		       )
		   )
	`, artifactID)
	if err != nil {
		return nil, fmt.Errorf("list vex assertions: %w", err)
	}
	defer rows.Close()

	var matches []domain.VEXAssertionMatch
	for rows.Next() {
		var match domain.VEXAssertionMatch
		if err := rows.Scan(&match.ID, &match.VEXDocumentID, &match.ComponentPURL, &match.CVEID,
			&match.Status, &match.Justification, &match.DocumentTime, &match.Source); err != nil {
			return nil, err
		}
		matches = append(matches, match)
	}
	return matches, rows.Err()
}

func (r *PostgresEnrichmentRepository) GetRiskContext(ctx context.Context, artifactID, componentPURL, cveID string) (domain.RiskContextSnapshot, error) {
	var snapshot domain.RiskContextSnapshot
	var score float64
	var level *string
	var blastScore float64
	err := r.pool.QueryRow(ctx, `
		SELECT effective_state,
		       COALESCE(raw_severity, ''), COALESCE(vex_status, ''),
		       COALESCE(vex_assertion_id::text, ''), COALESCE(suppression_reason, ''),
		       COALESCE(risk_score, 0), epss_score, kev_listed, exploit_public,
		       deterministic_level, COALESCE(blast_radius_score, 1.0)
		FROM risk_context
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, componentPURL, cveID).Scan(
		&snapshot.EffectiveState,
		&snapshot.RawSeverity,
		&snapshot.VEXStatus,
		&snapshot.VEXAssertionID,
		&snapshot.SuppressionReason,
		&score,
		&snapshot.EPSSScore,
		&snapshot.KEVListed,
		&snapshot.ExploitPublic,
		&level,
		&blastScore,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.RiskContextSnapshot{}, nil
		}
		return domain.RiskContextSnapshot{}, fmt.Errorf("get risk context: %w", err)
	}
	snapshot.RiskScore = int(score)
	if level != nil && *level != "" {
		snapshot.DeterministicLevel = domain.DeterministicLevel(*level)
	}
	snapshot.BlastRadiusScore = blastScore
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
			artifact_id, component_purl, cve_id, effective_state, priority, risk_score,
			raw_severity, vex_status, vex_assertion_id, suppression_reason, triage_notes,
			deterministic_level, blast_radius_score, upstream_vex_coverage
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14
		)
		ON CONFLICT (artifact_id, component_purl, cve_id) DO UPDATE SET
			effective_state = EXCLUDED.effective_state,
			priority = EXCLUDED.priority,
			risk_score = EXCLUDED.risk_score,
			raw_severity = EXCLUDED.raw_severity,
			vex_status = EXCLUDED.vex_status,
			vex_assertion_id = EXCLUDED.vex_assertion_id,
			suppression_reason = EXCLUDED.suppression_reason,
			deterministic_level = EXCLUDED.deterministic_level,
			blast_radius_score = EXCLUDED.blast_radius_score,
			upstream_vex_coverage = EXCLUDED.upstream_vex_coverage,
			updated_at = NOW()
	`, finding.ArtifactID, finding.ComponentPURL, finding.CVEID, snapshot.EffectiveState, priority, snapshot.RiskScore,
		snapshot.RawSeverity, nullIfEmpty(snapshot.VEXStatus), vexAssertionID, nullIfEmpty(snapshot.SuppressionReason),
		nullIfEmpty(snapshot.SuppressionReason), nullIfEmpty(string(snapshot.DeterministicLevel)), snapshot.BlastRadiusScore,
		nullIfEmpty(string(snapshot.UpstreamVEXCoverage)))
	if err != nil {
		return fmt.Errorf("upsert risk context: %w", err)
	}
	return nil
}

func (r *PostgresEnrichmentRepository) CountOpenRiskContexts(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM risk_context
		WHERE effective_state IN ('detected', 'in_triage')
	`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count open risk contexts: %w", err)
	}
	return count, nil
}

func (r *PostgresEnrichmentRepository) ListOpenRiskContexts(ctx context.Context, offset, limit int) ([]domain.OpenRiskContextRow, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := r.pool.Query(ctx, `
		SELECT rc.artifact_id::text, rc.component_purl, rc.cve_id,
		       COALESCE(rc.raw_severity, v.severity, 'unknown'), rc.effective_state,
		       COALESCE(v.cvss_score, 0),
		       COALESCE(rc.blast_radius_score, 1.0)
		FROM risk_context rc
		JOIN vulnerabilities v ON v.cve_id = rc.cve_id
		WHERE rc.effective_state IN ('detected', 'in_triage')
		ORDER BY rc.artifact_id, rc.component_purl, rc.cve_id
		OFFSET $1 LIMIT $2
	`, offset, limit)
	if err != nil {
		return nil, fmt.Errorf("list open risk contexts: %w", err)
	}
	defer rows.Close()
	var out []domain.OpenRiskContextRow
	for rows.Next() {
		var row domain.OpenRiskContextRow
		if err := rows.Scan(
			&row.ArtifactID,
			&row.ComponentPURL,
			&row.CVEID,
			&row.RawSeverity,
			&row.EffectiveState,
			&row.CVSSScore,
			&row.BlastRadiusScore,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r *PostgresEnrichmentRepository) UpdateRiskContextSignals(
	ctx context.Context,
	row domain.OpenRiskContextRow,
	epssScore *float64,
	kevListed bool,
	exploitPublic bool,
	deterministicLevel domain.DeterministicLevel,
	riskScore int,
) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE risk_context
		SET epss_score = $4,
		    kev_listed = $5,
		    exploit_public = $6,
		    deterministic_level = $7,
		    risk_score = $8,
		    updated_at = NOW()
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, row.ArtifactID, row.ComponentPURL, row.CVEID, epssScore, kevListed, exploitPublic, nullIfEmpty(string(deterministicLevel)), riskScore)
	if err != nil {
		return fmt.Errorf("update risk context signals: %w", err)
	}
	return nil
}

func (r *PostgresEnrichmentRepository) ArtifactForVEX(ctx context.Context, vexDocumentID string) (string, error) {
	var artifactID string
	err := r.pool.QueryRow(ctx, `
		SELECT COALESCE(artifact_id::text, '') FROM vex_documents WHERE id = $1
	`, vexDocumentID).Scan(&artifactID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("vex document %q not found", vexDocumentID)
		}
		return "", fmt.Errorf("lookup vex document: %w", err)
	}
	return artifactID, nil
}

// PostgresVEXAssertionWriter persists parsed VEX assertions.
type PostgresVEXAssertionWriter struct {
	pool pgPool
}

// NewPostgresVEXAssertionWriter creates a VEX assertion writer.
func NewPostgresVEXAssertionWriter(pool pgPool) *PostgresVEXAssertionWriter {
	return &PostgresVEXAssertionWriter{pool: pool}
}

func (w *PostgresVEXAssertionWriter) SyncAssertions(ctx context.Context, vexDocumentID, artifactID string, assertions []domain.ParsedVEXAssertion) error {
	if _, err := w.pool.Exec(ctx, `DELETE FROM vex_assertions WHERE vex_document_id = $1`, vexDocumentID); err != nil {
		return fmt.Errorf("clear vex assertions: %w", err)
	}
	for _, assertion := range assertions {
		vulnID, err := w.lookupVulnerabilityID(ctx, assertion.CVEID)
		if err != nil {
			return err
		}
		componentVersionID, err := w.lookupComponentVersionID(ctx, artifactID, assertion.ComponentPURL)
		if err != nil {
			return err
		}
		var cvnID any
		if componentVersionID != "" {
			cvnID = componentVersionID
		}
		if _, err := w.pool.Exec(ctx, `
			INSERT INTO vex_assertions (
				id, vex_document_id, vulnerability_id, component_version_id, component_purl, status, justification
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, uuid.NewString(), vexDocumentID, vulnID, cvnID, assertion.ComponentPURL, assertion.Status, assertion.Justification); err != nil {
			return fmt.Errorf("insert vex assertion: %w", err)
		}
	}
	return nil
}

func (w *PostgresVEXAssertionWriter) lookupVulnerabilityID(ctx context.Context, cveID string) (string, error) {
	var id string
	err := w.pool.QueryRow(ctx, `SELECT id::text FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("vulnerability %q not found for vex assertion", cveID)
		}
		return "", err
	}
	return id, nil
}

// lookupComponentVersionID resolves a component version for a purl among the
// artifact's SBOM compositions. Best-effort: returns "" (NULL) when not found so a
// VEX referencing a component absent from the SBOM still records its assertion.
func (w *PostgresVEXAssertionWriter) lookupComponentVersionID(ctx context.Context, artifactID, purl string) (string, error) {
	var id string
	err := w.pool.QueryRow(ctx, `
		SELECT cvn.id::text
		FROM component_versions cvn
		JOIN components c ON c.id = cvn.component_id
		JOIN sboms s ON s.id = cvn.sbom_id
		WHERE s.artifact_id = $1 AND (c.purl = $2 OR c.purl || '@' || cvn.version = $2)
		LIMIT 1
	`, artifactID, purl).Scan(&id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
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
