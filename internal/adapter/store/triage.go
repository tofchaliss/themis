package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

// PostgresTriageRepository records triage decisions and history.
type PostgresTriageRepository struct {
	pool pgQueryPool
}

// NewPostgresTriageRepository creates a triage repository.
func NewPostgresTriageRepository(pool pgQueryPool) *PostgresTriageRepository {
	return &PostgresTriageRepository{pool: pool}
}

func (r *PostgresTriageRepository) GetFindingScope(ctx context.Context, findingID string) (string, error) {
	var productID string
	err := r.pool.QueryRow(ctx, `
		SELECT i.product_id::text
		FROM component_vulnerabilities cv
		JOIN sbom_documents s ON s.id = cv.sbom_document_id
		JOIN images i ON i.id = s.image_id
		WHERE cv.id = $1
	`, findingID).Scan(&productID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("finding %q not found", findingID)
		}
		return "", fmt.Errorf("get finding scope: %w", err)
	}
	return productID, nil
}

func (r *PostgresTriageRepository) GetFindingContext(ctx context.Context, findingID string) (domain.TriageFindingContext, error) {
	var finding domain.TriageFindingContext
	var effectiveState string
	err := r.pool.QueryRow(ctx, `
		SELECT cv.id, c.purl, v.cve_id, s.id::text, s.checksum_sha256,
		       COALESCE(rc.raw_severity, v.severity, 'unknown'),
		       COALESCE(rc.effective_state, 'detected')
		FROM component_vulnerabilities cv
		JOIN component_versions cvn ON cvn.id = cv.component_version_id
		JOIN components c ON c.id = cvn.component_id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		JOIN sbom_documents s ON s.id = cv.sbom_document_id
		LEFT JOIN risk_context rc ON rc.component_vulnerability_id = cv.id
		WHERE cv.id = $1
	`, findingID).Scan(
		&finding.FindingID,
		&finding.ComponentPURL,
		&finding.CVEID,
		&finding.SBOMDocumentID,
		&finding.SBOMChecksum,
		&finding.RawSeverity,
		&effectiveState,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.TriageFindingContext{}, fmt.Errorf("finding %q not found", findingID)
		}
		return domain.TriageFindingContext{}, fmt.Errorf("get finding context: %w", err)
	}
	finding.EffectiveState = effectiveState
	return finding, nil
}

func (r *PostgresTriageRepository) AppendHistory(ctx context.Context, record domain.TriageHistoryRecord) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO triage_history (
			id, component_vulnerability_id, decision, justification, actor,
			accepted_until, assigned_to, recorded_at
		) VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8)
	`, uuid.NewString(), record.FindingID, record.Decision, record.Justification,
		record.Actor, record.AcceptedUntil, record.AssignedTo, record.RecordedAt)
	if err != nil {
		return fmt.Errorf("append triage history: %w", err)
	}
	return nil
}

func (r *PostgresTriageRepository) ListHistory(ctx context.Context, findingID string, page domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	limit := normalizeLimit(page.Limit)
	args := []any{findingID, limit + 1}
	where := "WHERE component_vulnerability_id = $1"
	if page.Cursor != "" {
		where += " AND recorded_at < $3::timestamptz"
		args = append(args, page.Cursor)
	}
	rows, err := r.pool.Query(ctx, `
		SELECT decision, justification, actor, COALESCE(assigned_to, ''), recorded_at
		FROM triage_history
		`+where+`
		ORDER BY recorded_at DESC
		LIMIT $2
	`, args...)
	if err != nil {
		return nil, domain.PageResult{}, fmt.Errorf("list triage history: %w", err)
	}
	defer rows.Close()

	var items []domain.TriageHistoryEntry
	for rows.Next() {
		var item domain.TriageHistoryEntry
		if err := rows.Scan(&item.Decision, &item.Justification, &item.Actor, &item.AssignedTo, &item.RecordedAt); err != nil {
			return nil, domain.PageResult{}, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, domain.PageResult{}, err
	}
	var next domain.PageResult
	if len(items) > limit {
		next.NextCursor = items[limit-1].RecordedAt.UTC().Format(time.RFC3339Nano)
		items = items[:limit]
	}
	return items, next, nil
}

func (r *PostgresTriageRepository) UpdateRiskContext(ctx context.Context, update domain.RiskContextTriageUpdate) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE risk_context
		SET effective_state = $2,
		    triaged_by = $3,
		    triaged_at = $4,
		    assigned_to = NULLIF($5, ''),
		    accepted_until = $6,
		    risk_score = $7,
		    updated_at = NOW()
		WHERE component_vulnerability_id = $1
	`, update.FindingID, update.EffectiveState, update.TriagedBy, update.TriagedAt,
		update.AssignedTo, update.AcceptedUntil, update.RiskScore)
	if err != nil {
		return fmt.Errorf("update risk context from triage: %w", err)
	}
	return nil
}

func (r *PostgresTriageRepository) ListExpiredAcceptedRiskFindings(ctx context.Context, now time.Time) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT th.component_vulnerability_id::text
		FROM triage_history th
		WHERE th.decision = 'accepted_risk'
		  AND th.accepted_until IS NOT NULL
		  AND th.accepted_until < $1
	`, now)
	if err != nil {
		return nil, fmt.Errorf("list expired accepted risk: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r *PostgresTriageRepository) LatestDecision(ctx context.Context, findingID string) (string, error) {
	var decision string
	err := r.pool.QueryRow(ctx, `
		SELECT decision
		FROM triage_history
		WHERE component_vulnerability_id = $1
		ORDER BY recorded_at DESC
		LIMIT 1
	`, findingID).Scan(&decision)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("latest triage decision: %w", err)
	}
	return decision, nil
}

// PostgresTriageVEXGenerator creates themis_generated VEX documents.
type PostgresTriageVEXGenerator struct {
	pool pgQueryPool
}

// NewPostgresTriageVEXGenerator creates a triage VEX generator.
func NewPostgresTriageVEXGenerator(pool pgQueryPool) *PostgresTriageVEXGenerator {
	return &PostgresTriageVEXGenerator{pool: pool}
}

func (g *PostgresTriageVEXGenerator) CreateFromDecision(ctx context.Context, input domain.GeneratedVEXInput) (string, error) {
	raw, checksum, err := buildThemisGeneratedVEX(input)
	if err != nil {
		return "", err
	}

	vexID := uuid.NewString()
	_, err = g.pool.Exec(ctx, `
		INSERT INTO vex_documents (
			id, sbom_document_id, sbom_checksum, checksum_sha256, format, spec_version,
			supplier_identity, signature_verified, trust_status, raw_document,
			source, issuer, ingested_at
		) VALUES (
			$1, $2, $3, $4, 'openvex', '0.2.0',
			$5, FALSE, 'unsigned', $6::jsonb,
			'themis_generated', $5, $7
		)
	`, vexID, input.Finding.SBOMDocumentID, input.Finding.SBOMChecksum, checksum,
		input.Issuer, raw, input.DocumentTime)
	if err != nil {
		return "", fmt.Errorf("insert themis generated vex: %w", err)
	}

	vulnID, err := lookupVulnerabilityID(ctx, g.pool, input.Assertion.CVEID)
	if err != nil {
		return "", err
	}
	componentVersionID, err := lookupComponentVersionID(ctx, g.pool, input.Finding.SBOMDocumentID, input.Assertion.ComponentPURL)
	if err != nil {
		return "", err
	}

	assertionID := uuid.NewString()
	_, err = g.pool.Exec(ctx, `
		INSERT INTO vex_assertions (
			id, vex_document_id, vulnerability_id, component_version_id,
			component_purl, status, justification, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, assertionID, vexID, vulnID, componentVersionID, input.Assertion.ComponentPURL,
		input.Assertion.Status, input.Assertion.Justification, input.DocumentTime)
	if err != nil {
		return "", fmt.Errorf("insert themis generated vex assertion: %w", err)
	}
	return vexID, nil
}

func buildThemisGeneratedVEX(input domain.GeneratedVEXInput) ([]byte, string, error) {
	doc := map[string]any{
		"@context": "https://openvex.dev/ns/v0.2.0",
		"@id":      fmt.Sprintf("themis:triage:%s:%d", input.Finding.FindingID, input.DocumentTime.UnixNano()),
		"author":   input.Issuer,
		"timestamp": input.DocumentTime.UTC().Format(time.RFC3339),
		"statements": []map[string]any{
			{
				"vulnerability": map[string]string{"name": input.Assertion.CVEID},
				"products": []map[string]string{
					{"@id": input.Assertion.ComponentPURL},
				},
				"status":        input.Assertion.Status,
				"justification": input.Assertion.Justification,
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, "", fmt.Errorf("marshal themis vex: %w", err)
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:]), nil
}

func lookupVulnerabilityID(ctx context.Context, pool pgQueryPool, cveID string) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `SELECT id::text FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", fmt.Errorf("vulnerability %q not found for vex assertion", cveID)
		}
		return "", err
	}
	return id, nil
}

func lookupComponentVersionID(ctx context.Context, pool pgQueryPool, sbomDocumentID, purl string) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
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
