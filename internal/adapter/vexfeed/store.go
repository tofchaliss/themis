package vexfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/domain"
)

type pgPool interface {
	Begin(ctx context.Context) (pgx.Tx, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PostgresAssertionStore persists upstream vendor VEX in vex_documents/vex_assertions.
type PostgresAssertionStore struct {
	pool pgPool
}

// NewPostgresAssertionStore creates a vendor VEX store.
func NewPostgresAssertionStore(pool pgPool) *PostgresAssertionStore {
	return &PostgresAssertionStore{pool: pool}
}

func (s *PostgresAssertionStore) UpsertAssertions(ctx context.Context, feed string, assertions []domain.VendorVEXAssertion) (int, error) {
	if len(assertions) == 0 {
		return 0, nil
	}
	byAdvisory := map[string][]domain.VendorVEXAssertion{}
	for _, a := range assertions {
		key := a.AdvisoryID
		if key == "" {
			key = feed + ":" + a.CVEID + ":" + a.PackageName
		}
		byAdvisory[key] = append(byAdvisory[key], a)
	}

	upserted := 0
	for advisoryID, group := range byAdvisory {
		raw, _ := json.Marshal(group)
		sum := sha256.Sum256(raw)
		checksum := hex.EncodeToString(sum[:])

		tx, err := s.pool.Begin(ctx)
		if err != nil {
			return upserted, err
		}

		var docID string
		err = tx.QueryRow(ctx, `
			INSERT INTO vex_documents (
				id, artifact_id, sbom_checksum, checksum_sha256, format, source, raw_document
			) VALUES ($1, NULL, $2, $3, 'csaf', $4, $5)
			ON CONFLICT (sbom_checksum, checksum_sha256) DO UPDATE SET
				raw_document = EXCLUDED.raw_document,
				ingested_at = NOW()
			RETURNING id::text
		`, uuid.NewString(), advisoryID, checksum, domain.VEXSourceUpstreamVendor, raw).Scan(&docID)
		if err != nil {
			_ = tx.Rollback(ctx)
			return upserted, fmt.Errorf("upsert vex document: %w", err)
		}

		if _, err := tx.Exec(ctx, `DELETE FROM vex_assertions WHERE vex_document_id = $1`, docID); err != nil {
			_ = tx.Rollback(ctx)
			return upserted, err
		}

		for _, a := range group {
			vulnID, err := s.ensureVulnerability(ctx, tx, a.CVEID)
			if err != nil {
				_ = tx.Rollback(ctx)
				return upserted, err
			}
			purl := a.ComponentPURL
			if purl == "" && a.PackageName != "" {
				purl = fmt.Sprintf("pkg:apk/alpine/%s", a.PackageName)
			}
			impact := osvImpactStatement(a)
			if _, err := tx.Exec(ctx, `
				INSERT INTO vex_assertions (
					id, vex_document_id, vulnerability_id, status, justification, component_purl, impact_statement
				) VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, uuid.NewString(), docID, vulnID, a.Status, nullStr(a.Justification), nullStr(purl), nullStr(impact)); err != nil {
				_ = tx.Rollback(ctx)
				return upserted, fmt.Errorf("insert vex assertion: %w", err)
			}
			upserted++
		}
		if err := tx.Commit(ctx); err != nil {
			return upserted, err
		}
	}
	return upserted, nil
}

func osvImpactStatement(a domain.VendorVEXAssertion) string {
	if a.Introduced == "" && a.Fixed == "" && a.PackageName == "" && a.Ecosystem == "" {
		return ""
	}
	meta, _ := json.Marshal(map[string]string{
		"introduced": a.Introduced,
		"fixed":      a.Fixed,
		"package":    a.PackageName,
		"ecosystem":  a.Ecosystem,
	})
	return string(meta)
}

func (s *PostgresAssertionStore) ListAssertionsForCVE(ctx context.Context, cveID string) ([]domain.VendorVEXAssertion, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT vd.sbom_checksum, COALESCE(va.component_purl, ''), v.cve_id, va.status,
		       COALESCE(va.justification, ''), COALESCE(va.impact_statement, '')
		FROM vex_assertions va
		JOIN vex_documents vd ON vd.id = va.vex_document_id
		JOIN vulnerabilities v ON v.id = va.vulnerability_id
		WHERE vd.source = $1 AND v.cve_id = $2
	`, domain.VEXSourceUpstreamVendor, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanVendorAssertions(rows)
}

func (s *PostgresAssertionStore) ListAssertionsForSBOMCVEs(ctx context.Context, sbomDocumentID string, cveIDs []string) (map[string][]domain.VendorVEXAssertion, error) {
	out := make(map[string][]domain.VendorVEXAssertion)
	for _, cveID := range cveIDs {
		assertions, err := s.ListAssertionsForCVE(ctx, cveID)
		if err != nil {
			return nil, err
		}
		if len(assertions) > 0 {
			out[cveID] = assertions
		}
	}
	_ = sbomDocumentID
	return out, nil
}

func (s *PostgresAssertionStore) FindSBOMDocumentIDsForCVE(ctx context.Context, cveID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT lf.artifact_id::text
		FROM v_latest_findings lf
		JOIN vulnerabilities v ON v.id = lf.vulnerability_id
		WHERE v.cve_id = $1
	`, cveID)
	if err != nil {
		return nil, err
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

func scanVendorAssertions(rows pgx.Rows) ([]domain.VendorVEXAssertion, error) {
	var out []domain.VendorVEXAssertion
	for rows.Next() {
		var a domain.VendorVEXAssertion
		var impact string
		if err := rows.Scan(&a.AdvisoryID, &a.ComponentPURL, &a.CVEID, &a.Status, &a.Justification, &impact); err != nil {
			return nil, err
		}
		if impact != "" {
			var meta map[string]string
			if err := json.Unmarshal([]byte(impact), &meta); err == nil {
				a.Introduced = meta["introduced"]
				a.Fixed = meta["fixed"]
				a.PackageName = meta["package"]
				a.Ecosystem = meta["ecosystem"]
			}
		}
		if a.Ecosystem == "Alpine" || strings.HasPrefix(a.ComponentPURL, "pkg:apk/") {
			if a.Ecosystem == "" {
				a.Ecosystem = "Alpine"
			}
			if a.PackageName == "" {
				a.PackageName = parsePURL(a.ComponentPURL).Name
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *PostgresAssertionStore) ensureVulnerability(ctx context.Context, tx pgx.Tx, cveID string) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT id::text FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != pgx.ErrNoRows {
		return "", err
	}
	id = uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'unknown')
	`, id, cveID)
	return id, err
}

func nullStr(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}
