//go:build integration

package store_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/vexgen"
)

func TestAC24_VEXExportPrecedence(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15471)
	productID := uuid.NewString()
	artifactID := uuid.NewString()
	projectID := uuid.NewString()
	versionID := uuid.NewString()
	cveID := "CVE-2024-VEX-24"
	version := "1.0.0"
	digest := "sha256:ac24-vex"

	// product → default project → version 1.0.0 → artifact
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'vex-export-product')`, productID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, product_id, name, is_default) VALUES ($1, $2, 'default', TRUE)`, projectID, productID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO versions (id, project_id, version) VALUES ($1, $2, $3)`, versionID, projectID, version); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO artifacts (id, version_id, artifact_type, image_digest, repository) VALUES ($1, $2, 'image', $3, 'themis/app')`, artifactID, versionID, digest); err != nil {
		t.Fatal(err)
	}

	_, purl := seedFinding(t, ctx, pool, artifactID, "pkg:rpm/redhat/httpd", "2.4.37-51.el8", cveID, "high", "")

	vendorStore := vexfeed.NewPostgresAssertionStore(pool)
	if _, err := vendorStore.UpsertAssertions(ctx, "rhel", []domain.VendorVEXAssertion{{
		AdvisoryID: "RHSA-AC24", CVEID: cveID,
		ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
		Status:        domain.VEXStatusAffected,
	}}); err != nil {
		t.Fatal(err)
	}

	// human-triage themis_generated VEX (highest precedence) bound to the artifact.
	var vulnDBID string
	if err := pool.QueryRow(ctx, `SELECT id FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(&vulnDBID); err != nil {
		t.Fatal(err)
	}
	vexDocID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO vex_documents (id, artifact_id, sbom_checksum, checksum_sha256, format, source, raw_document)
		VALUES ($1, $2, 'triage-ac24', 'checksum-triage', 'openvex', 'themis_generated', '{}')
	`, vexDocID, artifactID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO vex_assertions (id, vex_document_id, vulnerability_id, status, justification, component_purl)
		VALUES ($1, $2, $3, 'not_affected', 'human triage backport', $4)
	`, uuid.NewString(), vexDocID, vulnDBID, purl); err != nil {
		t.Fatal(err)
	}

	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	matcher := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}}
	handler := &enrichment.Handler{
		Repo:        enrichmentRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorStore},
		VendorMatch: matcher,
	}
	if err := handler.ApplyVEX(ctx, artifactID); err != nil {
		t.Fatal(err)
	}

	exportRepo := store.NewPostgresVEXExportRepository(pool)
	exportSvc := &vexgen.Handler{
		Repo:        exportRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorStore},
		VendorMatch: matcher,
	}
	body, err := exportSvc.ExportVEX(ctx, productID, version, domain.VEXExportFormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			Analysis struct {
				State string `json:"state"`
			} `json:"analysis"`
			XEPSS  *float64 `json:"x-themis-epss-score"`
			XKEV   *bool    `json:"x-themis-kev-listed"`
			XBlast *int     `json:"x-themis-blast-radius"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %d", len(doc.Vulnerabilities))
	}
	if doc.Vulnerabilities[0].Analysis.State != "not_affected" {
		t.Fatalf("expected human not_affected export, got %s body=%s", doc.Vulnerabilities[0].Analysis.State, string(body))
	}

	coverage, err := exportSvc.ExportCoverage(ctx, productID, version)
	if err != nil || coverage.Covered+coverage.NotCovered+coverage.PURLMismatch != 1 {
		t.Fatalf("coverage = %+v err = %v", coverage, err)
	}
}

func TestVEXExportRepositoryNotFound(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15472)
	repo := store.NewPostgresVEXExportRepository(pool)
	if _, err := repo.GetProductVersion(ctx, uuid.NewString(), "9.9.9"); err == nil {
		t.Fatal("expected not found")
	}
}
