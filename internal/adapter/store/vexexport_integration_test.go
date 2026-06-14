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
	imageID := uuid.NewString()
	versionID := uuid.NewString()
	sbomID := uuid.NewString()
	componentID := uuid.NewString()
	findingID := uuid.NewString()
	vulnID := uuid.NewString()
	cveID := "CVE-2024-VEX-24"
	version := "1.0.0"

	seedBaseData(t, ctx, pool, productID, artifactID, imageID, "sha256:ac24-vex")
	if _, err := pool.Exec(ctx, `
		INSERT INTO product_versions (id, product_id, version, release_status)
		VALUES ($1, $2, $3, 'released')
	`, versionID, productID, version); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE artifacts SET product_version_id = $1 WHERE id = $2`, versionID, artifactID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, image_digest, checksum_sha256, format, spec_version, raw_document, trust_status, is_latest)
		VALUES ($1, $2, 'sha256:ac24-vex', 'checksum-ac24', 'cyclonedx', '1.6', '{}', 'unsigned', true)
	`, sbomID, imageID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (id, purl, name, ecosystem) VALUES ($1, 'pkg:rpm/redhat/httpd@2.4.37-51.el8', 'httpd', 'rpm')
	`, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_document_id)
		VALUES ($1, $2, '2.4.37-51.el8', $3)
	`, uuid.NewString(), componentID, sbomID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, $2, 'high')
	`, vulnID, cveID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, sbom_document_id)
		VALUES ($1, (SELECT id FROM component_versions WHERE sbom_document_id = $2 LIMIT 1), $3, $2)
	`, findingID, sbomID, vulnID); err != nil {
		t.Fatal(err)
	}

	vendorStore := vexfeed.NewPostgresAssertionStore(pool)
	if _, err := vendorStore.UpsertAssertions(ctx, "rhel", []domain.VendorVEXAssertion{{
		AdvisoryID: "RHSA-AC24", CVEID: cveID,
		ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
		Status:        domain.VEXStatusAffected,
	}}); err != nil {
		t.Fatal(err)
	}

	vexDocID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO vex_documents (id, sbom_document_id, sbom_checksum, checksum_sha256, format, source, raw_document)
		VALUES ($1, $2, 'triage-ac24', 'checksum-triage', 'openvex', 'themis_generated', '{}')
	`, vexDocID, sbomID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO vex_assertions (id, vex_document_id, vulnerability_id, status, justification, component_purl)
		VALUES ($1, $2, $3, 'not_affected', 'human triage backport', 'pkg:rpm/redhat/httpd@2.4.37-51.el8')
	`, uuid.NewString(), vexDocID, vulnID); err != nil {
		t.Fatal(err)
	}

	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	matcher := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}}
	handler := &enrichment.Handler{
		Repo:        enrichmentRepo,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vendorStore},
		VendorMatch: matcher,
	}
	if err := handler.ApplyVEX(ctx, sbomID); err != nil {
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
			XEPSS    *float64 `json:"x-themis-epss-score"`
			XKEV     *bool    `json:"x-themis-kev-listed"`
			XBlast   *int     `json:"x-themis-blast-radius"`
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
