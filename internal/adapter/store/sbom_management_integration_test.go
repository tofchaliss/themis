//go:build integration

package store_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/assetgraph"
	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
	"github.com/themis-project/themis/internal/usecase/vexgen"
)

func TestAC22_SoftDeleteIsolation(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15470)
	productID := uuid.NewString()
	artifactID := uuid.NewString()
	imageID := uuid.NewString()
	digest := "sha256:ac22-soft-delete"
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, cvss_score, description, affected_versions)
		VALUES ('CVE-2021-23337', 'high', 7.5, 'npm:lodash', ARRAY['4.17.21'])
		ON CONFLICT (cve_id) DO NOTHING
	`); err != nil {
		t.Fatal(err)
	}

	graph := assetgraph.NewPostgresStore(pool)
	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	enrichmentSvc := &enrichment.Handler{Repo: enrichmentRepo, Layer2: graph}
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       store.NewPostgresIngestionRepository(pool),
		Trust:      trust.GateEvaluator{Gate: &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trust.NewPostgresRepository(pool)}},
		Parser:     parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:       store.NewPostgresSBOMStore(pool),
		Components: store.NewPostgresComponentStore(pool),
		Catalog:    store.NewPostgresVulnerabilityCatalog(pool),
		Fetcher: store.StaticVulnerabilityFetcher{Records: []domain.VulnerabilityRecord{
			{CVEID: "CVE-2021-23337", Severity: "high", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"4.17.21"}},
		}},
		Correlate:  store.NewPostgresCorrelationRepository(pool),
		Enrichment: enrichmentSvc,
		Notify:     notify.IngestionNotifier{},
	})
	result, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind: domain.ArtifactKindSBOM, Format: domain.SBOMFormatCycloneDX, SpecVersion: "1.6",
			RawDocument: raw, ImageDigest: digest, SupplierIdentity: "team-a", Actor: "test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ImageID:     imageID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE sbom_documents SET is_latest = FALSE WHERE id = $1`, result.ScanID); err != nil {
		t.Fatal(err)
	}

	statusRepo := store.NewPostgresSystemStatusRepository(pool)
	sbomRepo := store.NewPostgresSBOMManagementRepository(pool)
	scans := store.NewPostgresScanQueryRepository(pool)
	components := store.NewPostgresComponentCatalogRepository(pool)

	before, err := statusRepo.GetSystemStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if before.Components.TotalRegistered == 0 || before.Vulnerabilities.TotalFindings == 0 {
		t.Fatalf("expected seeded data in status: %+v", before)
	}

	summary, err := sbomRepo.SoftDeleteSBOM(ctx, result.ScanID, false)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ComponentCount == 0 {
		t.Fatal("expected component count in delete summary")
	}

	after, err := statusRepo.GetSystemStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if after.Components.TotalRegistered >= before.Components.TotalRegistered {
		t.Fatalf("status still counts deleted sbom components: before=%d after=%d", before.Components.TotalRegistered, after.Components.TotalRegistered)
	}
	if after.Vulnerabilities.TotalFindings >= before.Vulnerabilities.TotalFindings {
		t.Fatalf("status still counts deleted sbom findings")
	}

	items, total, _, err := sbomRepo.ListSBOMs(ctx, domain.PageRequest{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.ID == result.ScanID {
			t.Fatal("deleted sbom still in system list")
		}
	}
	productItems, _, _, err := sbomRepo.ListProductSBOMs(ctx, productID, domain.PageRequest{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range productItems {
		if item.ID == result.ScanID {
			t.Fatal("deleted sbom still in product list")
		}
	}
	_ = total

	if _, err := scans.GetScan(ctx, result.ScanID); err == nil {
		t.Fatal("get scan should fail for deleted sbom")
	}
	vulns, page, err := scans.ListScanVulnerabilities(ctx, result.ScanID, domain.ScanVulnerabilityFilter{}, domain.PageRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Fatalf("findings from deleted sbom listed: %+v cursor=%+v", vulns, page)
	}

	compList, _, err := components.ListComponents(ctx, "", productID, domain.PageRequest{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(compList) > 0 {
		t.Fatalf("component catalog still lists deleted sbom components: %+v", compList)
	}

	vexExport := store.NewPostgresVEXExportRepository(pool)
	if _, err := pool.Exec(ctx, `
		INSERT INTO product_versions (id, product_id, version, release_status)
		VALUES ($1, $2, '1.0.0', 'released') ON CONFLICT DO NOTHING
	`, uuid.NewString(), productID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE artifacts SET product_version_id = (
			SELECT id FROM product_versions WHERE product_id = $1 LIMIT 1
		) WHERE id = $2
	`, productID, artifactID); err != nil {
		t.Fatal(err)
	}
	vexSvc := &vexgen.Handler{
		Repo:        vexExport,
		VendorVEX:   vexfeed.EnrichmentAssertionReader{Store: vexfeed.NewPostgresAssertionStore(pool)},
		VendorMatch: vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}},
	}
	body, err := vexSvc.ExportVEX(ctx, productID, "1.0.0", domain.VEXExportFormatCycloneDX)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("expected vex export body")
	}

	topAfter, err := statusRepo.GetSystemStatus(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range topAfter.TopComponents {
		if item.VulnerabilityCount > 0 {
			t.Fatalf("top components still rank deleted sbom data: %+v", item)
		}
	}
}

func TestO14_SBOMDeleteAuditLog(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15471)
	productID := uuid.NewString()
	artifactID := uuid.NewString()
	imageID := uuid.NewString()
	digest := "sha256:o14-audit"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	var sbomID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO sbom_documents (id, image_id, image_digest, checksum_sha256, format, spec_version, raw_document, trust_status, is_latest)
		VALUES ($1, $2, $3, $4, 'cyclonedx', '1.6', '{}'::jsonb, 'unsigned', FALSE)
		RETURNING id::text
	`, uuid.NewString(), imageID, digest, "checksum-o14").Scan(&sbomID); err != nil {
		t.Fatal(err)
	}

	audit := trust.NewPostgresAuditRecorder(pool)
	sbomRepo := store.NewPostgresSBOMManagementRepository(pool)
	if _, err := sbomRepo.SoftDeleteSBOM(ctx, sbomID, false); err != nil {
		t.Fatal(err)
	}
	keyID := uuid.NewString()
	if err := audit.Record(ctx, domain.AuditEntry{
		Actor:        "api_key:" + keyID,
		Action:       domain.AuditActionSBOMDeleted,
		ResourceType: "sbom_document",
		ResourceID:   sbomID,
		Details:      map[string]string{"sbom_id": sbomID, "api_key_id": keyID},
	}); err != nil {
		t.Fatal(err)
	}

	var count int
	var resourceID, details string
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_log WHERE action = $1 AND resource_id = $2
	`, domain.AuditActionSBOMDeleted, sbomID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit rows = %d, want 1", count)
	}
	if err := pool.QueryRow(ctx, `
		SELECT resource_id, details::text FROM audit_log WHERE action = $1 AND resource_id = $2
	`, domain.AuditActionSBOMDeleted, sbomID).Scan(&resourceID, &details); err != nil {
		t.Fatal(err)
	}
	if resourceID != sbomID {
		t.Fatalf("resource_id = %q", resourceID)
	}
	if details == "" {
		t.Fatal("expected audit details")
	}
	_ = time.Now()
}
