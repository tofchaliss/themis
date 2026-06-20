//go:build integration

package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

// TestAC20_Layer1SynchronousBeforeAccepted verifies AC-20: deterministic_level is set during sync enrichment.
func TestAC20_Layer1SynchronousBeforeAccepted(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15458)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:ac20-layer1-sync"
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, cvss_score, description, affected_versions)
		VALUES ('CVE-2021-23337', 'high', 7.5, 'npm:lodash,4.17.21', ARRAY['4.17.21'])
		ON CONFLICT (cve_id) DO NOTHING
	`); err != nil {
		t.Fatal(err)
	}

	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	enrichmentSvc := &enrichment.Handler{Repo: enrichmentRepo}
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
	if _, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindSBOM,
			Format:           domain.SBOMFormatCycloneDX,
			SpecVersion:      "1.6",
			RawDocument:      raw,
			ImageDigest:      digest,
			CIJobID:          "ac20-job",
			CIPipelineURL:    "https://ci.example/ac20",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	}); err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	var (
		total   int
		missing int
	)
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE rc.deterministic_level IS NULL OR rc.deterministic_level = '')
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE sr.image_digest = $1
	`, digest).Scan(&total, &missing); err != nil {
		t.Fatal(err)
	}
	if total == 0 {
		t.Fatal("expected findings on ingested SBOM")
	}
	if missing > 0 {
		t.Fatalf("%d/%d findings missing deterministic_level", missing, total)
	}
}
