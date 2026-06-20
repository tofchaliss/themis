//go:build integration

package store_test

import (
	"fmt"
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
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

func TestAC21_BlastRadiusCap(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15459)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:ac21-blast-radius"
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

	ms, err := graph.CreateMicroservice(ctx, domain.Microservice{
		ProductID: productID,
		Name:      "checkout-api",
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		customer, err := graph.CreateCustomer(ctx, domain.Customer{
			Name:         fmt.Sprintf("team-%d", i),
			ContactEmail: fmt.Sprintf("team-%d@example.com", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := graph.CreateDeployment(ctx, domain.Deployment{
			MicroserviceID: ms.ID,
			CustomerID:     customer.ID,
			Environment:    "production",
			Region:         fmt.Sprintf("region-%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}

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
	if _, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindSBOM,
			Format:           domain.SBOMFormatCycloneDX,
			SpecVersion:      "1.6",
			RawDocument:      raw,
			ImageDigest:      digest,
			CIJobID:          "ac21-job",
			CIPipelineURL:    "https://ci.example/ac21",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	}); err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	var (
		total int
		max   float64
	)
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*), COALESCE(MAX(rc.blast_radius_score), 0)
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE sr.image_digest = $1
	`, digest).Scan(&total, &max); err != nil {
		t.Fatal(err)
	}
	if total == 0 {
		t.Fatal("expected findings")
	}
	if max != 2.0 {
		t.Fatalf("max blast_radius_score = %v, want 2.0", max)
	}
}

func TestAC21_BlastRadiusCustomerDedup(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15460)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'dedup-product')`, productID); err != nil {
		t.Fatal(err)
	}
	ms, err := graph.CreateMicroservice(ctx, domain.Microservice{ProductID: productID, Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	customer, err := graph.CreateCustomer(ctx, domain.Customer{Name: "shared-team", ContactEmail: "shared@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := graph.CreateDeployment(ctx, domain.Deployment{
			MicroserviceID: ms.ID,
			CustomerID:     customer.ID,
			Environment:    "production",
			Region:         fmt.Sprintf("r%d", i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := graph.ProductBlastRadius(ctx, productID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CustomerIDs) != 1 {
		t.Fatalf("unique customers = %d, want 1", len(result.CustomerIDs))
	}
	if result.Score != 1.0 {
		t.Fatalf("score = %v, want 1.0", result.Score)
	}
}

func TestAC20_Layer2SynchronousBeforeAccepted(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15461)
	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:ac20-layer2-sync"
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
	if _, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind: domain.ArtifactKindSBOM, Format: domain.SBOMFormatCycloneDX, SpecVersion: "1.6",
			RawDocument: raw, ImageDigest: digest, CIJobID: "ac20-l2", SupplierIdentity: "team-a", Actor: "test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	}); err != nil {
		t.Fatal(err)
	}

	var missing int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FILTER (WHERE rc.blast_radius_score IS NULL)
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE sr.image_digest = $1
	`, digest).Scan(&missing); err != nil {
		t.Fatal(err)
	}
	if missing > 0 {
		t.Fatalf("%d findings missing blast_radius_score", missing)
	}
}

func TestSoftDelete_ExcludedFromBlastRadius(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15462)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:soft-delete-blast"
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions)
		VALUES ('CVE-2021-23337', 'high', 'npm:lodash,4.17.21', ARRAY['4.17.21'])
		ON CONFLICT (cve_id) DO NOTHING
	`); err != nil {
		t.Fatal(err)
	}

	ms, err := graph.CreateMicroservice(ctx, domain.Microservice{ProductID: productID, Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	customer, err := graph.CreateCustomer(ctx, domain.Customer{Name: "team", ContactEmail: "team@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graph.CreateDeployment(ctx, domain.Deployment{
		MicroserviceID: ms.ID, CustomerID: customer.ID, Environment: "prod", Region: "us",
	}); err != nil {
		t.Fatal(err)
	}

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
		ArtifactID:  artifactID,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(ctx, `UPDATE scan_reports SET deleted_at = NOW() WHERE id = $1`, result.ScanID); err != nil {
		t.Fatal(err)
	}

	findings, err := enrichmentRepo.ListFindingsForArtifact(ctx, artifactID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("deleted sbom findings listed = %d, want 0", len(findings))
	}

	var componentID, vulnID string
	if err := pool.QueryRow(ctx, `
		SELECT c.id::text, v.id::text
		FROM component_vulnerabilities cv
		JOIN components c ON c.id = (SELECT component_id FROM component_versions WHERE id = cv.component_version_id)
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.scan_report_id = $1 LIMIT 1
	`, result.ScanID).Scan(&componentID, &vulnID); err != nil {
		t.Fatal(err)
	}

	blast, err := graph.ComputeBlastRadius(ctx, domain.EnrichmentFinding{
		ScanReportID:    result.ScanID,
		ProductID:       productID,
		ComponentID:     componentID,
		VulnerabilityID: vulnID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if blast.Score != 1.0 || len(blast.CustomerIDs) != 0 {
		t.Fatalf("deleted sbom blast = %+v, want baseline without customers", blast)
	}
}

func TestBlastRadius_NoGraph(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15463)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'no-graph')`, productID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO asset_graph_nodes (id, node_type, entity_id)
		VALUES ($1, 'Product', $2)
		ON CONFLICT (node_type, entity_id) DO NOTHING
	`, uuid.NewString(), productID); err != nil {
		t.Fatal(err)
	}

	result, err := graph.ProductBlastRadius(ctx, productID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 1.0 || len(result.CustomerIDs) != 0 {
		t.Fatalf("ProductBlastRadius() = %+v, want score 1.0 and no customers", result)
	}
}

func TestBlastRadius_OrphanMicroservice(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15464)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'orphan-ms')`, productID); err != nil {
		t.Fatal(err)
	}
	if _, err := graph.CreateMicroservice(ctx, domain.Microservice{ProductID: productID, Name: "lonely-api"}); err != nil {
		t.Fatal(err)
	}

	result, err := graph.ProductBlastRadius(ctx, productID, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Score != 1.0 || len(result.CustomerIDs) != 0 {
		t.Fatalf("orphan microservice blast = %+v, want score 1.0 and no customers", result)
	}
}

func TestBlastRadius_DepthCap(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15465)
	graph := assetgraph.NewPostgresStore(pool)

	productID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'depth-cap')`, productID); err != nil {
		t.Fatal(err)
	}
	ms, err := graph.CreateMicroservice(ctx, domain.Microservice{ProductID: productID, Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	customer, err := graph.CreateCustomer(ctx, domain.Customer{Name: "team", ContactEmail: "depth@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := graph.CreateDeployment(ctx, domain.Deployment{
		MicroserviceID: ms.ID, CustomerID: customer.ID, Environment: "prod", Region: "us",
	}); err != nil {
		t.Fatal(err)
	}

	var msNodeID, customerNodeID string
	if err := pool.QueryRow(ctx, `
		SELECT ms_node.id::text, cust_node.id::text
		FROM asset_graph_nodes ms_node, asset_graph_nodes cust_node
		WHERE ms_node.node_type = 'Microservice' AND ms_node.entity_id = $1::uuid
		  AND cust_node.node_type = 'Customer' AND cust_node.entity_id = $2::uuid
	`, ms.ID, customer.ID).Scan(&msNodeID, &customerNodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO asset_graph_edges (id, from_node_id, to_node_id, edge_type)
		VALUES ($1, $2::uuid, $3::uuid, $4)
		ON CONFLICT (from_node_id, to_node_id, edge_type) DO NOTHING
	`, uuid.NewString(), customerNodeID, msNodeID, domain.GraphEdgeTypeMicroserviceDeploy); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := graph.ProductBlastRadius(ctx, productID, "", "")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blast-radius traversal timed out with cyclic graph")
	}
}

func TestBlastRadius_SharedCustomerDedup(t *testing.T) {
	// Alias for AC-21 dedup scenario; keeps tasks.md test name discoverable.
	TestAC21_BlastRadiusCustomerDedup(t)
}
