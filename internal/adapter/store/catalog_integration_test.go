//go:build integration

package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

func TestCatalogRepositoriesIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := integrationDatabaseDSN(t, 15452)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	resetIntegrationDatabase(t, pool)

	catalog := store.NewPostgresProductCatalogRepository(pool)
	scans := store.NewPostgresScanQueryRepository(pool)
	components := store.NewPostgresComponentCatalogRepository(pool)
	watchFindings := store.NewPostgresCVEWatchFindingRepository(pool)
	notifyCfg := store.NewPostgresNotificationConfigRepository(pool)
	scannerCfg := store.NewPostgresScannerConfigRepository(pool)

	product, err := catalog.CreateProduct(ctx, "alpha-catalog", "first product")
	if err != nil {
		t.Fatalf("CreateProduct() error = %v", err)
	}
	if _, err := catalog.CreateProduct(ctx, "beta-catalog", ""); err != nil {
		t.Fatalf("CreateProduct beta: %v", err)
	}

	listed, page, err := catalog.ListProducts(ctx, domain.PageRequest{Limit: 1}, "")
	if err != nil || len(listed) != 1 || page.NextCursor == "" {
		t.Fatalf("ListProducts() = %+v page=%+v err=%v", listed, page, err)
	}
	if _, _, err := catalog.ListProducts(ctx, domain.PageRequest{}, product.ID); err != nil {
		t.Fatalf("ListProducts scoped: %v", err)
	}
	if got, err := catalog.GetProduct(ctx, product.ID); err != nil || got.Name != "alpha-catalog" {
		t.Fatalf("GetProduct() = %+v err=%v", got, err)
	}

	project, err := catalog.CreateProject(ctx, product.ID, "main", "primary app")
	if err != nil {
		t.Fatalf("CreateProject() error = %v", err)
	}
	projects, _, err := catalog.ListProjects(ctx, product.ID, domain.PageRequest{Limit: 10})
	if err != nil || len(projects) != 1 {
		t.Fatalf("ListProjects() = %+v err=%v", projects, err)
	}
	if _, _, err := catalog.ListProductVersions(ctx, product.ID, domain.PageRequest{}); err != nil {
		t.Fatalf("ListProductVersions() error = %v", err)
	}

	digest := "sha256:catalog-integration"
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	seedImageForProduct(t, ctx, pool, product.ID, artifactID, imageID, digest)
	if _, err := pool.Exec(ctx, `UPDATE images SET product_id = $1 WHERE id = $2`, product.ID, imageID); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions)
		VALUES ('CVE-2021-23337', 'high', 'npm:lodash,4.17.21', ARRAY['4.17.21'])
		ON CONFLICT (cve_id) DO NOTHING
	`); err != nil {
		t.Fatal(err)
	}

	jobs := store.NewPostgresIngestionRepository(pool)
	trustRepo := trust.NewPostgresRepository(pool)
	audit := trust.NewPostgresAuditRecorder(pool)
	gate := &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trustRepo, Audit: audit}
	enrichmentSvc := &enrichment.Handler{Repo: store.NewPostgresEnrichmentRepository(pool), Audit: audit}
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       jobs,
		Trust:      trust.GateEvaluator{Gate: gate},
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
	sbomResult, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindSBOM,
			Format:           domain.SBOMFormatCycloneDX,
			SpecVersion:      "1.6",
			RawDocument:      raw,
			ImageDigest:      digest,
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ImageID:     imageID,
		ProjectID:   project.ID,
	})
	if err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE sbom_documents SET project_id = $1 WHERE id = $2
	`, project.ID, sbomResult.ScanID); err != nil {
		t.Fatal(err)
	}

	scanList, _, err := scans.ListProjectScans(ctx, project.ID, domain.PageRequest{Limit: 10})
	if err != nil || len(scanList) == 0 {
		t.Fatalf("ListProjectScans() = %+v err=%v", scanList, err)
	}
	detail, err := scans.GetScan(ctx, scanList[0].ID)
	if err != nil || detail.ID != scanList[0].ID {
		t.Fatalf("GetScan() = %+v err=%v", detail, err)
	}
	vulns, _, err := scans.ListScanVulnerabilities(ctx, scanList[0].ID, domain.ScanVulnerabilityFilter{
		Severity: "high",
	}, domain.PageRequest{Limit: 10})
	if err != nil || len(vulns) == 0 {
		t.Fatalf("ListScanVulnerabilities() = %+v err=%v", vulns, err)
	}
	if pid, err := scans.GetProjectProductID(ctx, project.ID); err != nil || pid != product.ID {
		t.Fatalf("GetProjectProductID() = %q err=%v", pid, err)
	}

	comps, _, err := components.ListComponents(ctx, "pkg:npm/lodash@4.17.21", product.ID, domain.PageRequest{Limit: 10})
	if err != nil {
		t.Fatalf("ListComponents() error = %v", err)
	}
	if len(comps) == 0 {
		t.Fatal("expected catalog components")
	}

	if _, err := notifyCfg.ListRules(ctx); err != nil {
		t.Fatalf("ListRules() error = %v", err)
	}
	if err := notifyCfg.ReplaceRules(ctx, []domain.NotificationRule{{
		Name: "test", EventType: domain.NotificationEventIngestionCompleted,
		Channel: domain.NotificationChannelEmail, Destination: "ops@example.com", Enabled: true,
	}}); err != nil {
		t.Fatalf("ReplaceRules() error = %v", err)
	}

	settings, err := scannerCfg.Get(ctx)
	if err != nil {
		t.Fatalf("Get scanner settings: %v", err)
	}
	settings.MaxComponents = 750
	if err := scannerCfg.Save(ctx, settings); err != nil {
		t.Fatalf("Save scanner settings: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO cve_watch_findings (id, cve_id, product_id, status, details, detected_at)
		VALUES ($1, 'CVE-2021-23337', $2, 'new', '{"severity":"high"}', NOW())
	`, uuid.NewString(), product.ID); err != nil {
		t.Fatalf("insert watch finding: %v", err)
	}
	findings, _, err := watchFindings.ListFindings(ctx, product.ID, "high", domain.PageRequest{Limit: 10})
	if err != nil || len(findings) == 0 {
		t.Fatalf("ListFindings() = %+v err=%v", findings, err)
	}

	threatStore := store.NewPostgresThreatSignalStore(pool)
	if err := threatStore.UpsertEPSS(ctx, []domain.EPSSSignal{{
		CVEID: "CVE-2021-23337", Score: 0.42, FetchedAt: time.Now().UTC(),
	}}); err != nil {
		t.Fatalf("UpsertEPSS: %v", err)
	}
	if _, err := threatStore.LastSuccessfulFetch(ctx); err != nil {
		t.Fatalf("LastSuccessfulFetch: %v", err)
	}
}
