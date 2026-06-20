//go:build integration

package store_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

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

func TestIngestionPipelineIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15442)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	resetIntegrationDatabase(t, pool)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:integration-ingestion"
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}

	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	jobs := store.NewPostgresIngestionRepository(pool)
	trustRepo := trust.NewPostgresRepository(pool)
	audit := trust.NewPostgresAuditRecorder(pool)
	gate := &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trustRepo, Audit: audit}
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       jobs,
		Trust:      trust.GateEvaluator{Gate: gate},
		Parser:     parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:       store.NewPostgresSBOMStore(pool),
		Components: store.NewPostgresComponentStore(pool),
		Catalog:    store.NewPostgresVulnerabilityCatalog(pool),
		Fetcher: store.StaticVulnerabilityFetcher{Records: []domain.VulnerabilityRecord{
			{CVEID: "CVE-2021-23337", Severity: "high", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"4.17.21"}},
			{CVEID: "CVE-2021-23337", Severity: "high", Ecosystem: "npm", PackageName: "express", AffectedVersions: []string{"4.18.2"}},
		}},
		Correlate:  store.NewPostgresCorrelationRepository(pool),
		Enrichment: &enrichment.Handler{Repo: store.NewPostgresEnrichmentRepository(pool), Audit: audit},
		Notify:     notify.IngestionNotifier{},
	})

	input := domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindSBOM,
			Format:           domain.SBOMFormatCycloneDX,
			SpecVersion:      "1.6",
			RawDocument:      raw,
			ImageDigest:      digest,
			CIJobID:          "job-1",
			CIPipelineURL:    "https://ci.example/run/1",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
			ProductOwner:     "team-a",
		},
		IdempotencyKey: "integration-key-1",
		TrustPolicy:    domain.TrustPolicyStandard,
		ArtifactID:     artifactID,
	}

	result, err := pipeline.IngestSBOM(ctx, input)
	if err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}

	var jobStatus string
	if err := pool.QueryRow(ctx, `SELECT payload->>'pipeline_status' FROM ingestion_jobs WHERE id = $1`, result.IngestionID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != string(domain.IngestionStatusNotified) {
		t.Fatalf("pipeline status = %q", jobStatus)
	}

	var componentVulnCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM component_vulnerabilities`).Scan(&componentVulnCount); err != nil {
		t.Fatal(err)
	}
	if componentVulnCount == 0 {
		t.Fatal("expected component_vulnerabilities rows")
	}

	var riskCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context`).Scan(&riskCount); err != nil {
		t.Fatal(err)
	}
	if riskCount == 0 {
		t.Fatal("expected risk_context rows")
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount == 0 {
		t.Fatal("expected audit_log rows")
	}

	dup, err := pipeline.IngestSBOM(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if !dup.Duplicate || dup.IngestionID != result.IngestionID {
		t.Fatalf("duplicate result = %+v", dup)
	}

	var sbomChecksum string
	if err := pool.QueryRow(ctx, `SELECT s.sbom_checksum FROM scan_reports sr JOIN sboms s ON s.id = sr.sbom_id WHERE sr.id = $1`, result.ScanID).Scan(&sbomChecksum); err != nil {
		t.Fatal(err)
	}

	vexResult, err := pipeline.IngestVEX(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindVEX,
			Format:           "openvex",
			SpecVersion:      "1.0.0",
			RawDocument:      []byte(`{"@context":"https://openvex.dev/ns","statements":[]}`),
			SBOMChecksum:     sbomChecksum,
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
			ProductOwner:     "team-a",
		},
		TrustPolicy: domain.TrustPolicyStandard,
	})
	if err != nil {
		t.Fatalf("IngestVEX() error = %v", err)
	}
	if vexResult.Status != domain.IngestionStatusNotified {
		t.Fatalf("vex result = %+v", vexResult)
	}
}

func TestEnrichmentVEXOverlayIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15443)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	resetIntegrationDatabase(t, pool)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:enrichment-integration"
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
			CIJobID:          "job-1",
			CIPipelineURL:    "https://ci.example/run/1",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	})
	if err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	var effectiveState string
	if err := pool.QueryRow(ctx, `
		SELECT rc.effective_state
		FROM risk_context rc
		JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id
		WHERE cv.scan_report_id = $1
		LIMIT 1
	`, sbomResult.ScanID).Scan(&effectiveState); err != nil {
		t.Fatal(err)
	}
	if effectiveState != domain.EffectiveStateDetected {
		t.Fatalf("effective_state = %q", effectiveState)
	}

	var sbomChecksum string
	if err := pool.QueryRow(ctx, `SELECT s.sbom_checksum FROM scan_reports sr JOIN sboms s ON s.id = sr.sbom_id WHERE sr.id = $1`, sbomResult.ScanID).Scan(&sbomChecksum); err != nil {
		t.Fatal(err)
	}

	vexDoc := []byte(`{"@context":"https://openvex.dev/ns","statements":[{"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"not_affected","justification":"component_not_present"}]}`)
	if _, err := pipeline.IngestVEX(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindVEX,
			Format:           "openvex",
			SpecVersion:      "1.0.0",
			RawDocument:      vexDoc,
			SBOMChecksum:     sbomChecksum,
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
	}); err != nil {
		t.Fatalf("IngestVEX() error = %v", err)
	}

	if err := pool.QueryRow(ctx, `
		SELECT rc.effective_state, rc.raw_severity, v.severity
		FROM risk_context rc
		JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.scan_report_id = $1
		LIMIT 1
	`, sbomResult.ScanID).Scan(&effectiveState, new(string), new(string)); err != nil {
		t.Fatal(err)
	}
	if effectiveState != domain.EffectiveStateSuppressed {
		t.Fatalf("effective_state after vex = %q", effectiveState)
	}

	revokeDoc := []byte(`{"@context":"https://openvex.dev/ns","statements":[{"vulnerability":{"name":"CVE-2021-23337"},"products":[{"@id":"pkg:npm/lodash@4.17.21"}],"status":"under_investigation"}]}`)
	if _, err := pipeline.IngestVEX(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindVEX,
			Format:           "openvex",
			SpecVersion:      "1.0.0",
			RawDocument:      revokeDoc,
			SBOMChecksum:     sbomChecksum,
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
	}); err != nil {
		t.Fatalf("revoking IngestVEX() error = %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT rc.effective_state FROM risk_context rc
		JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id
		WHERE cv.scan_report_id = $1 LIMIT 1
	`, sbomResult.ScanID).Scan(&effectiveState); err != nil {
		t.Fatal(err)
	}
	if effectiveState != domain.EffectiveStateDetected {
		t.Fatalf("effective_state after revoke = %q", effectiveState)
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_log WHERE action = $1`, domain.AuditActionRiskStateTransition).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount == 0 {
		t.Fatal("expected enrichment audit entries")
	}
}

// seedImageForProduct creates a project → version → artifact chain for an existing
// product (v0.3.0 model). imageID is retained for call-site compatibility but the
// artifact is the unit of identity (image_digest globally unique).
func seedImageForProduct(t *testing.T, ctx context.Context, pool *pgxpool.Pool, productID, artifactID, imageID, digest string) {
	t.Helper()
	projectID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO projects (id, product_id, name, is_default) VALUES ($1, $2, $3, FALSE)`,
		projectID, productID, "proj-"+artifactID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	versionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO versions (id, project_id, version) VALUES ($1, $2, $3)`,
		versionID, projectID, "v-"+artifactID); err != nil {
		t.Fatalf("insert version: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO artifacts (id, version_id, artifact_type, image_digest, repository)
		VALUES ($1, $2, 'image', $3, 'themis/app')
	`, artifactID, versionID, digest); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	_ = imageID
}

func seedBaseData(t *testing.T, ctx context.Context, pool *pgxpool.Pool, productID, artifactID, imageID, digest string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO products (id, name) VALUES ($1, 'integration-product')`, productID); err != nil {
		t.Fatalf("insert product: %v", err)
	}
	seedImageForProduct(t, ctx, pool, productID, artifactID, imageID, digest)
}
