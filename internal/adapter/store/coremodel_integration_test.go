//go:build integration

package store_test

import (
	"context"
	"encoding/json"
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
	"github.com/themis-project/themis/internal/usecase/triage"
)

// coreModelConnect returns a pool against a freshly reset core-model schema.
func coreModelConnect(t *testing.T, port uint32) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}
	ctx := context.Background()
	dsn := integrationDatabaseDSN(t, port)
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
	return ctx, pool
}

// coreModelPipeline builds an ingestion pipeline + triage handler wired to the real
// PostgreSQL stores, with a static fetcher that returns the lodash CVE used by the
// cyclonedx-1.6 fixture.
func coreModelPipeline(pool *pgxpool.Pool) (*ingestion.Pipeline, *triage.Handler) {
	audit := trust.NewPostgresAuditRecorder(pool)
	trustRepo := trust.NewPostgresRepository(pool)
	gate := &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trustRepo, Audit: audit}
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       store.NewPostgresIngestionRepository(pool),
		Trust:      trust.GateEvaluator{Gate: gate},
		Parser:     parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:       store.NewPostgresSBOMStore(pool),
		Components: store.NewPostgresComponentStore(pool),
		Catalog:    store.NewPostgresVulnerabilityCatalog(pool),
		Fetcher: store.StaticVulnerabilityFetcher{Records: []domain.VulnerabilityRecord{
			{CVEID: "CVE-2021-23337", Severity: "high", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"4.17.21"}},
		}},
		Correlate:  store.NewPostgresCorrelationRepository(pool),
		Enrichment: &enrichment.Handler{Repo: store.NewPostgresEnrichmentRepository(pool), Audit: audit},
		Notify:     notify.IngestionNotifier{},
	})
	triageHandler := &triage.Handler{
		Repo:  store.NewPostgresTriageRepository(pool),
		VEX:   store.NewPostgresTriageVEXGenerator(pool),
		Audit: audit,
	}
	return pipeline, triageHandler
}

func coreModelSeedLodashCVE(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions)
		VALUES ('CVE-2021-23337', 'high', 'npm:lodash,4.17.21', ARRAY['4.17.21'])
		ON CONFLICT (cve_id) DO NOTHING
	`); err != nil {
		t.Fatal(err)
	}
}

func coreModelFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// variantDocument returns a byte-distinct copy of an SBOM (a new serialNumber) with
// identical components — so its checksum differs (new sboms row + scan_report) while
// correlation produces the same finding identity. This models a real "rescan".
func variantDocument(t *testing.T, raw []byte, marker string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["serialNumber"] = "urn:uuid:" + marker
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func coreModelIngest(t *testing.T, ctx context.Context, pipeline *ingestion.Pipeline, artifactID, digest string, doc []byte, idem string) domain.IngestionResult {
	t.Helper()
	result, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindSBOM,
			Format:           domain.SBOMFormatCycloneDX,
			SpecVersion:      "1.6",
			RawDocument:      doc,
			ImageDigest:      digest,
			CIJobID:          "job",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		IdempotencyKey: idem,
		TrustPolicy:    domain.TrustPolicyStandard,
		ArtifactID:     artifactID,
	})
	if err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}
	return result
}

// 8.2 — risk_context PK (artifact_id, component_purl, cve_id): two versions of the
// same package on the same artifact are distinct identities (D11/H3: busybox 1.35 vs
// 1.36), and triaging one does not touch the other.
func TestCoreModelRiskContextDistinctVersions(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15461)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-distinct-versions"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)

	sbomID, scanReportID := seedScan(t, ctx, pool, artifactID)
	purl135 := addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, "pkg:apk/busybox", "1.35.0", "CVE-2022-28391", "high", "detected")
	purl136 := addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, "pkg:apk/busybox", "1.36.0", "CVE-2022-28391", "high", "detected")
	if purl135 == purl136 {
		t.Fatalf("expected distinct version-qualified purls, got %q", purl135)
	}

	var rcCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context WHERE artifact_id = $1`, artifactID).Scan(&rcCount); err != nil {
		t.Fatal(err)
	}
	if rcCount != 2 {
		t.Fatalf("risk_context rows for distinct versions = %d, want 2", rcCount)
	}

	// Re-writing the same identity upserts on the PK (artifact_id, component_purl,
	// cve_id), never a third row.
	if _, err := pool.Exec(ctx, `
		INSERT INTO risk_context (artifact_id, component_purl, cve_id, effective_state, priority, risk_score, raw_severity)
		VALUES ($1, $2, $3, 'detected', 'high', 40, 'high')
		ON CONFLICT (artifact_id, component_purl, cve_id) DO UPDATE SET effective_state = EXCLUDED.effective_state
	`, artifactID, purl135, "CVE-2022-28391"); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context WHERE artifact_id = $1`, artifactID).Scan(&rcCount); err != nil {
		t.Fatal(err)
	}
	if rcCount != 2 {
		t.Fatalf("risk_context rows after re-upsert = %d, want 2 (PK collapses duplicates)", rcCount)
	}

	// Triaging one version's identity must leave the other untouched.
	if _, err := pool.Exec(ctx, `
		UPDATE risk_context SET effective_state = 'false_positive'
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, purl135, "CVE-2022-28391"); err != nil {
		t.Fatal(err)
	}
	var state136 string
	if err := pool.QueryRow(ctx, `
		SELECT effective_state FROM risk_context
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, purl136, "CVE-2022-28391").Scan(&state136); err != nil {
		t.Fatal(err)
	}
	if state136 != "detected" {
		t.Fatalf("untouched version state = %q, want detected", state136)
	}
}

// 8.3 — durable enrichment (D15): triage + an in_progress remediation survive a rescan
// of the same artifact without recomputation. The new scan produces the same finding
// identity; the human judgment on (artifact_id, component_purl, cve_id) is retained.
func TestCoreModelDurableEnrichmentSurvivesRescan(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15462)
	coreModelSeedLodashCVE(t, ctx, pool)
	pipeline, triageHandler := coreModelPipeline(pool)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-durable"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)
	raw := coreModelFixture(t)

	first := coreModelIngest(t, ctx, pipeline, artifactID, digest, raw, "durable-1")
	if first.Status != domain.IngestionStatusNotified {
		t.Fatalf("first ingest = %+v", first)
	}

	var findingID, componentPURL, cveID string
	if err := pool.QueryRow(ctx, `
		SELECT id::text, component_purl, cve_id
		FROM component_vulnerabilities WHERE scan_report_id = $1 LIMIT 1
	`, first.ScanID).Scan(&findingID, &componentPURL, &cveID); err != nil {
		t.Fatal(err)
	}

	if _, err := triageHandler.Submit(ctx, domain.TriageDecision{
		FindingID:     findingID,
		Decision:      domain.TriageDecisionFalsePositive,
		Justification: "not reachable",
		Actor:         "analyst-1",
	}); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	// A Phase 2b-shaped remediation row keyed on the stable identity.
	if _, err := pool.Exec(ctx, `
		INSERT INTO remediation_actions (artifact_id, component_purl, cve_id, action_type, status)
		VALUES ($1, $2, $3, 'upgrade', 'in_progress')
	`, artifactID, componentPURL, cveID); err != nil {
		t.Fatal(err)
	}

	var stateAfterTriage string
	if err := pool.QueryRow(ctx, `
		SELECT effective_state FROM risk_context
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, componentPURL, cveID).Scan(&stateAfterTriage); err != nil {
		t.Fatal(err)
	}

	// Rescan the SAME artifact with a byte-distinct SBOM (new scan_report).
	second := coreModelIngest(t, ctx, pipeline, artifactID, digest, variantDocument(t, raw, "durable-rescan"), "durable-2")
	if second.Duplicate || second.ScanID == first.ScanID {
		t.Fatalf("expected a new scan report on rescan, got %+v", second)
	}

	var stateAfterRescan string
	if err := pool.QueryRow(ctx, `
		SELECT effective_state FROM risk_context
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, componentPURL, cveID).Scan(&stateAfterRescan); err != nil {
		t.Fatal(err)
	}
	// The human decision must persist as a suppression-family state (re-applied via the
	// themis_generated VEX overlay), never silently revert to detected on rescan.
	if stateAfterRescan == domain.EffectiveStateDetected {
		t.Fatalf("triage lost on rescan: effective_state reverted to detected (was %q after triage)", stateAfterTriage)
	}

	var historyCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM triage_history
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, componentPURL, cveID).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 1 {
		t.Fatalf("triage history mutated on rescan: count = %d, want 1", historyCount)
	}

	var remediationStatus string
	if err := pool.QueryRow(ctx, `
		SELECT status FROM remediation_actions
		WHERE artifact_id = $1 AND component_purl = $2 AND cve_id = $3
	`, artifactID, componentPURL, cveID).Scan(&remediationStatus); err != nil {
		t.Fatal(err)
	}
	if remediationStatus != "in_progress" {
		t.Fatalf("remediation lost on rescan: status = %q, want in_progress", remediationStatus)
	}
}

// 8.3a — additivity assertion (D15): a representative ai_*-shaped table keyed on the
// stable identity attaches and joins to the latest-scan finding with NO ALTER to any
// core-model table — proving the Phase 2b base is clean.
func TestCoreModelAdditivityAttachesToLatestFinding(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15463)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-additivity"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)
	_, purl := seedFinding(t, ctx, pool, artifactID, "pkg:npm/lodash", "4.17.21", "CVE-2021-23337", "high", "detected")

	// Phase 2b would add a table exactly like this — additively, no core-model ALTER.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE ai_exploitability_test (
			artifact_id UUID NOT NULL,
			component_purl TEXT NOT NULL,
			cve_id TEXT NOT NULL,
			confidence DOUBLE PRECISION NOT NULL,
			PRIMARY KEY (artifact_id, component_purl, cve_id)
		)
	`); err != nil {
		t.Fatalf("create additive table: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS ai_exploitability_test`) })

	if _, err := pool.Exec(ctx, `
		INSERT INTO ai_exploitability_test (artifact_id, component_purl, cve_id, confidence)
		VALUES ($1, $2, $3, 0.91)
	`, artifactID, purl, "CVE-2021-23337"); err != nil {
		t.Fatalf("insert additive row: %v", err)
	}

	// The additive row joins to the latest-scan finding via the stable identity.
	var confidence float64
	if err := pool.QueryRow(ctx, `
		SELECT ai.confidence
		FROM v_latest_findings lf
		JOIN ai_exploitability_test ai
		  ON ai.artifact_id = lf.artifact_id
		 AND ai.component_purl = lf.component_purl
		 AND ai.cve_id = lf.cve_id
		WHERE lf.artifact_id = $1
	`, artifactID).Scan(&confidence); err != nil {
		t.Fatalf("join additive table to latest finding: %v", err)
	}
	if confidence != 0.91 {
		t.Fatalf("joined confidence = %v, want 0.91", confidence)
	}
}

// CR-3 — finding provenance: an ingested finding records the source that produced
// it (here the local catalog hit) and what that source asserted, never the
// pre-provenance 'legacy' default.
func TestCoreModelFindingProvenance(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15468)
	coreModelSeedLodashCVE(t, ctx, pool)
	pipeline, _ := coreModelPipeline(pool)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-provenance"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)

	result := coreModelIngest(t, ctx, pipeline, artifactID, digest, coreModelFixture(t), "provenance-1")
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("ingest status = %s", result.Status)
	}

	var source, sourceSeverity string
	if err := pool.QueryRow(ctx, `
		SELECT cv.source, cv.source_severity
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		WHERE sr.artifact_id = $1 AND cv.cve_id = 'CVE-2021-23337'
	`, artifactID).Scan(&source, &sourceSeverity); err != nil {
		t.Fatalf("read provenance: %v", err)
	}
	if source == domain.FindingSourceLegacy || source == "" {
		t.Fatalf("finding source not recorded: %q", source)
	}
	if source != domain.FindingSourceCatalog {
		t.Fatalf("catalog-matched finding source = %q, want %q", source, domain.FindingSourceCatalog)
	}
	if sourceSeverity != "high" {
		t.Fatalf("source_severity = %q, want high", sourceSeverity)
	}
}

// 8.4 — latest-scan counts (D10/H2): N rescans of one artifact yield latest-scan-only
// counts, not N×. v_latest_findings (and everything routed through it) sees one scan.
func TestCoreModelLatestScanCounts(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15464)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-latest-scan"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)

	const rescans = 4
	for range rescans {
		sbomID, scanReportID := seedScan(t, ctx, pool, artifactID)
		addFinding(t, ctx, pool, artifactID, sbomID, scanReportID, "pkg:npm/lodash", "4.17.21", "CVE-2021-23337", "high", "detected")
	}

	var scanReportCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_reports WHERE artifact_id = $1`, artifactID).Scan(&scanReportCount); err != nil {
		t.Fatal(err)
	}
	if scanReportCount != rescans {
		t.Fatalf("scan_reports = %d, want %d", scanReportCount, rescans)
	}

	var latestFindings int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM v_latest_findings WHERE artifact_id = $1`, artifactID).Scan(&latestFindings); err != nil {
		t.Fatal(err)
	}
	if latestFindings != 1 {
		t.Fatalf("v_latest_findings = %d after %d rescans, want 1 (latest only)", latestFindings, rescans)
	}

	// The system status repo is routed through the same filter.
	status, err := store.NewPostgresSystemStatusRepository(pool).GetSystemStatus(ctx, 10)
	if err != nil {
		t.Fatalf("GetSystemStatus() error = %v", err)
	}
	if status.Vulnerabilities.TotalFindings != 1 {
		t.Fatalf("status TotalFindings = %d after %d rescans, want 1", status.Vulnerabilities.TotalFindings, rescans)
	}
}

// 8.5 — idempotent re-submission (D12/H4): an identical re-upload returns the existing
// scan and does not append a phantom scan_report.
func TestCoreModelIdempotentResubmission(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15465)
	coreModelSeedLodashCVE(t, ctx, pool)
	pipeline, _ := coreModelPipeline(pool)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-idempotent"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)
	raw := coreModelFixture(t)

	first := coreModelIngest(t, ctx, pipeline, artifactID, digest, raw, "idem-same")

	var before int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_reports WHERE artifact_id = $1`, artifactID).Scan(&before); err != nil {
		t.Fatal(err)
	}

	second := coreModelIngest(t, ctx, pipeline, artifactID, digest, raw, "idem-same")
	if !second.Duplicate {
		t.Fatalf("identical re-upload not marked duplicate: %+v", second)
	}
	if second.ScanID != first.ScanID {
		t.Fatalf("duplicate scan id changed: %q -> %q", first.ScanID, second.ScanID)
	}

	var after int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_reports WHERE artifact_id = $1`, artifactID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("phantom scan appended: scan_reports %d -> %d", before, after)
	}
}

// 8.6 — divergent SBOM (D9/H1): a second SBOM with a different checksum for the same
// artifact creates a new sboms row; the earlier scan's findings are not orphaned.
func TestCoreModelDivergentSBOM(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15466)
	coreModelSeedLodashCVE(t, ctx, pool)
	pipeline, _ := coreModelPipeline(pool)

	productID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:coremodel-divergent"
	seedBaseData(t, ctx, pool, productID, artifactID, uuid.NewString(), digest)
	raw := coreModelFixture(t)

	first := coreModelIngest(t, ctx, pipeline, artifactID, digest, raw, "divergent-1")
	second := coreModelIngest(t, ctx, pipeline, artifactID, digest, variantDocument(t, raw, "divergent-2"), "divergent-2")
	if second.Duplicate {
		t.Fatalf("divergent SBOM treated as duplicate: %+v", second)
	}

	var sbomCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM sboms WHERE artifact_id = $1`, artifactID).Scan(&sbomCount); err != nil {
		t.Fatal(err)
	}
	if sbomCount != 2 {
		t.Fatalf("sboms rows for divergent uploads = %d, want 2", sbomCount)
	}

	// The earlier scan's raw findings remain (not orphaned, not deleted).
	var firstFindings int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM component_vulnerabilities WHERE scan_report_id = $1`, first.ScanID).Scan(&firstFindings); err != nil {
		t.Fatal(err)
	}
	if firstFindings == 0 {
		t.Fatal("first scan findings orphaned/deleted by divergent upload")
	}
}

// 8.7 — registration endpoints (16.4/16.10): RegisterArtifact returns the existing
// artifact for a duplicate digest; CreateVersion enforces PROJECT_NOT_FOUND and
// VERSION_CONFLICT.
func TestCoreModelRegistrationEndpoints(t *testing.T) {
	ctx, pool := coreModelConnect(t, 15467)
	catalog := store.NewPostgresProductCatalogRepository(pool)

	product, err := catalog.CreateProduct(ctx, "registration-product", "")
	if err != nil {
		t.Fatalf("CreateProduct() error = %v", err)
	}

	digest := "sha256:coremodel-registration"
	artifact, err := catalog.RegisterArtifact(ctx, product.ID, "1.0.0", digest, "themis/app")
	if err != nil {
		t.Fatalf("RegisterArtifact() error = %v", err)
	}
	if artifact.ImageDigest != digest || artifact.VersionID == "" {
		t.Fatalf("registered artifact = %+v", artifact)
	}

	// Duplicate digest returns the existing artifact (digest globally unique).
	again, err := catalog.RegisterArtifact(ctx, product.ID, "2.0.0", digest, "themis/app")
	if err != nil {
		t.Fatalf("RegisterArtifact duplicate error = %v", err)
	}
	if again.ID != artifact.ID {
		t.Fatalf("duplicate digest produced a new artifact: %q vs %q", again.ID, artifact.ID)
	}
	var artifactCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM artifacts WHERE image_digest = $1`, digest).Scan(&artifactCount); err != nil {
		t.Fatal(err)
	}
	if artifactCount != 1 {
		t.Fatalf("artifacts for digest = %d, want 1", artifactCount)
	}

	// CreateVersion on a missing project → PROJECT_NOT_FOUND.
	if _, err := catalog.CreateVersion(ctx, uuid.NewString(), "9.9.9"); err != domain.ErrProjectNotFound {
		t.Fatalf("CreateVersion missing project err = %v, want ErrProjectNotFound", err)
	}

	// CreateVersion duplicate on a real project → VERSION_CONFLICT.
	defaultProjectID := defaultProjectIDForProduct(t, ctx, pool, product.ID)
	if _, err := catalog.CreateVersion(ctx, defaultProjectID, "3.0.0"); err != nil {
		t.Fatalf("CreateVersion() error = %v", err)
	}
	if _, err := catalog.CreateVersion(ctx, defaultProjectID, "3.0.0"); err != domain.ErrVersionConflict {
		t.Fatalf("CreateVersion duplicate err = %v, want ErrVersionConflict", err)
	}
}

func defaultProjectIDForProduct(t *testing.T, ctx context.Context, pool *pgxpool.Pool, productID string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `SELECT id FROM projects WHERE product_id = $1 AND is_default LIMIT 1`, productID).Scan(&id); err != nil {
		t.Fatalf("resolve default project: %v", err)
	}
	return id
}
