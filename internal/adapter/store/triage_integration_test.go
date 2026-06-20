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
	"github.com/themis-project/themis/internal/usecase/triage"
)

func TestTriageFlowIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15451)
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
	digest := "sha256:triage-integration"
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
	if sbomResult.Status != domain.IngestionStatusNotified {
		t.Fatalf("sbom result = %+v", sbomResult)
	}

	var findingID, effectiveState, rawSeverity string
	err = pool.QueryRow(ctx, `
		SELECT cv.id::text, rc.effective_state, rc.raw_severity
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		LIMIT 1
	`).Scan(&findingID, &effectiveState, &rawSeverity)
	if err != nil {
		t.Fatal(err)
	}
	if effectiveState != domain.EffectiveStateDetected {
		t.Fatalf("initial state = %q", effectiveState)
	}

	triageRepo := store.NewPostgresTriageRepository(pool)
	triageHandler := &triage.Handler{
		Repo:  triageRepo,
		VEX:   store.NewPostgresTriageVEXGenerator(pool),
		Audit: audit,
	}
	decision, err := triageHandler.Submit(ctx, domain.TriageDecision{
		FindingID:     findingID,
		Decision:      domain.TriageDecisionFalsePositive,
		Justification: "not reachable in prod",
		Actor:         "analyst-1",
	})
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	if decision.EffectiveState != domain.EffectiveStateFalsePositive {
		t.Fatalf("triage state = %q", decision.EffectiveState)
	}

	var vexSource string
	err = pool.QueryRow(ctx, `
		SELECT source FROM vex_documents WHERE source = 'themis_generated' LIMIT 1
	`).Scan(&vexSource)
	if err != nil {
		t.Fatalf("themis_generated vex: %v", err)
	}

	var historyCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM triage_history th JOIN component_vulnerabilities cv ON cv.id = $1 JOIN scan_reports sr ON sr.id = cv.scan_report_id WHERE th.artifact_id = sr.artifact_id AND th.component_purl = cv.component_purl AND th.cve_id = cv.cve_id
	`, findingID).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 1 {
		t.Fatalf("history count = %d", historyCount)
	}

	secondDigest := "sha256:triage-integration-2"
	secondArtifact := uuid.NewString()
	secondImage := uuid.NewString()
	seedImageForProduct(t, ctx, pool, productID, secondArtifact, secondImage, secondDigest)

	_, err = pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindSBOM,
			Format:           domain.SBOMFormatCycloneDX,
			SpecVersion:      "1.6",
			RawDocument:      raw,
			ImageDigest:      secondDigest,
			CIJobID:          "job-2",
			CIPipelineURL:    "https://ci.example/run/2",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  secondArtifact,
	})
	if err != nil {
		t.Fatalf("second IngestSBOM() error = %v", err)
	}

	var secondState string
	err = pool.QueryRow(ctx, `
		SELECT rc.effective_state
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE sr.image_digest = $1
		LIMIT 1
	`, secondDigest).Scan(&secondState)
	if err != nil {
		t.Fatal(err)
	}
	if secondState != domain.EffectiveStateSuppressed {
		t.Fatalf("second sbom state = %q, want suppressed", secondState)
	}

	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM triage_history th JOIN component_vulnerabilities cv ON cv.id = $1 JOIN scan_reports sr ON sr.id = cv.scan_report_id WHERE th.artifact_id = sr.artifact_id AND th.component_purl = cv.component_purl AND th.cve_id = cv.cve_id
	`, findingID).Scan(&historyCount); err != nil {
		t.Fatal(err)
	}
	if historyCount != 1 {
		t.Fatalf("history mutated, count = %d", historyCount)
	}
	if rawSeverity == "" {
		t.Fatal("expected raw severity preserved on first finding")
	}

	until := time.Now().Add(-time.Minute)
	if _, err := triageHandler.Submit(ctx, domain.TriageDecision{
		FindingID: findingID, Decision: domain.TriageDecisionAcceptedRisk,
		Justification: "temporary", AcceptedUntil: &until, Actor: "analyst-2",
	}); err != nil {
		t.Fatalf("accepted_risk submit: %v", err)
	}
	if err := triageHandler.ProcessExpiredAcceptedRisk(ctx, time.Now()); err != nil {
		t.Fatalf("ProcessExpiredAcceptedRisk: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT rc.effective_state FROM risk_context rc JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id WHERE cv.id = $1
	`, findingID).Scan(&effectiveState); err != nil {
		t.Fatal(err)
	}
	if effectiveState != domain.EffectiveStateDetected {
		t.Fatalf("expired state = %q", effectiveState)
	}
}
