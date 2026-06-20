//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/epsskev"
	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

type persistJobQueue struct {
	pool *pgxpool.Pool
}

func (p persistJobQueue) Enqueue(ctx context.Context, job domain.Job) (string, error) {
	id := job.ID
	if id == "" {
		id = uuid.NewString()
	}
	_, err := p.pool.Exec(ctx, `
		INSERT INTO ingestion_jobs (id, job_type, status, payload, attempts)
		VALUES ($1, $2, 'pending', $3, 0)
	`, id, string(job.Type), job.Payload)
	return id, err
}

func (persistJobQueue) Consume(context.Context) (<-chan domain.Job, error) {
	return nil, nil
}

func (persistJobQueue) Ack(context.Context, string) error {
	return nil
}

type stubThreatFetcher struct {
	epss []domain.EPSSSignal
	kev  []domain.KEVSignal
}

func (s stubThreatFetcher) FetchEPSS(context.Context) ([]domain.EPSSSignal, error) {
	return s.epss, nil
}

func (s stubThreatFetcher) FetchKEV(context.Context) ([]domain.KEVSignal, error) {
	return s.kev, nil
}

func setupEPSSKevIntegration(t *testing.T, port uint32) (*pgxpool.Pool, context.Context) {
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
	ensureIntegrationSchema(t, dsn, pool, migrationsPath)
	resetIntegrationDataPreservingSchema(t, pool)
	return pool, ctx
}

func ensureIntegrationSchema(t *testing.T, dsn string, pool *pgxpool.Pool, migrationsPath string) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'products'
		)
	`).Scan(&exists); err != nil {
		t.Fatalf("check schema: %v", err)
	}
	if exists {
		return
	}
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
}

func resetIntegrationDataPreservingSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	_, err := pool.Exec(ctx, `
		DO $$
		DECLARE r RECORD;
		BEGIN
			FOR r IN (
				SELECT tablename FROM pg_tables
				WHERE schemaname = 'public' AND tablename <> 'schema_migrations'
			) LOOP
				EXECUTE 'TRUNCATE TABLE ' || quote_ident(r.tablename) || ' RESTART IDENTITY CASCADE';
			END LOOP;
		END $$;
	`)
	if err != nil {
		t.Fatalf("truncate integration database: %v", err)
	}
}

// TestAC16_KEVRetroactiveScoreIncrease verifies AC-16: KEV sync retroactively raises
// risk_score and sets kev_listed without re-ingesting the SBOM.
func TestAC16_KEVRetroactiveScoreIncrease(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15452)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:ac16-kev-retroactive"
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions)
		VALUES ('CVE-2021-23337', 'low', 'npm:lodash,4.17.21', ARRAY['4.17.21'])
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
			{CVEID: "CVE-2021-23337", Severity: "low", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"4.17.21"}},
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
			CIJobID:          "ac16-job",
			CIPipelineURL:    "https://ci.example/ac16",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	}); err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	var (
		findingID    string
		cveID        string
		initialScore int
		kevListed    bool
		detectedAt   time.Time
	)
	err = pool.QueryRow(ctx, `
		SELECT cv.id::text, v.cve_id, rc.risk_score::int, rc.kev_listed, cv.detected_at
		FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE v.cve_id = 'CVE-2021-23337'
		LIMIT 1
	`).Scan(&findingID, &cveID, &initialScore, &kevListed, &detectedAt)
	if err != nil {
		t.Fatal(err)
	}
	if kevListed {
		t.Fatal("expected kev_listed false before sync")
	}
	var rcCountBefore int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context`).Scan(&rcCountBefore); err != nil {
		t.Fatal(err)
	}
	initialExpected := enrichment.ComputeRiskScoreV2(
		"low",
		domain.EffectiveStateDetected,
		nil,
		false,
		false,
		string(domain.DeterministicLevelInformational),
		domain.RiskScoreBlastRadiusMin,
	)
	if initialScore != initialExpected {
		t.Fatalf("initial score = %d, want %d", initialScore, initialExpected)
	}

	threatStore := store.NewPostgresThreatSignalStore(pool)
	syncSvc := &epsskev.Service{
		Fetcher: stubThreatFetcher{
			epss: []domain.EPSSSignal{{CVEID: cveID, Score: 0.1, FetchedAt: time.Now().UTC()}},
			kev:  []domain.KEVSignal{{CVEID: cveID, Listed: true, FetchedAt: time.Now().UTC()}},
		},
		Store: threatStore,
	}
	if _, err := syncSvc.RunSync(ctx); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}
	if err := enrichmentSvc.ReEnrichSignalsBatch(ctx, 0, 500, store.CombinedSignalReader{
		Threat:  threatStore,
		Exploit: store.NewPostgresExploitStore(pool),
	}); err != nil {
		t.Fatalf("ReEnrichSignalsBatch() error = %v", err)
	}

	var (
		updatedScore int
		updatedKEV   bool
		stillAt      time.Time
	)
	err = pool.QueryRow(ctx, `
		SELECT rc.risk_score::int, rc.kev_listed, cv.detected_at
		FROM component_vulnerabilities cv
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE cv.id = $1
	`, findingID).Scan(&updatedScore, &updatedKEV, &stillAt)
	if err != nil {
		t.Fatal(err)
	}
	expectedEPSS := 0.1
	expected := enrichment.ComputeRiskScoreV2(
		"low",
		domain.EffectiveStateDetected,
		&expectedEPSS,
		true,
		false,
		string(domain.DeterministicLevelHigh),
		domain.RiskScoreBlastRadiusMin,
	)
	if updatedScore != expected {
		t.Fatalf("updated score = %d, want %d", updatedScore, expected)
	}
	if updatedScore <= initialScore {
		t.Fatalf("score did not increase: before=%d after=%d", initialScore, updatedScore)
	}
	if !updatedKEV {
		t.Fatal("expected kev_listed true after sync")
	}
	if !stillAt.Equal(detectedAt) {
		t.Fatalf("raw finding detected_at changed: before=%v after=%v", detectedAt, stillAt)
	}

	var rcCountAfter int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context`).Scan(&rcCountAfter); err != nil {
		t.Fatal(err)
	}
	if rcCountAfter != rcCountBefore {
		t.Fatalf("risk_context row count changed: before=%d after=%d", rcCountBefore, rcCountAfter)
	}

	var rawCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM component_vulnerabilities WHERE id = $1`, findingID).Scan(&rawCount); err != nil {
		t.Fatal(err)
	}
	if rawCount != 1 {
		t.Fatalf("raw finding row count = %d", rawCount)
	}
}

// TestReEnrichJob_Idempotent verifies C14: identical ReEnrichJob runs leave risk_context unchanged.
func TestReEnrichJob_Idempotent(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15466)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:reenrich-idempotent"
	raw, err := os.ReadFile(filepath.Join("..", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions)
		VALUES ('CVE-2021-23337', 'low', 'npm:lodash,4.17.21', ARRAY['4.17.21'])
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
			{CVEID: "CVE-2021-23337", Severity: "low", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"4.17.21"}},
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
			CIJobID:          "idempotent-job",
			CIPipelineURL:    "https://ci.example/idempotent",
			SupplierIdentity: "team-a",
			Actor:            "integration-test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	}); err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	var findingID string
	if err := pool.QueryRow(ctx, `
		SELECT cv.id::text
		FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = 'CVE-2021-23337'
		LIMIT 1
	`).Scan(&findingID); err != nil {
		t.Fatal(err)
	}

	threatStore := store.NewPostgresThreatSignalStore(pool)
	syncSvc := &epsskev.Service{
		Fetcher: stubThreatFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-2021-23337", Score: 0.2, FetchedAt: time.Now().UTC()}},
			kev:  []domain.KEVSignal{{CVEID: "CVE-2021-23337", Listed: true, FetchedAt: time.Now().UTC()}},
		},
		Store: threatStore,
	}
	if _, err := syncSvc.RunSync(ctx); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}

	reader := store.CombinedSignalReader{
		Threat:  threatStore,
		Exploit: store.NewPostgresExploitStore(pool),
	}
	if err := enrichmentSvc.ReEnrichSignalsBatch(ctx, 0, 500, reader); err != nil {
		t.Fatalf("first ReEnrichSignalsBatch() error = %v", err)
	}

	type riskSnapshot struct {
		score       int
		kev         bool
		level       string
		blast       float64
		epssPresent bool
	}
	var before riskSnapshot
	if err := pool.QueryRow(ctx, `
		SELECT rc.risk_score::int, rc.kev_listed, COALESCE(rc.deterministic_level, ''),
		       COALESCE(rc.blast_radius_score, 1.0), rc.epss_score IS NOT NULL
		FROM risk_context rc
		JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id
		JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id
		WHERE cv.id = $1
	`, findingID).Scan(&before.score, &before.kev, &before.level, &before.blast, &before.epssPresent); err != nil {
		t.Fatal(err)
	}

	if err := enrichmentSvc.ReEnrichSignalsBatch(ctx, 0, 500, reader); err != nil {
		t.Fatalf("second ReEnrichSignalsBatch() error = %v", err)
	}

	var after riskSnapshot
	if err := pool.QueryRow(ctx, `
		SELECT rc.risk_score::int, rc.kev_listed, COALESCE(rc.deterministic_level, ''),
		       COALESCE(rc.blast_radius_score, 1.0), rc.epss_score IS NOT NULL
		FROM risk_context rc
		JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id
		JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id
		WHERE cv.id = $1
	`, findingID).Scan(&after.score, &after.kev, &after.level, &after.blast, &after.epssPresent); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("risk_context changed on second run: before=%+v after=%+v", before, after)
	}

	var rowCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context rc JOIN scan_reports sr ON sr.artifact_id = rc.artifact_id JOIN component_vulnerabilities cv ON cv.scan_report_id = sr.id AND cv.component_purl = rc.component_purl AND cv.cve_id = rc.cve_id WHERE cv.id = $1`, findingID).Scan(&rowCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 1 {
		t.Fatalf("risk_context row count = %d, want 1", rowCount)
	}
}

// TestReEnrichJob_BatchCap1200 verifies task 19.12: 1200 open findings enqueue 3 batches of ≤500.
func TestReEnrichJob_BatchCap1200(t *testing.T) {
	pool, ctx := setupEPSSKevIntegration(t, 15453)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, "sha256:batch-cap-1200")
	seedBulkOpenFindings(t, ctx, pool, artifactID, 1200)

	enrichmentRepo := store.NewPostgresEnrichmentRepository(pool)
	var openCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM risk_context WHERE effective_state IN ('detected', 'in_triage')
	`).Scan(&openCount); err != nil {
		t.Fatal(err)
	}
	if openCount != 1200 {
		t.Fatalf("open findings = %d, want 1200", openCount)
	}

	dispatcher := &ingestion.AsyncDispatcher{Queue: persistJobQueue{pool: pool}}
	syncSvc := &epsskev.Service{
		Fetcher: stubThreatFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-BULK-OPEN", Score: 0.2, FetchedAt: time.Now().UTC()}},
			kev:  nil,
		},
		Store:        store.NewPostgresThreatSignalStore(pool),
		ReEnrich:     dispatcher,
		OpenFindings: enrichmentRepo,
	}
	if _, err := syncSvc.RunSync(ctx); err != nil {
		t.Fatalf("RunSync() error = %v", err)
	}

	var jobCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM ingestion_jobs WHERE job_type = $1
	`, string(domain.JobTypeReEnrichSignals)).Scan(&jobCount); err != nil {
		t.Fatal(err)
	}
	if jobCount != 3 {
		t.Fatalf("reenrich job count = %d, want 3", jobCount)
	}

	rows, err := pool.Query(ctx, `
		SELECT payload
		FROM ingestion_jobs
		WHERE job_type = $1
		ORDER BY (payload->>'offset')::int
	`, string(domain.JobTypeReEnrichSignals))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type batch struct {
		offset int
		limit  int
	}
	var batches []batch
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatal(err)
		}
		var p struct {
			Offset int `json:"offset"`
			Limit  int `json:"limit"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		batches = append(batches, batch{offset: p.Offset, limit: p.Limit})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(batches) != 3 {
		t.Fatalf("batches = %+v", batches)
	}
	want := []batch{{0, 500}, {500, 500}, {1000, 500}}
	for i, got := range batches {
		if got != want[i] {
			t.Fatalf("batch[%d] = %+v, want %+v", i, got, want[i])
		}
	}
}

func seedBulkOpenFindings(t *testing.T, ctx context.Context, pool *pgxpool.Pool, artifactID string, count int) {
	t.Helper()
	sbomID, scanReportID := seedScan(t, ctx, pool, artifactID)
	vulnID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (id, cve_id, severity) VALUES ($1, 'CVE-BULK-OPEN', 'high')
		ON CONFLICT (cve_id) DO NOTHING
	`, vulnID); err != nil {
		t.Fatalf("insert vulnerability: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		WITH series AS (SELECT generate_series(1, $1) AS n)
		INSERT INTO components (id, purl, name, ecosystem)
		SELECT gen_random_uuid(), 'pkg:npm/bulk-' || n, 'bulk-' || n, 'npm' FROM series;
	`, count); err != nil {
		t.Fatalf("insert components: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_id)
		SELECT gen_random_uuid(), c.id, '1.0.0', $1
		FROM components c WHERE c.purl LIKE 'pkg:npm/bulk-%';
	`, sbomID); err != nil {
		t.Fatalf("insert component_versions: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_vulnerabilities (id, component_version_id, vulnerability_id, scan_report_id, component_purl, cve_id)
		SELECT gen_random_uuid(), cvn.id, $2, $1, c.purl || '@1.0.0', 'CVE-BULK-OPEN'
		FROM component_versions cvn JOIN components c ON c.id = cvn.component_id
		WHERE cvn.sbom_id = $3;
	`, scanReportID, vulnID, sbomID); err != nil {
		t.Fatalf("insert component_vulnerabilities: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO risk_context (artifact_id, component_purl, cve_id, effective_state, priority, risk_score, raw_severity)
		SELECT $1, c.purl || '@1.0.0', 'CVE-BULK-OPEN', 'detected', 'high', 70, 'high'
		FROM component_versions cvn JOIN components c ON c.id = cvn.component_id
		WHERE cvn.sbom_id = $2;
	`, artifactID, sbomID); err != nil {
		t.Fatalf("insert risk_context: %v", err)
	}
}
