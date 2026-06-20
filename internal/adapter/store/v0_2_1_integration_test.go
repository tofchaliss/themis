//go:build integration

package store_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/epsskev"

	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/adapter/parser"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/adapter/trust"
	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

func TestV021AlpineSBOMOSVCorrelation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []map[string]any{{
				"vulns": []map[string]any{{
					"id":      "ALPINE-CVE-2024-0001",
					"aliases": []string{"CVE-2024-0001"},
					"severity": []map[string]string{{
						"type":  "CVSS_V3",
						"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					}},
					"affected": []map[string]any{{
						"package": map[string]string{"ecosystem": "Alpine", "name": "busybox"},
						"ranges": []map[string]any{{
							"events": []map[string]string{
								{"introduced": "0"},
								{"fixed": "1.36.1-r0"},
							},
						}},
					}},
				}},
			}},
		})
	}))
	t.Cleanup(osvSrv.Close)

	ctx := context.Background()
	dsn := integrationDatabaseDSN(t, 15480)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := applyIntegrationMigrations(dsn, filepath.Join("..", "..", "..", "migrations")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	resetIntegrationDatabase(t, pool)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:v021-alpine"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	osvClient := osv.NewClient(osv.ClientConfig{
		BaseURL:     osvSrv.URL,
		RateLimiter: osv.NewTokenBucket(100, 100),
	})
	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       store.NewPostgresIngestionRepository(pool),
		Trust:      trust.GateEvaluator{Gate: &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trust.NewPostgresRepository(pool), Audit: trust.NewPostgresAuditRecorder(pool)}},
		Parser:     parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:       store.NewPostgresSBOMStore(pool),
		Components: store.NewPostgresComponentStore(pool),
		Catalog:    store.NewPostgresVulnerabilityCatalog(pool),
		Fetcher: &osv.ComponentFetcher{
			Client: osvClient,
			Logger: osv.NoOpCorrelationLogger{},
		},
		Correlate:  store.NewPostgresCorrelationRepository(pool),
		Enrichment: &enrichment.Handler{Repo: store.NewPostgresEnrichmentRepository(pool), Audit: trust.NewPostgresAuditRecorder(pool)},
		Notify:     notify.IngestionNotifier{},
	})

	sbom := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		"components":[{"type":"library","name":"busybox","version":"1.35.0-r6",
			"purl":"pkg:apk/alpine/busybox@1.35.0-r6"}]
	}`)
	result, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind: domain.ArtifactKindSBOM, Format: domain.SBOMFormatCycloneDX, SpecVersion: "1.6",
			RawDocument: sbom, ImageDigest: digest, CIJobID: "v021", CIPipelineURL: "https://ci.example/v021",
			SupplierIdentity: "test", Actor: "test", ProductOwner: "test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	})
	if err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("status = %v", result.Status)
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = 'CVE-2024-0001'
	`).Scan(&count); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	if count == 0 {
		t.Fatal("expected non-zero alpine OSV findings")
	}
}

func TestV021RPMSBOMIngestSkipsUnsupportedOSV(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx := context.Background()
	dsn := integrationDatabaseDSN(t, 15481)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := applyIntegrationMigrations(dsn, filepath.Join("..", "..", "..", "migrations")); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	resetIntegrationDatabase(t, pool)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:v021-rpm"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	pipeline := ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       store.NewPostgresIngestionRepository(pool),
		Trust:      trust.GateEvaluator{Gate: &trust.Gate{Verifier: trust.StubVerifier{}, Repo: trust.NewPostgresRepository(pool), Audit: trust.NewPostgresAuditRecorder(pool)}},
		Parser:     parser.RegistryPort{Registry: parser.NewRegistry(parser.RegistryConfig{})},
		SBOM:       store.NewPostgresSBOMStore(pool),
		Components: store.NewPostgresComponentStore(pool),
		Catalog:    store.NewPostgresVulnerabilityCatalog(pool),
		Fetcher: &osv.ComponentFetcher{
			Logger: osv.NoOpCorrelationLogger{},
		},
		Correlate:  store.NewPostgresCorrelationRepository(pool),
		Enrichment: &enrichment.Handler{Repo: store.NewPostgresEnrichmentRepository(pool), Audit: trust.NewPostgresAuditRecorder(pool)},
		Notify:     notify.IngestionNotifier{},
	})

	sbom := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		"components":[{"type":"library","name":"openssl","version":"1.1.1k",
			"purl":"pkg:rpm/centos/openssl@1.1.1k"}]
	}`)
	result, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind: domain.ArtifactKindSBOM, Format: domain.SBOMFormatCycloneDX, SpecVersion: "1.6",
			RawDocument: sbom, ImageDigest: digest, CIJobID: "v021-rpm", CIPipelineURL: "https://ci.example/rpm",
			SupplierIdentity: "test", Actor: "test", ProductOwner: "test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	})
	if err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}
	if result.Status == domain.IngestionStatusFailed {
		t.Fatalf("rpm ingest should not fail: %+v", result)
	}
}

func TestV021AlpineEPSSAfterReEnrich(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	pool, ctx := setupEPSSKevIntegration(t, 15482)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:v021-alpine-epss"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	if _, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions, cvss_score)
		VALUES ('CVE-2024-0001', 'critical', 'alpine:busybox', ARRAY['1.35.0-r6'], 9.8)
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
			{CVEID: "CVE-2024-0001", Severity: "critical", CVSSScore: 9.8, Ecosystem: "apk", PackageName: "busybox", AffectedVersions: []string{"1.35.0-r6"}},
		}},
		Correlate:  store.NewPostgresCorrelationRepository(pool),
		Enrichment: enrichmentSvc,
		Notify:     notify.IngestionNotifier{},
	})

	sbom := []byte(`{
		"bomFormat":"CycloneDX","specVersion":"1.6","version":1,
		"components":[{"type":"library","name":"busybox","version":"1.35.0-r6",
			"purl":"pkg:apk/alpine/busybox@1.35.0-r6"}]
	}`)
	if _, err := pipeline.IngestSBOM(ctx, domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind: domain.ArtifactKindSBOM, Format: domain.SBOMFormatCycloneDX, SpecVersion: "1.6",
			RawDocument: sbom, ImageDigest: digest, CIJobID: "v021-epss", CIPipelineURL: "https://ci.example/epss",
			SupplierIdentity: "test", Actor: "test", ProductOwner: "test",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  artifactID,
	}); err != nil {
		t.Fatalf("IngestSBOM() error = %v", err)
	}

	threatStore := store.NewPostgresThreatSignalStore(pool)
	syncSvc := &epsskev.Service{
		Fetcher: stubThreatFetcher{
			epss: []domain.EPSSSignal{{CVEID: "CVE-2024-0001", Score: 0.42, FetchedAt: time.Now().UTC()}},
			kev:  []domain.KEVSignal{{CVEID: "CVE-2024-0001", Listed: true, FetchedAt: time.Now().UTC()}},
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

	var epssScore float64
	var kevListed bool
	err := pool.QueryRow(ctx, `
		SELECT rc.epss_score, rc.kev_listed
		FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		JOIN scan_reports sr ON sr.id = cv.scan_report_id
		JOIN risk_context rc ON rc.artifact_id = sr.artifact_id AND rc.component_purl = cv.component_purl AND rc.cve_id = cv.cve_id
		WHERE v.cve_id = 'CVE-2024-0001'
	`).Scan(&epssScore, &kevListed)
	if err != nil {
		t.Fatalf("query risk_context: %v", err)
	}
	if epssScore <= 0 {
		t.Fatalf("epss_score = %v, want > 0", epssScore)
	}
	if !kevListed {
		t.Fatal("expected kev_listed true after re-enrich")
	}
}

func TestV021ZipVendorVEXFeedLoadsAssertions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	pool, ctx := setupEPSSKevIntegration(t, 15483)
	vendorStore := vexfeed.NewPostgresAssertionStore(pool)

	var zipBody []byte
	{
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(zipBody)
		}))
		t.Cleanup(srv.Close)

		zipBody = buildTestOSVZip(t, `{"id":"ALPINE-CVE-2024-0001","aliases":["CVE-2024-0001"],"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"1.36.1-r0"}]}]}]}`)
		src := vexfeed.ZipOSVFeedSource{
			Name_:   "alpine",
			URL:     srv.URL,
			Fetcher: &vexfeed.HTTPFetcher{HTTPClient: srv.Client()},
		}
		assertions, err := src.Fetch(ctx)
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if len(assertions) == 0 {
			t.Fatal("expected zip feed assertions")
		}
		if assertions[0].CVEID != "CVE-2024-0001" {
			t.Fatalf("CVEID = %q, want CVE-2024-0001", assertions[0].CVEID)
		}
		n, err := vendorStore.UpsertAssertions(ctx, "alpine", assertions)
		if err != nil {
			t.Fatalf("UpsertAssertions() error = %v", err)
		}
		if n == 0 {
			t.Fatal("expected upserted assertions")
		}
	}

	var count int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM vex_assertions va
		JOIN vulnerabilities v ON v.id = va.vulnerability_id
		WHERE v.cve_id = 'CVE-2024-0001'
	`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected vendor assertions stored with canonical CVE ID")
	}
}

func buildTestOSVZip(t *testing.T, entryJSON string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("ALPINE-CVE-2024-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(entryJSON)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
