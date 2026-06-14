//go:build integration

package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
	"github.com/themis-project/themis/internal/infrastructure/metrics"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

type e2eEnv struct {
	t         *testing.T
	ctx       context.Context
	pool      *pgxpool.Pool
	serverURL string
	client    *http.Client
	auth      func(*http.Request)
	productID string
	projectID string
}

func newE2EEnv(t *testing.T) *e2eEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	dsn := apiIntegrationDatabaseDSN(t)
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyAPIIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	insertIntegrationAPIKey(t, ctx, pool)
	seedVulnerabilityCatalog(t, ctx, pool)

	workers, err := queue.NewInProcessQueue(queue.InProcessConfig{
		PoolSize:  2,
		MaxRetry:  3,
		BaseDelay: time.Millisecond,
		Store:     queue.NewPostgresJobStore(pool),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := workers.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = workers.Stop(stopCtx)
	})

	router := chi.NewRouter()
	router.Handle("/metrics", metrics.Handler())
	httpserver.MountAPI(ctx, router, httpserver.APIConfig{
		Pool: pool,
		AppConfig: config.Config{
			Upload:  config.UploadConfig{MaxSizeBytes: 10 * 1024 * 1024},
			Trust:   config.TrustConfig{DefaultPolicy: config.TrustPolicyStandard},
			Webhook: config.WebhookConfig{Secret: "integration-webhook"},
		},
		InProcessQueue: workers,
	})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	client := &http.Client{Timeout: 15 * time.Second}
	auth := func(req *http.Request) { req.Header.Set("X-API-Key", integrationAPIKey) }

	productID := createProduct(t, client, server.URL, auth)
	projectID := createProject(t, client, server.URL, auth, productID)

	return &e2eEnv{
		t:         t,
		ctx:       ctx,
		pool:      pool,
		serverURL: server.URL,
		client:    client,
		auth:      auth,
		productID: productID,
		projectID: projectID,
	}
}

func (e *e2eEnv) uploadSBOM(t *testing.T, digest, imageID, idempotencyKey string) (ingestionID string, statusCode int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "adapter", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"format":       "cyclonedx",
		"spec_version": "1.6",
		"document":     document,
		"image_id":     imageID,
		"project_id":   e.projectID,
		"image_digest": digest,
		"ci_job_id":    "e2e-job",
	})
	req, _ := http.NewRequest(http.MethodPost, e.serverURL+"/api/v1/sbom/upload", bytes.NewReader(body))
	e.auth(req)
	req.Header.Set("Content-Type", "application/json")
	if idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", idempotencyKey)
	}
	resp := mustDo(t, e.client, req)
	defer resp.Body.Close()
	var accepted struct {
		IngestionID string `json:"ingestion_id"`
	}
	decodeJSON(t, resp, &accepted)
	return accepted.IngestionID, resp.StatusCode
}

func (e *e2eEnv) uploadVEX(t *testing.T, sbomChecksum string, document []byte) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"format":            "openvex",
		"spec_version":      "1.0.0",
		"document":          json.RawMessage(document),
		"sbom_checksum":     sbomChecksum,
		"supplier_identity": "e2e-team",
	})
	req, _ := http.NewRequest(http.MethodPost, e.serverURL+"/api/v1/vex/upload", bytes.NewReader(body))
	e.auth(req)
	req.Header.Set("Content-Type", "application/json")
	resp := mustDo(t, e.client, req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("vex upload status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var accepted struct {
		IngestionID string `json:"ingestion_id"`
	}
	decodeJSON(t, resp, &accepted)
	waitForIngestion(t, e.client, e.serverURL, e.auth, accepted.IngestionID)
	return accepted.IngestionID
}

func (e *e2eEnv) scanVulnerabilities(t *testing.T, scanID string) []scanVuln {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, e.serverURL+"/api/v1/scans/"+scanID+"/vulnerabilities", nil)
	e.auth(req)
	resp := mustDo(t, e.client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list vulnerabilities status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out struct {
		Items []scanVuln `json:"items"`
	}
	decodeJSON(t, resp, &out)
	return out.Items
}

type scanVuln struct {
	ID             string  `json:"id"`
	CveID          string  `json:"cve_id"`
	Severity       string  `json:"severity"`
	EffectiveState *string `json:"effective_state"`
	ComponentPurl  *string `json:"component_purl"`
}

func (e *e2eEnv) sbomChecksum(t *testing.T, scanID string) string {
	t.Helper()
	var checksum string
	if err := e.pool.QueryRow(e.ctx, `SELECT checksum_sha256 FROM sbom_documents WHERE id = $1`, scanID).Scan(&checksum); err != nil {
		t.Fatal(err)
	}
	return checksum
}

func (e *e2eEnv) seedImage(t *testing.T, digest string) string {
	t.Helper()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	seedImage(t, e.ctx, e.pool, e.productID, artifactID, imageID, digest)
	return imageID
}

func effectiveState(v scanVuln) string {
	if v.EffectiveState == nil {
		return ""
	}
	return *v.EffectiveState
}

func vexDocument(cveID, purl, status, justification string) []byte {
	doc := map[string]any{
		"@context": "https://openvex.dev/ns",
		"statements": []map[string]any{{
			"vulnerability": map[string]string{"name": cveID},
			"products":      []map[string]string{{"@id": purl}},
			"status":        status,
			"justification": justification,
		}},
	}
	raw, _ := json.Marshal(doc)
	return raw
}

func vulnRefs(v scanVuln) (cveID, purl string) {
	purl = "pkg:npm/lodash@4.17.21"
	if v.ComponentPurl != nil && *v.ComponentPurl != "" {
		purl = *v.ComponentPurl
	}
	return v.CveID, purl
}

// Task 15.1: SBOM upload → COMPLETED → vulnerabilities with effective_state=detected.
func TestE2E_SBOMPipelineDetected(t *testing.T) {
	env := newE2EEnv(t)
	digest := "sha256:e2e-detected-" + uuid.NewString()
	imageID := env.seedImage(t, digest)

	ingestionID, status := env.uploadSBOM(t, digest, imageID, "e2e-detected-"+uuid.NewString())
	if status != http.StatusAccepted {
		t.Fatalf("upload status=%d", status)
	}
	waitForIngestion(t, env.client, env.serverURL, env.auth, ingestionID)

	scans := listProjectScans(t, env.client, env.serverURL, env.auth, env.projectID)
	if len(scans) == 0 {
		t.Fatal("expected scans")
	}
	vulns := env.scanVulnerabilities(t, scans[0].ID)
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}
	for _, v := range vulns {
		if effectiveState(v) != domain.EffectiveStateDetected {
			t.Fatalf("finding %s effective_state=%q want detected", v.ID, effectiveState(v))
		}
	}

	var riskCount int
	if err := env.pool.QueryRow(env.ctx, `SELECT COUNT(*) FROM risk_context WHERE effective_state = $1`, domain.EffectiveStateDetected).Scan(&riskCount); err != nil {
		t.Fatal(err)
	}
	if riskCount == 0 {
		t.Fatal("expected risk_context rows")
	}
}

// Task 15.2: VEX upload → effective_state suppressed; raw finding preserved.
func TestE2E_VEXSuppressionPreservesFinding(t *testing.T) {
	env := newE2EEnv(t)
	digest := "sha256:e2e-vex-" + uuid.NewString()
	imageID := env.seedImage(t, digest)

	ingestionID, _ := env.uploadSBOM(t, digest, imageID, "e2e-vex-"+uuid.NewString())
	waitForIngestion(t, env.client, env.serverURL, env.auth, ingestionID)
	scans := listProjectScans(t, env.client, env.serverURL, env.auth, env.projectID)
	scanID := scans[0].ID
	vulns := env.scanVulnerabilities(t, scanID)
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}
	findingID := vulns[0].ID
	var rawSeverity string
	if err := env.pool.QueryRow(env.ctx, `
		SELECT v.severity FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.id = $1
	`, findingID).Scan(&rawSeverity); err != nil {
		t.Fatal(err)
	}

	checksum := env.sbomChecksum(t, scanID)
	cveID, purl := vulnRefs(vulns[0])
	vexDoc := vexDocument(cveID, purl, "not_affected", "component_not_present")
	env.uploadVEX(t, checksum, vexDoc)

	after := env.scanVulnerabilities(t, scanID)
	if len(after) == 0 {
		t.Fatal("expected vulnerabilities after vex")
	}
	if effectiveState(after[0]) != domain.EffectiveStateSuppressed {
		t.Fatalf("effective_state=%q want suppressed", effectiveState(after[0]))
	}
	var stillThere string
	if err := env.pool.QueryRow(env.ctx, `
		SELECT v.severity FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE cv.id = $1
	`, findingID).Scan(&stillThere); err != nil {
		t.Fatal(err)
	}
	if stillThere != rawSeverity {
		t.Fatalf("raw finding changed: %q -> %q", rawSeverity, stillThere)
	}
}

// Task 15.3: L4 triage → themis_generated VEX → second SBOM auto-suppressed.
func TestE2E_TriageGeneratedVEXAutoApply(t *testing.T) {
	env := newE2EEnv(t)
	digest := "sha256:e2e-triage-" + uuid.NewString()
	imageID := env.seedImage(t, digest)

	ingestionID, _ := env.uploadSBOM(t, digest, imageID, "e2e-triage-"+uuid.NewString())
	waitForIngestion(t, env.client, env.serverURL, env.auth, ingestionID)
	scans := listProjectScans(t, env.client, env.serverURL, env.auth, env.projectID)
	vulns := env.scanVulnerabilities(t, scans[0].ID)
	findingID := vulns[0].ID

	triageBody, _ := json.Marshal(map[string]string{
		"decision":      "false_positive",
		"justification": "e2e triage justification",
	})
	req, _ := http.NewRequest(http.MethodPost, env.serverURL+"/api/v1/vulnerabilities/"+findingID+"/triage", bytes.NewReader(triageBody))
	env.auth(req)
	req.Header.Set("Content-Type", "application/json")
	resp := mustDo(t, env.client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("triage status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	resp.Body.Close()

	var vexCount int
	if err := env.pool.QueryRow(env.ctx, `SELECT COUNT(*) FROM vex_documents WHERE source = 'themis_generated'`).Scan(&vexCount); err != nil {
		t.Fatal(err)
	}
	if vexCount == 0 {
		t.Fatal("expected themis_generated vex document")
	}

	secondDigest := "sha256:e2e-triage-second-" + uuid.NewString()
	secondImage := env.seedImage(t, secondDigest)
	secondIngestion, _ := env.uploadSBOM(t, secondDigest, secondImage, "e2e-triage-second-"+uuid.NewString())
	waitForIngestion(t, env.client, env.serverURL, env.auth, secondIngestion)

	secondScans := listProjectScans(t, env.client, env.serverURL, env.auth, env.projectID)
	var secondScanID string
	for _, scan := range secondScans {
		if scan.ID != scans[0].ID {
			secondScanID = scan.ID
			break
		}
	}
	if secondScanID == "" {
		t.Fatal("expected second scan")
	}
	secondVulns := env.scanVulnerabilities(t, secondScanID)
	if len(secondVulns) == 0 {
		t.Fatal("expected second scan vulnerabilities")
	}
	triagedCVE := vulns[0].CveID
	var matchedSecond scanVuln
	for _, v := range secondVulns {
		if v.CveID == triagedCVE {
			matchedSecond = v
			break
		}
	}
	if matchedSecond.ID == "" {
		t.Fatalf("expected finding for triaged CVE %q on second scan", triagedCVE)
	}
	if effectiveState(matchedSecond) != domain.EffectiveStateSuppressed {
		t.Fatalf("second scan effective_state=%q want suppressed", effectiveState(matchedSecond))
	}
}

// Task 15.4: duplicate SBOM (same digest + checksum) returns same ingestion_id without new sbom row.
func TestE2E_DuplicateSBOMIdempotency(t *testing.T) {
	env := newE2EEnv(t)
	digest := "sha256:e2e-dup-" + uuid.NewString()
	imageID := env.seedImage(t, digest)
	idempotencyKey := "e2e-dup-" + uuid.NewString()

	firstID, firstStatus := env.uploadSBOM(t, digest, imageID, idempotencyKey)
	if firstStatus != http.StatusAccepted {
		t.Fatalf("first upload status=%d", firstStatus)
	}
	waitForIngestion(t, env.client, env.serverURL, env.auth, firstID)

	var sbomCount int
	if err := env.pool.QueryRow(env.ctx, `SELECT COUNT(*) FROM sbom_documents`).Scan(&sbomCount); err != nil {
		t.Fatal(err)
	}

	secondID, secondStatus := env.uploadSBOM(t, digest, imageID, idempotencyKey)
	if secondStatus != http.StatusOK {
		t.Fatalf("duplicate upload status=%d want 200", secondStatus)
	}
	if secondID != firstID {
		t.Fatalf("ingestion_id changed: %q -> %q", firstID, secondID)
	}

	var sbomCountAfter int
	if err := env.pool.QueryRow(env.ctx, `SELECT COUNT(*) FROM sbom_documents`).Scan(&sbomCountAfter); err != nil {
		t.Fatal(err)
	}
	if sbomCountAfter != sbomCount {
		t.Fatalf("sbom_documents count changed: %d -> %d", sbomCount, sbomCountAfter)
	}
}

// Task 15.5: VEX not_affected suppresses; revoking VEX resurfaces finding as detected.
func TestE2E_VEXRevokeResurface(t *testing.T) {
	env := newE2EEnv(t)
	digest := "sha256:e2e-revoke-" + uuid.NewString()
	imageID := env.seedImage(t, digest)

	ingestionID, _ := env.uploadSBOM(t, digest, imageID, "e2e-revoke-"+uuid.NewString())
	waitForIngestion(t, env.client, env.serverURL, env.auth, ingestionID)
	scans := listProjectScans(t, env.client, env.serverURL, env.auth, env.projectID)
	scanID := scans[0].ID
	vulns := env.scanVulnerabilities(t, scanID)
	findingID := vulns[0].ID
	checksum := env.sbomChecksum(t, scanID)

	cveID, purl := vulnRefs(vulns[0])
	suppressDoc := vexDocument(cveID, purl, "not_affected", "not present")
	env.uploadVEX(t, checksum, suppressDoc)
	afterSuppress := env.scanVulnerabilities(t, scanID)
	if effectiveState(afterSuppress[0]) != domain.EffectiveStateSuppressed {
		t.Fatalf("after suppress effective_state=%q", effectiveState(afterSuppress[0]))
	}

	revokeDoc := vexDocument(cveID, purl, "under_investigation", "")
	env.uploadVEX(t, checksum, revokeDoc)
	afterRevoke := env.scanVulnerabilities(t, scanID)
	if effectiveState(afterRevoke[0]) != domain.EffectiveStateDetected {
		t.Fatalf("after revoke effective_state=%q want detected", effectiveState(afterRevoke[0]))
	}

	var findingCount int
	if err := env.pool.QueryRow(env.ctx, `SELECT COUNT(*) FROM component_vulnerabilities WHERE id = $1`, findingID).Scan(&findingCount); err != nil {
		t.Fatal(err)
	}
	if findingCount != 1 {
		t.Fatalf("raw finding deleted: count=%d", findingCount)
	}
}
