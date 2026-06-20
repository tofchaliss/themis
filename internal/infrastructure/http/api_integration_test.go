//go:build integration

package httpserver_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/infrastructure/config"
	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
	"github.com/themis-project/themis/internal/infrastructure/metrics"
	"github.com/themis-project/themis/internal/infrastructure/queue"
)

const integrationAPIKey = "integration-secret"

func TestAPIFlowIntegrationPostgres(t *testing.T) {
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

	client := &http.Client{Timeout: 10 * time.Second}
	authHeader := func(req *http.Request) {
		req.Header.Set("X-API-Key", integrationAPIKey)
	}

	productID := createProduct(t, client, server.URL, authHeader)
	projectID := defaultProjectID(t, ctx, pool, productID)

	digest := "sha256:api-integration"
	artifactID := registerArtifact(t, client, server.URL, authHeader, productID, digest)

	raw, err := os.ReadFile(filepath.Join("..", "..", "adapter", "parser", "testdata", "cyclonedx-1.6.json"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	uploadBody, _ := json.Marshal(map[string]any{
		"format":       "cyclonedx",
		"spec_version": "1.6",
		"document":     document,
		"artifact_id":  artifactID,
		"project_id":   projectID,
		"image_digest": digest,
		"ci_job_id":    "integration-job",
	})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/api/v1/sbom/upload", bytes.NewReader(uploadBody))
	authHeader(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", "api-integration-"+uuid.NewString())
	resp := mustDo(t, client, req)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("upload status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var accepted struct {
		IngestionID string `json:"ingestion_id"`
	}
	decodeJSON(t, resp, &accepted)
	waitForIngestion(t, client, server.URL, authHeader, accepted.IngestionID)
	verifyIngestionMetrics(t, client, server.URL)

	scans := listProjectScans(t, client, server.URL, authHeader, projectID)
	if len(scans) == 0 {
		t.Fatal("expected scans")
	}
	scanID := scans[0].ID

	vulns := listScanVulnerabilities(t, client, server.URL, authHeader, scanID)
	if len(vulns) == 0 {
		t.Fatal("expected vulnerabilities")
	}
	findingID := vulns[0].ID

	triageBody, _ := json.Marshal(map[string]string{
		"decision":      "false_positive",
		"justification": "integration test finding",
	})
	req, _ = http.NewRequest(http.MethodPost, server.URL+"/api/v1/vulnerabilities/"+findingID+"/triage", bytes.NewReader(triageBody))
	authHeader(req)
	req.Header.Set("Content-Type", "application/json")
	resp = mustDo(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("triage status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL+"/api/v1/vulnerabilities/"+findingID+"/triage/history", nil)
	authHeader(req)
	resp = mustDo(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("history status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var history struct {
		Items []struct {
			Decision string `json:"decision"`
		} `json:"items"`
	}
	decodeJSON(t, resp, &history)
	if len(history.Items) == 0 || history.Items[0].Decision != "false_positive" {
		t.Fatalf("history=%+v", history)
	}
}

func apiIntegrationDatabaseDSN(t *testing.T) string {
	t.Helper()
	if dsn := os.Getenv("THEMIS_TEST_DATABASE_DSN"); dsn != "" {
		return dsn
	}
	return startAPIIntegrationPostgres(t)
}

func createProduct(t *testing.T, client *http.Client, baseURL string, auth func(*http.Request)) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": "integration-app", "description": "api test"})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/products", bytes.NewReader(body))
	auth(req)
	req.Header.Set("Content-Type", "application/json")
	resp := mustDo(t, client, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create product status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var product struct {
		ID string `json:"id"`
	}
	decodeJSON(t, resp, &product)
	return product.ID
}

func waitForIngestion(t *testing.T, client *http.Client, baseURL string, auth func(*http.Request), ingestionID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/ingestions/"+ingestionID, nil)
		auth(req)
		resp := mustDo(t, client, req)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("ingestion status=%d body=%s", resp.StatusCode, readBody(t, resp))
		}
		var status struct {
			Status string `json:"status"`
		}
		decodeJSON(t, resp, &status)
		switch status.Status {
		case string(domain.IngestionStatusNotified), string(domain.IngestionStatusCompleted):
			return
		case string(domain.IngestionStatusFailed), string(domain.IngestionStatusRejected):
			t.Fatalf("ingestion failed: %+v", status)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out waiting for ingestion")
}

func listProjectScans(t *testing.T, client *http.Client, baseURL string, auth func(*http.Request), projectID string) []struct {
	ID string `json:"id"`
} {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/projects/"+projectID+"/scans", nil)
	auth(req)
	resp := mustDo(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list scans status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	decodeJSON(t, resp, &out)
	return out.Items
}

func listScanVulnerabilities(t *testing.T, client *http.Client, baseURL string, auth func(*http.Request), scanID string) []struct {
	ID string `json:"id"`
} {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/scans/"+scanID+"/vulnerabilities", nil)
	auth(req)
	resp := mustDo(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list vulnerabilities status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	decodeJSON(t, resp, &out)
	return out.Items
}

func insertIntegrationAPIKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(integrationAPIKey), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO api_keys (id, name, key_hash, scopes)
		VALUES ($1, 'integration', $2, $3)
		ON CONFLICT (key_hash) DO NOTHING
	`, uuid.NewString(), string(hash), []string{domain.ScopeAdmin})
	if err != nil {
		t.Fatalf("insert api key: %v", err)
	}
}

// registerArtifact registers an artifact by image digest via the v0.3.0 REST endpoint
// (POST /api/v1/products/{id}/artifacts) and returns its id. The endpoint auto-creates the
// product's default project + "latest" version, so the artifact's scans surface under the
// default project.
func registerArtifact(t *testing.T, client *http.Client, baseURL string, auth func(*http.Request), productID, digest string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"image_digest": digest,
		"repository":   "themis/integration",
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/products/"+productID+"/artifacts", bytes.NewReader(body))
	auth(req)
	req.Header.Set("Content-Type", "application/json")
	resp := mustDo(t, client, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register artifact status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var out struct {
		ID string `json:"id"`
	}
	decodeJSON(t, resp, &out)
	return out.ID
}

// defaultProjectID returns the auto-created default project for a product.
func defaultProjectID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, productID string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `SELECT id FROM projects WHERE product_id = $1 AND is_default LIMIT 1`, productID).Scan(&id); err != nil {
		t.Fatalf("resolve default project: %v", err)
	}
	return id
}

func seedVulnerabilityCatalog(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO vulnerabilities (cve_id, severity, description, affected_versions)
		VALUES
			('CVE-2021-23337', 'high', 'npm:lodash,4.17.21', ARRAY['4.17.21']),
			('CVE-2021-23338', 'high', 'npm:express,4.18.2', ARRAY['4.18.2'])
		ON CONFLICT (cve_id) DO NOTHING
	`)
	if err != nil {
		t.Fatalf("seed vulnerabilities: %v", err)
	}
}

func applyAPIIntegrationMigrations(dsn, migrationsPath string) error {
	m, err := migrate.New("file://"+migrationsPath, dsn)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
	}()
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

func verifyIngestionMetrics(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := mustDo(t, client, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", resp.StatusCode, readBody(t, resp))
	}
	body := readBody(t, resp)
	for _, name := range []string{
		"themis_ingestion_jobs_total",
		"themis_job_duration_seconds",
		"themis_queue_depth",
		"themis_notifications_total",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("metrics body missing %q", name)
		}
	}
	for _, sample := range []string{
		`themis_ingestion_jobs_total{job_type="ingest_sbom",status="success"} `,
		`themis_notifications_total{channel_type="ingestion",status="success"} `,
	} {
		if !strings.Contains(body, sample) {
			t.Fatalf("metrics body missing non-zero sample %q in:\n%s", sample, body)
		}
	}
}

func mustDo(t *testing.T, client *http.Client, req *http.Request) *http.Response {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func decodeJSON(t *testing.T, resp *http.Response, dst any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatal(err)
	}
}
