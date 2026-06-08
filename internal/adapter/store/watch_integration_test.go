//go:build integration

package store_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/adapter/notify"
	"github.com/themis-project/themis/internal/adapter/nvd"
	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/adapter/store"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/watch"
)

func TestWatchCycleIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15444)
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

	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2021-23337",
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "v", "baseSeverity": "HIGH"}}]},
					"configurations": [{"nodes": [{"cpeMatch": [{
						"vulnerable": true,
						"criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
						"versionEndExcluding": "4.17.21"
					}]}]}]
				}
			}]
		}`))
	}))
	t.Cleanup(nvdSrv.Close)

	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	t.Cleanup(osvSrv.Close)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:watch-integration"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	componentID := uuid.NewString()
	versionID := uuid.NewString()
	sbomID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, format, checksum_sha256, image_digest, trust_status, raw_document)
		VALUES ($1, $2, 'cyclonedx', 'abc', $3, 'verified', '{}')
	`, sbomID, imageID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (id, purl, ecosystem, name)
		VALUES ($1, 'pkg:npm/lodash', 'npm', 'lodash')
	`, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_document_id)
		VALUES ($1, $2, '4.17.20', $3)
	`, versionID, componentID, sbomID); err != nil {
		t.Fatal(err)
	}

	watchRepo := store.NewPostgresWatchRepository(pool)
	notifier := &integrationNotifier{}
	var lastSuccess time.Time
	svc := &watch.Service{
		NVD: nvd.NewClient(nvd.ClientConfig{
			BaseURL:     nvdSrv.URL,
			RateLimiter: nvd.NewTokenBucket(100, 100),
		}),
		OSV: osv.NewClient(osv.ClientConfig{
			BaseURL:     osvSrv.URL,
			RateLimiter: osv.NewTokenBucket(100, 100),
		}),
		Repo:   watchRepo,
		Notify: notifier,
		OnSuccess: func(ts time.Time) {
			lastSuccess = ts
		},
	}

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}

	var componentVulnCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = 'CVE-2021-23337'
	`).Scan(&componentVulnCount); err != nil {
		t.Fatal(err)
	}
	if componentVulnCount != 1 {
		t.Fatalf("component_vuln_count = %d, want 1", componentVulnCount)
	}

	var riskCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM risk_context`).Scan(&riskCount); err != nil {
		t.Fatal(err)
	}
	if riskCount != 1 {
		t.Fatalf("risk_count = %d, want 1", riskCount)
	}

	var watchFindingCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM cve_watch_findings WHERE cve_id = 'CVE-2021-23337'`).Scan(&watchFindingCount); err != nil {
		t.Fatal(err)
	}
	if watchFindingCount != 1 {
		t.Fatalf("watch_finding_count = %d, want 1", watchFindingCount)
	}

	if len(notifier.events) != 1 {
		t.Fatalf("notification events = %d, want 1", len(notifier.events))
	}
	if notifier.events[0].Type != domain.NotificationEventCVEWatchFinding {
		t.Fatalf("event type = %q", notifier.events[0].Type)
	}

	storedTS, err := watchRepo.GetLastSuccessTimestamp(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if storedTS.IsZero() || !lastSuccess.Equal(storedTS) {
		t.Fatalf("last success = %v stored = %v", lastSuccess, storedTS)
	}

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = 'CVE-2021-23337'
	`).Scan(&componentVulnCount); err != nil {
		t.Fatal(err)
	}
	if componentVulnCount != 1 {
		t.Fatalf("duplicate cycle created rows: %d", componentVulnCount)
	}
}

func TestWatchCycleIntegrationPostgresOSVFallback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	dsn := integrationDatabaseDSN(t, 15445)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	migrationsPath := filepath.Join("..", "..", "..", "migrations")
	if err := applyIntegrationMigrations(dsn, migrationsPath); err != nil {
		t.Fatal(err)
	}
	resetIntegrationDatabase(t, pool)

	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(nvdSrv.Close)

	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"results": [{
				"vulns": [{
					"id": "CVE-2021-23337",
					"severity": [{"type": "CVSS_V3", "score": "7.5"}],
					"affected": [{
						"package": {"ecosystem": "npm", "name": "lodash"},
						"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
					}]
				}]
			}]
		}`))
	}))
	t.Cleanup(osvSrv.Close)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:watch-osv-fallback"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	componentID := uuid.NewString()
	versionID := uuid.NewString()
	sbomID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, format, checksum_sha256, image_digest, trust_status, raw_document)
		VALUES ($1, $2, 'cyclonedx', 'def', $3, 'verified', '{}')
	`, sbomID, imageID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (id, purl, ecosystem, name)
		VALUES ($1, 'pkg:npm/lodash', 'npm', 'lodash')
	`, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_document_id)
		VALUES ($1, $2, '4.17.20', $3)
	`, versionID, componentID, sbomID); err != nil {
		t.Fatal(err)
	}

	svc := &watch.Service{
		NVD: nvd.NewClient(nvd.ClientConfig{BaseURL: nvdSrv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)}),
		OSV: osv.NewClient(osv.ClientConfig{BaseURL: osvSrv.URL, RateLimiter: osv.NewTokenBucket(100, 100)}),
		Repo: store.NewPostgresWatchRepository(pool),
	}
	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM cve_watch_findings`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("watch findings = %d", count)
	}
}

type integrationNotifier struct {
	events []domain.NotificationEvent
}

func (n *integrationNotifier) Dispatch(_ context.Context, event domain.NotificationEvent) error {
	n.events = append(n.events, event)
	return nil
}

func (integrationNotifier) FlushDigest(context.Context, string) error { return nil }

// Task 15.6: CVE watch cycle against mock NVD creates findings and dispatches email via mock SMTP.
func TestE2EWatchCycleWithSMTPIntegrationPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping embedded postgres test in short mode")
	}

	host, smtpPort, mailReceived := notify.StartIntegrationSMTPServer(t)

	dsn := integrationDatabaseDSN(t, 15446)
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

	nvdSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2021-23337",
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "v", "baseSeverity": "HIGH"}}]},
					"configurations": [{"nodes": [{"cpeMatch": [{
						"vulnerable": true,
						"criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
						"versionEndExcluding": "4.17.21"
					}]}]}]
				}
			}]
		}`))
	}))
	t.Cleanup(nvdSrv.Close)

	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	t.Cleanup(osvSrv.Close)

	productID := uuid.NewString()
	imageID := uuid.NewString()
	artifactID := uuid.NewString()
	digest := "sha256:watch-smtp-e2e"
	seedBaseData(t, ctx, pool, productID, artifactID, imageID, digest)

	componentID := uuid.NewString()
	versionID := uuid.NewString()
	sbomID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO sbom_documents (id, image_id, format, checksum_sha256, image_digest, trust_status, raw_document)
		VALUES ($1, $2, 'cyclonedx', 'abc', $3, 'verified', '{}')
	`, sbomID, imageID, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO components (id, purl, ecosystem, name)
		VALUES ($1, 'pkg:npm/lodash', 'npm', 'lodash')
	`, componentID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO component_versions (id, component_id, version, sbom_document_id)
		VALUES ($1, $2, '4.17.20', $3)
	`, versionID, componentID, sbomID); err != nil {
		t.Fatal(err)
	}

	notifySvc := notify.NewService(notify.ServiceConfig{
		Rules: &notifyStubRules{rules: []domain.NotificationRule{
			{
				Name:        "watch-email",
				EventType:   domain.NotificationEventCVEWatchFinding,
				Channel:     domain.NotificationChannelEmail,
				Destination: "ops@example.com",
				Enabled:     true,
			},
		}},
		SMTP: notify.SMTPSettings{
			Host:   host,
			Port:   smtpPort,
			From:   "alerts@themis.local",
			UseTLS: false,
		},
		MaxRetry:  1,
		BaseDelay: time.Millisecond,
	})

	watchRepo := store.NewPostgresWatchRepository(pool)
	svc := &watch.Service{
		NVD: nvd.NewClient(nvd.ClientConfig{
			BaseURL:     nvdSrv.URL,
			RateLimiter: nvd.NewTokenBucket(100, 100),
		}),
		OSV: osv.NewClient(osv.ClientConfig{
			BaseURL:     osvSrv.URL,
			RateLimiter: osv.NewTokenBucket(100, 100),
		}),
		Repo:   watchRepo,
		Notify: notifySvc,
	}

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}

	var componentVulnCount int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM component_vulnerabilities cv
		JOIN vulnerabilities v ON v.id = cv.vulnerability_id
		WHERE v.cve_id = 'CVE-2021-23337'
	`).Scan(&componentVulnCount); err != nil {
		t.Fatal(err)
	}
	if componentVulnCount != 1 {
		t.Fatalf("component_vuln_count = %d, want 1", componentVulnCount)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mailReceived() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("expected SMTP notification for CVE watch finding")
}

type notifyStubRules struct {
	rules []domain.NotificationRule
}

func (s *notifyStubRules) ListRules(context.Context) ([]domain.NotificationRule, error) {
	return s.rules, nil
}

func (s *notifyStubRules) ReplaceRules(context.Context, []domain.NotificationRule) error {
	return nil
}
