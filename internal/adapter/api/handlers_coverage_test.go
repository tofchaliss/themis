package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/adapter/api"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/domain"
)

const (
	testProductID   = "11111111-1111-4111-8111-111111111111"
	testProjectID   = "22222222-2222-4222-8222-222222222222"
	testScanID      = "33333333-3333-4333-8333-333333333333"
	testFindingID   = "44444444-4444-4444-8444-444444444444"
	testIngestionID = "55555555-5555-4555-8555-555555555555"
)

func TestCatalogEndpointsSuccess(t *testing.T) {
	now := time.Now()
	catalog := &richCatalog{
		products: []domain.Product{{ID: testProductID, Name: "themis", Description: "desc", CreatedAt: now}},
		projects: []domain.Project{{ID: testProjectID, ProductID: testProductID, Name: "core", CreatedAt: now}},
		versions: []domain.ProductVersion{{ID: "v1", ProjectID: testProjectID, Version: "1.0.0", ReleaseStatus: "released", CreatedAt: now}},
	}
	scans := &richScans{
		projectProductID: testProductID,
		summaries: []domain.ScanSummary{{
			ID: testScanID, ProjectID: testProjectID, ProductID: testProductID,
			ImageDigest: "sha256:abc", Format: "cyclonedx", TrustStatus: "unsigned", IngestedAt: now,
		}},
		detail: domain.ScanDetail{
			ScanSummary: domain.ScanSummary{
				ID: testScanID, ProjectID: testProjectID, ProductID: testProductID,
				ImageDigest: "sha256:abc", Format: "cyclonedx", TrustStatus: "unsigned", IngestedAt: now, IngestionID: testIngestionID,
			},
			VulnerabilityCounts: map[string]int{"critical": 1},
		},
		vulnerabilities: []domain.ScanVulnerability{{
			ID: testFindingID, CVEID: "CVE-2024-0001", Severity: "high", EffectiveState: "detected", ComponentPURL: "pkg:npm/foo@1.0.0",
		}},
	}
	handler := fullHandler(t, catalog, scans)
	r := mountTestAPI(handler, adminKeyRepo(t))

	tests := []struct {
		method, path string
		body         string
		want         int
	}{
		{http.MethodPost, "/api/v1/products", `{"name":"new","description":"d"}`, http.StatusCreated},
		{http.MethodGet, "/api/v1/products?cursor=abc&limit=10", "", http.StatusOK},
		{http.MethodGet, "/api/v1/products/" + testProductID + "/projects", "", http.StatusOK},
		{http.MethodPost, "/api/v1/products/" + testProductID + "/projects", `{"name":"svc"}`, http.StatusCreated},
		{http.MethodGet, "/api/v1/products/" + testProductID + "/versions?limit=5", "", http.StatusOK},
		{http.MethodGet, "/api/v1/projects/" + testProjectID + "/scans", "", http.StatusOK},
		{http.MethodGet, "/api/v1/scans/" + testScanID, "", http.StatusOK},
		{http.MethodGet, "/api/v1/scans/" + testScanID + "/vulnerabilities?severity=high&effective_state=detected&cve_id=CVE-2024-0001", "", http.StatusOK},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestCatalogEndpointsErrors(t *testing.T) {
	catalog := &richCatalog{listProductsErr: errBoom, listProjectsErr: errBoom, createProjectErr: errBoom, listVersionsErr: errBoom}
	scans := &richScans{projectProductErr: errBoom, listScansErr: errBoom, getScanErr: errBoom, listVulnErr: errBoom}
	handler := fullHandler(t, catalog, scans)
	r := mountTestAPI(handler, adminKeyRepo(t))

	tests := []struct {
		method, path string
		body         string
		want         int
	}{
		{http.MethodPost, "/api/v1/products", `{`, http.StatusUnprocessableEntity},
		{http.MethodGet, "/api/v1/products", "", http.StatusUnprocessableEntity},
		{http.MethodGet, "/api/v1/products/" + testProductID + "/projects", "", http.StatusNotFound},
		{http.MethodPost, "/api/v1/products/" + testProductID + "/projects", `{`, http.StatusUnprocessableEntity},
		{http.MethodGet, "/api/v1/products/" + testProductID + "/versions", "", http.StatusNotFound},
		{http.MethodGet, "/api/v1/projects/" + testProjectID + "/scans", "", http.StatusNotFound},
		{http.MethodGet, "/api/v1/scans/" + testScanID, "", http.StatusNotFound},
		{http.MethodGet, "/api/v1/scans/" + testScanID + "/vulnerabilities", "", http.StatusNotFound},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		assertProblem(t, rec, tc.want)
	}
}

func TestProductScopeFilteringAndForbidden(t *testing.T) {
	catalog := &richCatalog{
		products: []domain.Product{
			{ID: testProductID, Name: "themis"},
			{ID: "99999999-9999-4999-8999-999999999999", Name: "other"},
		},
	}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog})
	r := mountTestAPI(handler, productKeyRepo(t, testProductID))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list products status=%d", rec.Code)
	}
	var resp struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("items = %+v", resp.Items)
	}

	other := "99999999-9999-4999-8999-999999999999"
	req = httptest.NewRequest(http.MethodGet, "/api/v1/products/"+other+"/projects", nil)
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rec.Code)
	}
}

func TestConfigAndCatalogListEndpoints(t *testing.T) {
	now := time.Now()
	handler := api.NewHandler(api.Dependencies{
		Catalog:       &richCatalog{},
		Scans:         &richScans{},
		Components:    &richComponents{items: []domain.CatalogComponent{{PURL: "pkg:npm/a@1", Name: "a", Ecosystem: "npm", Version: "1", ProductID: testProductID}}},
		Watch:         &richWatch{findings: []domain.CVEWatchFinding{{ID: "f1", CVEID: "CVE-1", ProductID: testProductID, ProjectID: testProjectID, Status: "open", DetectedAt: now}}},
		Notifications: &richNotifications{rules: []domain.NotificationRule{{Name: "n", EventType: "ingestion", Channel: "email", Destination: "a@b.c", Enabled: true}}},
		Scanners:      &richScanners{settings: domain.ScannerSettings{EnabledFormats: []string{"cyclonedx"}, MaxComponents: 100, ParseTimeoutSeconds: 30}},
		Jobs:          &fakeJobs{},
		Dispatcher:    &fakeDispatcher{},
	})
	r := mountTestAPI(handler, adminKeyRepo(t))

	body, _ := json.Marshal(map[string]any{
		"rules": []map[string]any{{"name": "n", "event_type": "ingestion", "channel": "email", "destination": "a@b.c", "enabled": true}},
	})
	for _, tc := range []struct {
		method, path string
		payload      []byte
		want         int
	}{
		{http.MethodGet, "/api/v1/components?purl=pkg:npm/a@1&product_id=" + testProductID, nil, http.StatusOK},
		{http.MethodGet, "/api/v1/cve-watch/findings?product_id=" + testProductID + "&severity=high", nil, http.StatusOK},
		{http.MethodPut, "/api/v1/config/notifications", body, http.StatusOK},
		{http.MethodPut, "/api/v1/config/scanners", []byte(`{"max_components":500}`), http.StatusOK},
	} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.payload))
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestConfigEndpointsErrors(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{
		Notifications: &richNotifications{listErr: errBoom, replaceErr: errBoom},
		Scanners:      &richScanners{getErr: errBoom, saveErr: errBoom},
		Components:    &richComponents{listErr: errBoom},
		Watch:         &richWatch{listErr: errBoom},
	})
	r := mountTestAPI(handler, adminKeyRepo(t))

	tests := []struct {
		method, path, body string
		want               int
	}{
		{http.MethodGet, "/api/v1/config/notifications", "", http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/v1/config/notifications", `{`, http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/v1/config/notifications", `{"rules":[]}`, http.StatusUnprocessableEntity},
		{http.MethodGet, "/api/v1/config/scanners", "", http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/v1/config/scanners", `{`, http.StatusUnprocessableEntity},
		{http.MethodPut, "/api/v1/config/scanners", `{}`, http.StatusUnprocessableEntity},
		{http.MethodGet, "/api/v1/components", "", http.StatusUnprocessableEntity},
		{http.MethodGet, "/api/v1/cve-watch/findings", "", http.StatusUnprocessableEntity},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s status=%d", tc.method, tc.path, rec.Code)
		}
	}
}

func TestTriageSuccessAndHistory(t *testing.T) {
	repo := &richTriageRepo{productID: testProductID}
	handler := api.NewHandler(api.Dependencies{
		Triage: &stubTriageService{
			submit: func(_ context.Context, _ domain.TriageDecision) (domain.TriageDecision, error) {
				return domain.TriageDecision{EffectiveState: domain.EffectiveStateSuppressed}, nil
			},
			history: func(_ context.Context, _ string, _ domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
				return repo.history, domain.PageResult{}, nil
			},
		},
		TriageRepo: repo,
	})
	r := mountTestAPI(handler, productKeyRepo(t, testProductID))

	body := `{"decision":"false_positive","justification":"not reachable"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/"+testFindingID+"/triage", strings.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("triage status=%d body=%s", rec.Code, rec.Body.String())
	}

	repo.history = []domain.TriageHistoryEntry{{Decision: "false_positive", Justification: "not reachable", Actor: "k1", RecordedAt: time.Now()}}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/"+testFindingID+"/triage/history?cursor=c&limit=5", nil)
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("history status=%d", rec.Code)
	}
}

func TestTriageForbidden(t *testing.T) {
	repo := &richTriageRepo{productID: testProductID}
	handler := api.NewHandler(api.Dependencies{Triage: &stubTriageService{}, TriageRepo: repo})
	r := mountTestAPI(handler, productKeyRepo(t, "99999999-9999-4999-8999-999999999999"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/"+testFindingID+"/triage", strings.NewReader(`{"decision":"confirmed","justification":"ok"}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("forbidden status=%d", rec.Code)
	}
}

func TestTriageFindingNotFound(t *testing.T) {
	repo := &richTriageRepo{scopeErr: errNotFound}
	handler := api.NewHandler(api.Dependencies{Triage: &stubTriageService{}, TriageRepo: repo})
	r := mountTestAPI(handler, adminKeyRepo(t))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/"+testFindingID+"/triage", strings.NewReader(`{"decision":"confirmed","justification":"ok"}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestTriageHistoryNotFound(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{
		Triage: &stubTriageService{history: func(context.Context, string, domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
			return nil, domain.PageResult{}, errNotFound
		}},
		TriageRepo: &richTriageRepo{},
	})
	r := mountTestAPI(handler, adminKeyRepo(t))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/"+testFindingID+"/triage/history", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("history status=%d", rec.Code)
	}
}

func TestIngestionUploadPaths(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	jobs := &fakeJobs{}
	handler := api.NewHandler(api.Dependencies{Jobs: jobs, Dispatcher: dispatcher, MaxUpload: 1024 * 1024, TrustPolicy: domain.TrustPolicyStrict})
	r := mountTestAPI(handler, adminKeyRepo(t))

	// JSON upload with optional fields
	body := `{"format":"cyclonedx","document":{"k":"v"},"artifact_id":"` + testProductID + `","project_id":"` + testProjectID + `","ci_job_id":"42","ci_pipeline_url":"https://ci","supplier_identity":"vendor"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("json upload status=%d", rec.Code)
	}

	// Multipart success
	var mp bytes.Buffer
	writer := multipartWriter(t, &mp, []byte(`{"components":[]}`))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", &mp)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("multipart upload status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Missing format
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader(`{"document":{}}`))
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing format status=%d", rec.Code)
	}

	// Get ingestion with scan id
	jobs.getErr = false
	jobs.scanID = testScanID
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ingestions/"+testIngestionID, nil)
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get ingestion status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUploadSBOMValidationErrors(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}, MaxUpload: 4096})
	r := mountTestAPI(handler, adminKeyRepo(t))

	var mp bytes.Buffer
	writer := multipart.NewWriter(&mp)
	_ = writer.WriteField("format", "cyclonedx")
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", &mp)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing document status=%d", rec.Code)
	}

	handler = api.NewHandler(api.Dependencies{Dispatcher: nil})
	r = mountTestAPI(handler, adminKeyRepo(t))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader(`{"format":"cyclonedx","document":{}}`))
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no dispatcher status=%d", rec.Code)
	}

	handler = api.NewHandler(api.Dependencies{Dispatcher: &failDispatcher{}})
	r = mountTestAPI(handler, adminKeyRepo(t))
	req = httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader(`{"format":"cyclonedx","document":{}}`))
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("dispatcher error status=%d", rec.Code)
	}
}

func TestUploadVEX(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	handler := api.NewHandler(api.Dependencies{Jobs: &fakeJobs{}, Dispatcher: dispatcher, TrustPolicy: domain.TrustPolicyStandard})
	r := mountTestAPI(handler, adminKeyRepo(t))

	body := `{"format":"openvex","document":{"statements":[]},"sbom_checksum":"sha256:deadbeef","spec_version":"0.1","supplier_identity":"vendor"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex/upload", strings.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("Idempotency-Key", "vex-1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("vex upload status=%d body=%s", rec.Code, rec.Body.String())
	}
	if dispatcher.lastInput.Kind != domain.ArtifactKindVEX {
		t.Fatalf("kind = %s", dispatcher.lastInput.Kind)
	}

	for _, payload := range []string{`{`, `{}`, `{"format":"openvex","document":{}}`} {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/vex/upload", strings.NewReader(payload))
		req.Header.Set("X-API-Key", "secret")
		rec = httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("payload %q status=%d", payload, rec.Code)
		}
	}
}

func TestWebhookValidationErrors(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}})
	r := mountTestAPI(handler, adminKeyRepo(t))

	body := []byte(`{"format":"cyclonedx","document":{},"image_digest":""}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/scan", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", api.SignHMAC("topsecret", body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("webhook validation status=%d", rec.Code)
	}
}

func TestScanAuthorizationPaths(t *testing.T) {
	scans := &richScans{
		projectProductID: testProductID,
		detail:           domain.ScanDetail{ScanSummary: domain.ScanSummary{ID: testScanID, ProductID: testProductID}},
	}
	handler := api.NewHandler(api.Dependencies{Scans: scans})
	r := mountTestAPI(handler, productKeyRepo(t, "99999999-9999-4999-8999-999999999999"))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+testScanID, nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scan forbidden status=%d", rec.Code)
	}

	scans.getScanErr = errNotFound
	r = mountTestAPI(handler, adminKeyRepo(t))
	req = httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+testScanID, nil)
	req.Header.Set("X-API-Key", "secret")
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("scan not found status=%d", rec.Code)
	}
}

func TestListProjectsUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Catalog: &richCatalog{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/projects", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestProblemTypes(t *testing.T) {
	cases := []struct {
		status int
		title  string
	}{
		{http.StatusUnauthorized, "Unauthorized"},
		{http.StatusForbidden, "Forbidden"},
		{http.StatusNotFound, "Not Found"},
		{http.StatusRequestEntityTooLarge, "Payload Too Large"},
		{http.StatusUnprocessableEntity, "Unprocessable Entity"},
		{http.StatusMethodNotAllowed, "Method Not Allowed"},
		{http.StatusTeapot, "Error"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
		api.WriteProblem(rec, req, tc.status, tc.title, "detail")
		assertProblem(t, rec, tc.status)
	}
}

func TestWithAuthRoundTrip(t *testing.T) {
	ctx := api.WithAuth(context.Background(), domain.AuthPrincipal{KeyID: "k1", Scopes: []string{domain.ScopeAdmin}})
	principal, ok := api.AuthFromContext(ctx)
	if !ok || principal.KeyID != "k1" {
		t.Fatal("auth context lost")
	}
	if !api.AuthorizeWriteConfig(principal) {
		t.Fatal("admin should write config")
	}
	readOnly := domain.AuthPrincipal{Scopes: []string{domain.ScopeReadOnly}}
	if api.AuthorizeWriteConfig(readOnly) {
		t.Fatal("read-only should not write config")
	}
}

func TestPaginationCursorInResponse(t *testing.T) {
	catalog := &richCatalog{
		products: []domain.Product{{ID: testProductID, Name: "themis"}},
		page:     domain.PageResult{NextCursor: "next-page"},
	}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var resp struct {
		NextCursor *string `json:"next_cursor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.NextCursor == nil || *resp.NextCursor != "next-page" {
		t.Fatalf("cursor = %+v", resp.NextCursor)
	}
}

func fullHandler(t *testing.T, catalog *richCatalog, scans *richScans) *api.Handler {
	t.Helper()
	return api.NewHandler(api.Dependencies{
		Catalog:    catalog,
		Scans:      scans,
		Jobs:       &fakeJobs{},
		Dispatcher: &fakeDispatcher{},
		MaxUpload:  1024 * 1024,
	})
}

func TestCreateProductError(t *testing.T) {
	catalog := &richCatalog{createProductErr: errBoom}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestListProjectScansError(t *testing.T) {
	scans := &richScans{projectProductID: testProductID, listScansErr: errBoom}
	handler := api.NewHandler(api.Dependencies{Scans: scans})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+testProjectID+"/scans", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestUploadSBOMMultipartInvalidDocumentJSON(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}, MaxUpload: 4096})
	r := mountTestAPI(handler, adminKeyRepo(t))
	var mp bytes.Buffer
	writer := multipartWriter(t, &mp, []byte(`not-json`))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", &mp)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestUploadSBOMInvalidJSONBody(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader(`{`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookInvalidJSON(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	body := []byte(`{`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/scan", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", api.SignHMAC("topsecret", body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestGetIngestionUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Jobs: &fakeJobs{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingestions/"+testIngestionID, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestCreateProjectNotFound(t *testing.T) {
	catalog := &richCatalog{createProjectErr: errNotFound}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products/"+testProductID+"/projects", strings.NewReader(`{"name":"svc"}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestListEndpointsUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{
		Catalog:       &richCatalog{},
		Scans:         &richScans{},
		Components:    &richComponents{},
		Watch:         &richWatch{},
		Notifications: &richNotifications{},
		Scanners:      &richScanners{},
	})
	r := mountTestAPI(handler, emptyKeyRepo())
	paths := []string{
		"/api/v1/products",
		"/api/v1/components",
		"/api/v1/cve-watch/findings",
		"/api/v1/config/notifications",
		"/api/v1/config/scanners",
		"/api/v1/projects/" + testProjectID + "/scans",
	}
	for _, path := range paths {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d", path, rec.Code)
		}
	}
}

func TestVerifyHMACInvalid(t *testing.T) {
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", "deadbeef")
	if api.VerifyHMACSignature("secret", req) {
		t.Fatal("expected invalid signature")
	}
}

func TestPaginatedListResponses(t *testing.T) {
	next := "page-2"
	catalog := &richCatalog{
		projects: []domain.Project{{ID: testProjectID, ProductID: testProductID, Name: "core"}},
		page:     domain.PageResult{NextCursor: next},
	}
	scans := &richScans{
		projectProductID: testProductID,
		summaries:        []domain.ScanSummary{{ID: testScanID, ProjectID: testProjectID, ProductID: testProductID}},
		page:             domain.PageResult{NextCursor: next},
		vulnerabilities:  []domain.ScanVulnerability{{ID: testFindingID, CVEID: "CVE-1", Severity: "low"}},
	}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog, Scans: scans})
	r := mountTestAPI(handler, adminKeyRepo(t))

	for _, path := range []string{
		"/api/v1/products/" + testProductID + "/projects",
		"/api/v1/projects/" + testProjectID + "/scans",
		"/api/v1/scans/" + testScanID + "/vulnerabilities",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if resp["next_cursor"] != next {
			t.Fatalf("%s cursor=%v", path, resp["next_cursor"])
		}
	}
}

func TestSubmitTriageInvalidJSON(t *testing.T) {
	repo := &richTriageRepo{productID: testProductID}
	handler := api.NewHandler(api.Dependencies{Triage: &stubTriageService{}, TriageRepo: repo})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/"+testFindingID+"/triage", strings.NewReader(`{`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestUploadVEXUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vex/upload", strings.NewReader(`{"format":"openvex","document":{},"sbom_checksum":"x"}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookWithOptionalFields(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	handler := api.NewHandler(api.Dependencies{Dispatcher: dispatcher})
	body := []byte(`{"format":"cyclonedx","document":{},"image_digest":"sha256:abc","image_id":"` + testProductID + `","project_id":"` + testProjectID + `","ci_job_id":"job-1","ci_pipeline_url":"https://ci.example/run/1"}`)
	r := chi.NewRouter()
	api.Mount(r, api.MountConfig{
		Handler:       handler,
		APIKeyAuth:    apimiddleware.APIKeyAuth{Keys: adminKeyRepo(t)},
		WebhookAuth:   apimiddleware.WebhookAuth{Secret: "topsecret"},
		MaxUploadSize: 1024,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/scan", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", api.SignHMAC("topsecret", body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if dispatcher.lastInput.CIJobID != "job-1" {
		t.Fatalf("input=%+v", dispatcher.lastInput)
	}
}

func TestUploadSBOMMultipartParseError(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}, MaxUpload: 4096})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader("not-a-valid-multipart-body"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=----boundary")
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestUploadSBOMJSONPayloadTooLarge(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}, MaxUpload: 64})
	r := mountTestAPIWithLimit(handler, adminKeyRepo(t), 64)
	payload := strings.Repeat("x", 128)
	body := `{"format":"cyclonedx","document":{"data":"` + payload + `"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", strings.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestProductVersionsPagination(t *testing.T) {
	catalog := &richCatalog{
		versions: []domain.ProductVersion{{ID: "v1", ProjectID: testProjectID, Version: "1.0.0"}},
		page:     domain.PageResult{NextCursor: "v-next"},
	}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/versions", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["next_cursor"] != "v-next" {
		t.Fatalf("cursor=%v", resp["next_cursor"])
	}
}

func TestUpdateScannerConfigAllFields(t *testing.T) {
	scanners := &richScanners{}
	handler := api.NewHandler(api.Dependencies{Scanners: scanners})
	r := mountTestAPI(handler, adminKeyRepo(t))
	body := `{"enabled_formats":["cyclonedx","spdx"],"max_components":2500,"parse_timeout_seconds":120}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/scanners", strings.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestVerifyHMACMissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(`{}`))
	if api.VerifyHMACSignature("secret", req) {
		t.Fatal("expected missing header to fail")
	}
}

func TestListProductsUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Catalog: &richCatalog{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/products", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestScanDetailWithoutIngestionID(t *testing.T) {
	scans := &richScans{
		detail: domain.ScanDetail{ScanSummary: domain.ScanSummary{ID: testScanID, ProductID: testProductID, ProjectID: testProjectID}},
	}
	handler := api.NewHandler(api.Dependencies{Scans: scans})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+testScanID, nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestUpdateNotificationConfigNullRules(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Notifications: &richNotifications{}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/notifications", strings.NewReader(`{"rules":null}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestListScanVulnerabilitiesUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: &richScans{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+testScanID+"/vulnerabilities", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestCreateProjectInvalidJSON(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Catalog: &richCatalog{}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/products/"+testProductID+"/projects", strings.NewReader(`{`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestListProjectScansUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: &richScans{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+testProjectID+"/scans", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestSubmitTriageUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Triage: &stubTriageService{}, TriageRepo: &richTriageRepo{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/"+testFindingID+"/triage", strings.NewReader(`{"decision":"confirmed","justification":"ok"}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestGetTriageHistoryUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Triage: &stubTriageService{}, TriageRepo: &richTriageRepo{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/vulnerabilities/"+testFindingID+"/triage/history", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestListProductVersionsForbidden(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Catalog: &richCatalog{}})
	r := mountTestAPI(handler, productKeyRepo(t, testProductID))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/99999999-9999-4999-8999-999999999999/versions", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestListScanVulnerabilitiesForbidden(t *testing.T) {
	scans := &richScans{
		detail: domain.ScanDetail{ScanSummary: domain.ScanSummary{ID: testScanID, ProductID: testProductID}},
	}
	handler := api.NewHandler(api.Dependencies{Scans: scans})
	r := mountTestAPI(handler, productKeyRepo(t, "99999999-9999-4999-8999-999999999999"))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans/"+testScanID+"/vulnerabilities", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestComponentAndWatchListPagination(t *testing.T) {
	now := time.Now()
	handler := api.NewHandler(api.Dependencies{
		Components: &richComponents{
			items: []domain.CatalogComponent{{PURL: "pkg:npm/a@1", Name: "a", Ecosystem: "npm"}},
			page:  domain.PageResult{NextCursor: "c-next"},
		},
		Watch: &richWatch{
			findings: []domain.CVEWatchFinding{{ID: "f1", CVEID: "CVE-1", Status: "open", DetectedAt: now}},
			page:     domain.PageResult{NextCursor: "w-next"},
		},
	})
	r := mountTestAPI(handler, adminKeyRepo(t))
	for _, tc := range []struct{ path, want string }{
		{"/api/v1/components", "c-next"},
		{"/api/v1/cve-watch/findings", "w-next"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if resp["next_cursor"] != tc.want {
			t.Fatalf("%s cursor=%v", tc.path, resp["next_cursor"])
		}
	}
}

var errBoom = errors.New("boom")

type failDispatcher struct{}

func (f *failDispatcher) EnqueueIngestion(context.Context, domain.IngestionInput, domain.JobType) (string, error) {
	return "", errBoom
}

type richCatalog struct {
	products            []domain.Product
	projects            []domain.Project
	versions            []domain.ProductVersion
	page                domain.PageResult
	listProductsErr     error
	listProjectsErr     error
	createProjectErr    error
	listVersionsErr     error
	createProductErr    error
	createVersionErr    error
	registerArtifactErr error
}

func (c *richCatalog) CreateProduct(_ context.Context, name, description string) (domain.Product, error) {
	if c.createProductErr != nil {
		return domain.Product{}, c.createProductErr
	}
	return domain.Product{ID: testProductID, Name: name, Description: description, CreatedAt: time.Now()}, nil
}
func (c *richCatalog) ListProducts(_ context.Context, _ domain.PageRequest, productScope string) ([]domain.Product, domain.PageResult, error) {
	if c.listProductsErr != nil {
		return nil, domain.PageResult{}, c.listProductsErr
	}
	if productScope == "" {
		return c.products, c.page, nil
	}
	for _, p := range c.products {
		if p.ID == productScope {
			return []domain.Product{p}, c.page, nil
		}
	}
	return nil, c.page, nil
}
func (c *richCatalog) GetProduct(_ context.Context, id string) (domain.Product, error) {
	return domain.Product{ID: id}, nil
}
func (c *richCatalog) CreateProject(_ context.Context, productID, name, description string) (domain.Project, error) {
	if c.createProjectErr != nil {
		return domain.Project{}, c.createProjectErr
	}
	return domain.Project{ID: testProjectID, ProductID: productID, Name: name, Description: description, CreatedAt: time.Now()}, nil
}
func (c *richCatalog) ListProjects(_ context.Context, _ string, _ domain.PageRequest) ([]domain.Project, domain.PageResult, error) {
	if c.listProjectsErr != nil {
		return nil, domain.PageResult{}, c.listProjectsErr
	}
	return c.projects, c.page, nil
}
func (c *richCatalog) ListProductVersions(_ context.Context, _ string, _ domain.PageRequest) ([]domain.ProductVersion, domain.PageResult, error) {
	if c.listVersionsErr != nil {
		return nil, domain.PageResult{}, c.listVersionsErr
	}
	return c.versions, c.page, nil
}

func (c *richCatalog) CreateVersion(_ context.Context, projectID, version string) (domain.ProductVersion, error) {
	if c.createVersionErr != nil {
		return domain.ProductVersion{}, c.createVersionErr
	}
	return domain.ProductVersion{ID: "v-new", ProjectID: projectID, Version: version}, nil
}

func (c *richCatalog) RegisterArtifact(_ context.Context, _, version, imageDigest, _ string) (domain.Artifact, error) {
	if c.registerArtifactErr != nil {
		return domain.Artifact{}, c.registerArtifactErr
	}
	return domain.Artifact{ID: "art-new", VersionID: "v-new", ImageDigest: imageDigest}, nil
}

type richScans struct {
	summaries         []domain.ScanSummary
	detail            domain.ScanDetail
	vulnerabilities   []domain.ScanVulnerability
	page              domain.PageResult
	projectProductID  string
	projectProductErr error
	listScansErr      error
	getScanErr        error
	listVulnErr       error
}

func (s *richScans) ListProjectScans(_ context.Context, _ string, _ domain.PageRequest) ([]domain.ScanSummary, domain.PageResult, error) {
	if s.listScansErr != nil {
		return nil, domain.PageResult{}, s.listScansErr
	}
	return s.summaries, s.page, nil
}
func (s *richScans) GetScan(_ context.Context, _ string) (domain.ScanDetail, error) {
	if s.getScanErr != nil {
		return domain.ScanDetail{}, s.getScanErr
	}
	return s.detail, nil
}
func (s *richScans) ListScanVulnerabilities(_ context.Context, _ string, _ domain.ScanVulnerabilityFilter, _ domain.PageRequest) ([]domain.ScanVulnerability, domain.PageResult, error) {
	if s.listVulnErr != nil {
		return nil, domain.PageResult{}, s.listVulnErr
	}
	return s.vulnerabilities, s.page, nil
}
func (s *richScans) GetProjectProductID(_ context.Context, _ string) (string, error) {
	if s.projectProductErr != nil {
		return "", s.projectProductErr
	}
	return s.projectProductID, nil
}

type richComponents struct {
	items   []domain.CatalogComponent
	page    domain.PageResult
	listErr error
}

func (c *richComponents) ListComponents(_ context.Context, _, _ string, _ domain.PageRequest) ([]domain.CatalogComponent, domain.PageResult, error) {
	if c.listErr != nil {
		return nil, domain.PageResult{}, c.listErr
	}
	return c.items, c.page, nil
}

type richWatch struct {
	findings []domain.CVEWatchFinding
	page     domain.PageResult
	listErr  error
}

func (w *richWatch) ListFindings(_ context.Context, _, _ string, _ domain.PageRequest) ([]domain.CVEWatchFinding, domain.PageResult, error) {
	if w.listErr != nil {
		return nil, domain.PageResult{}, w.listErr
	}
	return w.findings, w.page, nil
}

type richNotifications struct {
	rules      []domain.NotificationRule
	listErr    error
	replaceErr error
}

func (n *richNotifications) ListRules(_ context.Context) ([]domain.NotificationRule, error) {
	if n.listErr != nil {
		return nil, n.listErr
	}
	return n.rules, nil
}
func (n *richNotifications) ReplaceRules(_ context.Context, _ []domain.NotificationRule) error {
	return n.replaceErr
}

type richScanners struct {
	settings domain.ScannerSettings
	getErr   error
	saveErr  error
}

func (s *richScanners) Get(_ context.Context) (domain.ScannerSettings, error) {
	if s.getErr != nil {
		return domain.ScannerSettings{}, s.getErr
	}
	return s.settings, nil
}
func (s *richScanners) Save(_ context.Context, _ domain.ScannerSettings) error {
	return s.saveErr
}

type richTriageRepo struct {
	productID  string
	history    []domain.TriageHistoryEntry
	scopeErr   error
	historyErr error
}

func (r *richTriageRepo) GetFindingScope(_ context.Context, _ string) (string, error) {
	if r.scopeErr != nil {
		return "", r.scopeErr
	}
	return r.productID, nil
}
func (r *richTriageRepo) GetFindingContext(_ context.Context, _ string) (domain.TriageFindingContext, error) {
	return domain.TriageFindingContext{FindingID: testFindingID, RawSeverity: "high"}, nil
}
func (r *richTriageRepo) AppendHistory(_ context.Context, _ domain.TriageHistoryRecord) error {
	return nil
}
func (r *richTriageRepo) UpdateRiskContext(_ context.Context, _ domain.RiskContextTriageUpdate) error {
	return nil
}
func (r *richTriageRepo) ListExpiredAcceptedRiskFindings(context.Context, time.Time) ([]string, error) {
	return nil, nil
}
func (r *richTriageRepo) LatestDecision(context.Context, string) (string, error) { return "", nil }
func (r *richTriageRepo) ListHistory(_ context.Context, _ string, _ domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	if r.historyErr != nil {
		return nil, domain.PageResult{}, r.historyErr
	}
	return r.history, domain.PageResult{}, nil
}

type stubTriageService struct {
	submit  func(context.Context, domain.TriageDecision) (domain.TriageDecision, error)
	history func(context.Context, string, domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error)
}

func (s *stubTriageService) Submit(ctx context.Context, decision domain.TriageDecision) (domain.TriageDecision, error) {
	if s.submit != nil {
		return s.submit(ctx, decision)
	}
	return domain.TriageDecision{EffectiveState: domain.EffectiveStateConfirmed}, nil
}
func (s *stubTriageService) History(ctx context.Context, findingID string, page domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	if s.history != nil {
		return s.history(ctx, findingID, page)
	}
	return nil, domain.PageResult{}, nil
}
func (s *stubTriageService) ProcessExpiredAcceptedRisk(context.Context, time.Time) error { return nil }
