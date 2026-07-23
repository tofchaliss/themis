package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/domain"
)

func scopedVulnFixture() *richScans {
	return &richScans{
		vulnerabilities:  []domain.ScanVulnerability{{ID: "f1", CVEID: "CVE-2024-0001", Severity: "high", EffectiveState: "confirmed"}},
		projectProductID: testProductID,
	}
}

func TestScopedVulnerabilitiesDefaultLimit(t *testing.T) {
	scans := scopedVulnFixture()
	handler := api.NewHandler(api.Dependencies{Scans: scans})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/vulnerabilities", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if scans.gotLimit != 50 {
		t.Fatalf("scoped-vuln default limit = %d, want 50", scans.gotLimit)
	}

	// An over-large limit is clamped to 100.
	clampReq := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/vulnerabilities?limit=500", nil)
	clampReq.Header.Set("X-API-Key", "secret")
	clampRec := httptest.NewRecorder()
	r.ServeHTTP(clampRec, clampReq)
	if scans.gotLimit != 100 {
		t.Fatalf("scoped-vuln clamped limit = %d, want 100", scans.gotLimit)
	}
}

func TestScopedVulnerabilitiesUnauthorized(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: scopedVulnFixture()})
	r := mountTestAPI(handler, emptyKeyRepo())
	for _, path := range []string{
		"/api/v1/products/" + testProductID + "/vulnerabilities",
		"/api/v1/projects/" + testProjectID + "/vulnerabilities",
		"/api/v1/products/" + testProductID + "/versions/1.0.0/vulnerabilities",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s status=%d, want 401", path, rec.Code)
		}
	}
}

func TestScopedVulnerabilitiesForbidden(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: scopedVulnFixture()})
	// Key scoped to a different product than the one being queried.
	r := mountTestAPI(handler, productKeyRepo(t, "99999999-9999-4999-8999-999999999999"))
	for _, path := range []string{
		"/api/v1/products/" + testProductID + "/vulnerabilities",
		"/api/v1/projects/" + testProjectID + "/vulnerabilities",
		"/api/v1/products/" + testProductID + "/versions/1.0.0/vulnerabilities",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s status=%d, want 403", path, rec.Code)
		}
	}
}

func TestScopedVulnerabilitiesSuccess(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: scopedVulnFixture()})
	r := mountTestAPI(handler, adminKeyRepo(t))
	for _, path := range []string{
		"/api/v1/products/" + testProductID + "/vulnerabilities?severity=high&limit=10",
		"/api/v1/projects/" + testProjectID + "/vulnerabilities?effective_state=confirmed",
		"/api/v1/products/" + testProductID + "/versions/1.0.0/vulnerabilities?cve_id=CVE-2024-0001&cursor=f0",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d, want 200", path, rec.Code)
		}
	}
}

func TestProjectVulnerabilitiesNotFound(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: &richScans{projectProductErr: errBoom}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+testProjectID+"/vulnerabilities", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rec.Code)
	}
}

func TestScopedVulnerabilitiesStoreError(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Scans: &richScans{projectProductID: testProductID, listVulnErr: errBoom}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/vulnerabilities", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", rec.Code)
	}
}
