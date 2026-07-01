package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/api"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/domain"
)

func TestAuthorizeProductScopes(t *testing.T) {
	admin := domain.AuthPrincipal{Scopes: []string{domain.ScopeAdmin}}
	if !api.AuthorizeProduct(admin, "any") {
		t.Fatal("admin should pass")
	}
	product := domain.AuthPrincipal{Scopes: []string{domain.ProductScopePrefix + "p1"}}
	if !api.AuthorizeProduct(product, "p1") || api.AuthorizeProduct(product, "p2") {
		t.Fatal("product scope mismatch")
	}
}

func TestPageFromParams(t *testing.T) {
	cursor := "abc"
	limit := 10
	page := api.PageFromParams(&cursor, &limit)
	if page.Cursor != "abc" || page.Limit != 10 {
		t.Fatalf("page = %+v", page)
	}
}

func TestListProductsAndConfig(t *testing.T) {
	catalog := &fakeCatalog{
		products: []domain.Product{{ID: "11111111-1111-4111-8111-111111111111", Name: "themis"}},
	}
	notifications := &fakeNotifications{rules: []domain.NotificationRule{{Name: "default", EventType: "ingestion", Channel: "email", Destination: "a@b.c", Enabled: true}}}
	scanners := &fakeScanners{settings: domain.ScannerSettings{MaxComponents: 1000}}
	handler := api.NewHandler(api.Dependencies{
		Catalog:       catalog,
		Scans:         &fakeScans{},
		Components:    &fakeComponents{},
		Watch:         &fakeWatch{},
		Notifications: notifications,
		Scanners:      scanners,
	})
	r := mountTestAPI(handler, adminKeyRepo(t))

	for _, tc := range []struct {
		method, path string
		body         []byte
		want         int
	}{
		{http.MethodGet, "/api/v1/products", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/config/notifications", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/config/scanners", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/components", nil, http.StatusOK},
		{http.MethodGet, "/api/v1/cve-watch/findings", nil, http.StatusOK},
	} {
		req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
		req.Header.Set("X-API-Key", "secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s %s status=%d body=%s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

func TestMiddlewareRejectsMissingKey(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := apimiddleware.APIKeyAuth{Keys: &fakeKeys{}}.Middleware(next)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/products", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSignHMAC(t *testing.T) {
	body := []byte(`{"ok":true}`)
	sig := api.SignHMAC("secret", body)
	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", sig)
	if !api.VerifyHMACSignature("secret", req) {
		t.Fatal("expected valid signature")
	}
}

type fakeNotifications struct {
	rules []domain.NotificationRule
}

func (f *fakeNotifications) ListRules(context.Context) ([]domain.NotificationRule, error) { return f.rules, nil }
func (f *fakeNotifications) ReplaceRules(context.Context, []domain.NotificationRule) error { return nil }

type fakeScanners struct {
	settings domain.ScannerSettings
}

func (f *fakeScanners) Get(context.Context) (domain.ScannerSettings, error) { return f.settings, nil }
func (f *fakeScanners) Save(context.Context, domain.ScannerSettings) error    { return nil }

type fakeScans struct{}

func (f *fakeScans) ListProjectScans(context.Context, string, domain.PageRequest) ([]domain.ScanSummary, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}
func (f *fakeScans) GetScan(context.Context, string) (domain.ScanDetail, error) {
	return domain.ScanDetail{}, errNotFound
}
func (f *fakeScans) ListScanVulnerabilities(context.Context, string, domain.ScanVulnerabilityFilter, domain.PageRequest) ([]domain.ScanVulnerability, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}
func (f *fakeScans) ListScopedVulnerabilities(context.Context, domain.FindingScope, domain.ScanVulnerabilityFilter, domain.PageRequest) ([]domain.ScanVulnerability, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}
func (f *fakeScans) GetProjectProductID(context.Context, string) (string, error) { return "", errNotFound }

type fakeComponents struct{}

func (f *fakeComponents) ListComponents(context.Context, string, string, domain.PageRequest) ([]domain.CatalogComponent, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}

type fakeWatch struct{}

func (f *fakeWatch) ListFindings(context.Context, string, string, domain.PageRequest) ([]domain.CVEWatchFinding, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}


func TestUpdateNotificationConfigRequiresAdmin(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Notifications: &fakeNotifications{}})
	r := mountTestAPI(handler, readOnlyKeyRepo(t))
	body, _ := json.Marshal(map[string]any{"rules": []any{}})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/config/notifications", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}
