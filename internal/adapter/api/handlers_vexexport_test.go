package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/domain"
)

type fakeVEXExport struct {
	body      []byte
	coverage  domain.VEXCoverageSummary
	exportErr error
}

func (f *fakeVEXExport) ExportVEX(context.Context, string, string, domain.VEXExportFormat) ([]byte, error) {
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	return f.body, nil
}

func (f *fakeVEXExport) ExportCoverage(context.Context, string, string) (domain.VEXCoverageSummary, error) {
	if f.exportErr != nil {
		return domain.VEXCoverageSummary{}, f.exportErr
	}
	return f.coverage, nil
}

func TestGetProductVersionVEX(t *testing.T) {
	export := &fakeVEXExport{body: []byte(`{"bomFormat":"CycloneDX"}`)}
	handler := api.NewHandler(api.Dependencies{VEXExport: export})
	r := chi.NewRouter()
	r.Get("/api/v1/products/{id}/versions/{v}/vex", handler.GetProductVersionVEX)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/versions/1.0.0/vex?format=cyclonedx", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGetProductVersionVEXNotFound(t *testing.T) {
	export := &fakeVEXExport{exportErr: domain.ErrProductNotFound}
	handler := api.NewHandler(api.Dependencies{VEXExport: export})
	r := chi.NewRouter()
	r.Get("/api/v1/products/{id}/versions/{v}/vex", handler.GetProductVersionVEX)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/versions/9.9.9/vex", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestGetProductVersionVEXCoverage(t *testing.T) {
	export := &fakeVEXExport{coverage: domain.VEXCoverageSummary{Covered: 2, NotCovered: 1, PURLMismatch: 3}}
	handler := api.NewHandler(api.Dependencies{VEXExport: export})
	r := chi.NewRouter()
	r.Get("/api/v1/products/{id}/versions/{v}/vex-coverage", handler.GetProductVersionVEXCoverage)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/versions/1.0.0/vex-coverage", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["covered"] != 2 {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
}

func TestGetProductVersionVEXUnavailable(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{})
	r := chi.NewRouter()
	r.Get("/api/v1/products/{id}/versions/{v}/vex", handler.GetProductVersionVEX)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products/"+testProductID+"/versions/1.0.0/vex", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d", rec.Code)
	}
}
