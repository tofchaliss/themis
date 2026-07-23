package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/adapter/api/gen"
	"github.com/themis-project/themis/internal/domain"
)

// A read-only key must be rejected from every mutating endpoint before any
// business logic runs (these handlers previously checked only auth presence).
func TestWriteScopedMutationsRejectReadOnlyKey(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{})
	readOnly := domain.AuthPrincipal{KeyID: "ro", Scopes: []string{domain.ScopeReadOnly}}
	req := func(method, path string) *http.Request {
		r := httptest.NewRequest(method, path, http.NoBody)
		return r.WithContext(api.WithAuth(context.Background(), readOnly))
	}

	t.Run("DeleteSBOM", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.DeleteSBOM(rec, req(http.MethodDelete, "/api/v1/sboms/x"))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", rec.Code)
		}
	})
	t.Run("UploadSBOM", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.UploadSBOM(rec, req(http.MethodPost, "/api/v1/sbom/upload"), gen.UploadSBOMParams{})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", rec.Code)
		}
	})
	t.Run("UploadVEX", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.UploadVEX(rec, req(http.MethodPost, "/api/v1/vex/upload"), gen.UploadVEXParams{})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status=%d, want 403", rec.Code)
		}
	})
}

// With no authenticated principal at all, uploads report 401 and delete 403.
func TestMutationsRejectMissingAuth(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{})
	bare := func(method, path string) *http.Request {
		return httptest.NewRequest(method, path, http.NoBody)
	}
	recSBOM := httptest.NewRecorder()
	handler.UploadSBOM(recSBOM, bare(http.MethodPost, "/api/v1/sbom/upload"), gen.UploadSBOMParams{})
	if recSBOM.Code != http.StatusUnauthorized {
		t.Fatalf("UploadSBOM status=%d, want 401", recSBOM.Code)
	}
	recVEX := httptest.NewRecorder()
	handler.UploadVEX(recVEX, bare(http.MethodPost, "/api/v1/vex/upload"), gen.UploadVEXParams{})
	if recVEX.Code != http.StatusUnauthorized {
		t.Fatalf("UploadVEX status=%d, want 401", recVEX.Code)
	}
	recDel := httptest.NewRecorder()
	handler.DeleteSBOM(recDel, bare(http.MethodDelete, "/api/v1/sboms/x"))
	if recDel.Code != http.StatusForbidden {
		t.Fatalf("DeleteSBOM status=%d, want 403", recDel.Code)
	}
}
