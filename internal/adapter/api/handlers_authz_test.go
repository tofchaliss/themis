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
