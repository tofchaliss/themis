package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/adapter/api"
	"github.com/themis-project/themis/internal/adapter/assetgraph"
	"github.com/themis-project/themis/internal/domain"
)

func TestErrorCode_SBOMNotFound(t *testing.T) {
	assertCatalog(t, domain.ErrSBOMNotFound, http.StatusNotFound, api.CodeSBOMNotFound)
}

func TestErrorCode_ProductNotFound(t *testing.T) {
	assertCatalog(t, domain.ErrProductNotFound, http.StatusNotFound, api.CodeProductNotFound)
}

func TestErrorCode_ImageNotFound(t *testing.T) {
	assertCatalog(t, errors.New("image not found — ingest parent first"), http.StatusNotFound, api.CodeImageNotFound)
}

func TestErrorCode_CustomerNotFound(t *testing.T) {
	assertCatalog(t, assetgraph.ErrCustomerNotFound, http.StatusNotFound, api.CodeCustomerNotFound)
}

func TestErrorCode_CannotDeleteLatestSBOM(t *testing.T) {
	assertCatalog(t, domain.ErrCannotDeleteLatestSBOM, http.StatusConflict, api.CodeCannotDeleteLatestSBOM)
}

func TestErrorCode_DuplicateMicroservice(t *testing.T) {
	assertCatalog(t, assetgraph.ErrDuplicateMicroservice, http.StatusConflict, api.CodeDuplicateMicroservice)
}

func TestErrorCode_DuplicateCustomer(t *testing.T) {
	assertCatalog(t, assetgraph.ErrDuplicateCustomer, http.StatusConflict, api.CodeDuplicateCustomer)
}

func TestErrorCode_InvalidSBOMFormat(t *testing.T) {
	assertCatalog(t, errors.New("invalid sbom format"), http.StatusUnprocessableEntity, api.CodeInvalidSBOMFormat)
}

func TestErrorCode_InvalidRequest(t *testing.T) {
	assertCatalog(t, errors.New("name is required"), http.StatusBadRequest, api.CodeInvalidRequest)
}

func TestErrorCode_MissingAPIKey(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	handler := api.NewHandler(api.Dependencies{Status: &fakeStatus{}})
	r := mountTestAPI(handler, emptyKeyRepo())
	r.ServeHTTP(rec, req)
	assertAPIError(t, rec, http.StatusUnauthorized, "MISSING_API_KEY")
}

func TestErrorCode_InvalidAPIKey(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-API-Key", "wrong")
	handler := api.NewHandler(api.Dependencies{Status: &fakeStatus{}})
	r := mountTestAPI(handler, adminKeyRepo(t))
	r.ServeHTTP(rec, req)
	assertAPIError(t, rec, http.StatusUnauthorized, "INVALID_API_KEY")
}

func TestErrorCode_InternalError(t *testing.T) {
	assertCatalog(t, errors.New("unexpected boom"), http.StatusInternalServerError, api.CodeInternalError)
}

func TestErrorCode_FallbackForUnhandledErrors(t *testing.T) {
	rec := httptest.NewRecorder()
	api.RespondError(rec, httptest.NewRequest(http.MethodGet, "/", nil), errors.New("weird"))
	assertAPIError(t, rec, http.StatusInternalServerError, "INTERNAL_ERROR")
}

func TestAC23_NoRawDBErrorLeaks(t *testing.T) {
	pgErr := &pgconn.PgError{
		Code:           "23505",
		Message:        "duplicate key value violates unique constraint",
		ConstraintName: "products_name_key",
		TableName:      "products",
	}
	rec := httptest.NewRecorder()
	api.RespondError(rec, httptest.NewRequest(http.MethodGet, "/", nil), pgErr)
	body := rec.Body.String()
	for _, forbidden := range []string{"pq:", "23505", "products_name_key", "products"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, body)
		}
	}
	assertAPIError(t, rec, http.StatusInternalServerError, "INTERNAL_ERROR")
}

func assertCatalog(t *testing.T, err error, wantStatus int, wantCode api.ErrorCode) {
	t.Helper()
	code, status := api.MapError(err)
	if code != wantCode || status != wantStatus {
		t.Fatalf("MapError(%v) = (%s, %d), want (%s, %d)", err, code, status, wantCode, wantStatus)
	}
	rec := httptest.NewRecorder()
	api.WriteCatalogError(rec, status, code)
	assertAPIError(t, rec, status, string(wantCode))
}

type fakeStatus struct{}

func (fakeStatus) GetSystemStatus(context.Context, int) (domain.SystemStatus, error) {
	return domain.SystemStatus{}, nil
}
