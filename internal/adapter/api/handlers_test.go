package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/adapter/api"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/triage"
)

func TestUploadSBOMRequiresAPIKey(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{})
	r := mountTestAPI(handler, emptyKeyRepo())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", bytes.NewBufferString(`{"format":"cyclonedx","document":{}}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
	assertProblem(t, rec, http.StatusUnauthorized)
}

func TestUploadSBOMAccepted(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	jobs := &fakeJobs{}
	handler := api.NewHandler(api.Dependencies{
		Jobs:       jobs,
		Dispatcher: dispatcher,
		MaxUpload:  1024 * 1024,
	})
	r := mountTestAPI(handler, adminKeyRepo(t))

	body := `{"format":"cyclonedx","document":{"components":[]},"image_digest":"sha256:abc"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", bytes.NewBufferString(body))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if dispatcher.lastInput.ImageDigest != "sha256:abc" {
		t.Fatalf("input = %+v", dispatcher.lastInput)
	}
}

func TestUploadSBOMIdempotent(t *testing.T) {
	jobs := &fakeJobs{
		byKey: domain.IngestionRecord{
			ID:             "11111111-1111-4111-8111-111111111111",
			Status:         domain.IngestionStatusNotified,
			IdempotencyKey: "key-1",
		},
	}
	handler := api.NewHandler(api.Dependencies{Jobs: jobs, Dispatcher: &fakeDispatcher{}})
	r := mountTestAPI(handler, adminKeyRepo(t))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", bytes.NewBufferString(`{"format":"cyclonedx","document":{}}`))
	req.Header.Set("X-API-Key", "secret")
	req.Header.Set("Idempotency-Key", "key-1")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestUploadSBOMPayloadTooLarge(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{MaxUpload: 32, Dispatcher: &fakeDispatcher{}})
	r := mountTestAPIWithLimit(handler, adminKeyRepo(t), 32)

	var body bytes.Buffer
	writer := multipartWriter(t, &body, bytes.Repeat([]byte("x"), 128))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sbom/upload", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebhookInvalidSignature(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Dispatcher: &fakeDispatcher{}})
	r := chi.NewRouter()
	api.Mount(r, api.MountConfig{
		Handler:     handler,
		APIKeyAuth:  apimiddleware.APIKeyAuth{Keys: adminKeyRepo(t)},
		WebhookAuth: apimiddleware.WebhookAuth{Secret: "topsecret"},
		MaxUploadSize: 1024,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/scan", bytes.NewBufferString(`{"format":"cyclonedx","document":{},"image_digest":"sha256:abc"}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestWebhookAccepted(t *testing.T) {
	dispatcher := &fakeDispatcher{}
	handler := api.NewHandler(api.Dependencies{Dispatcher: dispatcher})
	body := []byte(`{"format":"cyclonedx","document":{},"image_digest":"sha256:abc"}`)
	r := chi.NewRouter()
	api.Mount(r, api.MountConfig{
		Handler:     handler,
		APIKeyAuth:  apimiddleware.APIKeyAuth{Keys: adminKeyRepo(t)},
		WebhookAuth: apimiddleware.WebhookAuth{Secret: "topsecret"},
		MaxUploadSize: 1024,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/scan", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", api.SignHMAC("topsecret", body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestGetIngestionNotFound(t *testing.T) {
	handler := api.NewHandler(api.Dependencies{Jobs: &fakeJobs{getErr: true}})
	r := mountTestAPI(handler, adminKeyRepo(t))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ingestions/11111111-1111-4111-8111-111111111111", nil)
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestCreateProductForbiddenForReadOnly(t *testing.T) {
	catalog := &fakeCatalog{}
	handler := api.NewHandler(api.Dependencies{Catalog: catalog})
	r := mountTestAPI(handler, readOnlyKeyRepo(t))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewBufferString(`{"name":"app"}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSubmitTriageValidation(t *testing.T) {
	repo := &fakeTriageRepo{productID: "22222222-2222-4222-8222-222222222222"}
	handler := api.NewHandler(api.Dependencies{
		Triage:     &triage.Handler{Repo: repo},
		TriageRepo: repo,
	})
	r := mountTestAPI(handler, productKeyRepo(t, "22222222-2222-4222-8222-222222222222"))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/vulnerabilities/33333333-3333-4333-8333-333333333333/triage",
		bytes.NewBufferString(`{"decision":"false_positive","justification":""}`))
	req.Header.Set("X-API-Key", "secret")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestProblemDetailShape(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	api.WriteProblem(rec, req, http.StatusNotFound, "Not Found", "missing")
	assertProblem(t, rec, http.StatusNotFound)
}

func mountTestAPI(handler *api.Handler, keys domain.APIKeyRepository) http.Handler {
	return mountTestAPIWithLimit(handler, keys, 1024*1024)
}

func mountTestAPIWithLimit(handler *api.Handler, keys domain.APIKeyRepository, max int64) http.Handler {
	r := chi.NewRouter()
	api.Mount(r, api.MountConfig{
		Handler:       handler,
		APIKeyAuth:    apimiddleware.APIKeyAuth{Keys: keys},
		WebhookAuth:   apimiddleware.WebhookAuth{Secret: "topsecret"},
		MaxUploadSize: max,
	})
	return r
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("content-type = %q", rec.Header().Get("Content-Type"))
	}
	var problem api.ProblemDetail
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem.Status != status || problem.Title == "" {
		t.Fatalf("problem = %+v", problem)
	}
}

func emptyKeyRepo() domain.APIKeyRepository { return &fakeKeys{} }

func adminKeyRepo(t *testing.T) domain.APIKeyRepository {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKeys{keys: []domain.APIKeyRecord{{ID: "k1", KeyHash: string(hash), Scopes: []string{domain.ScopeAdmin}}}}
}

func readOnlyKeyRepo(t *testing.T) domain.APIKeyRepository {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKeys{keys: []domain.APIKeyRecord{{ID: "k1", KeyHash: string(hash), Scopes: []string{domain.ScopeReadOnly}}}}
}

func productKeyRepo(t *testing.T, productID string) domain.APIKeyRepository {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKeys{keys: []domain.APIKeyRecord{{ID: "k1", KeyHash: string(hash), Scopes: []string{domain.ProductScopePrefix + productID}}}}
}

type fakeDispatcher struct {
	lastInput domain.IngestionInput
}

func (f *fakeDispatcher) EnqueueIngestion(_ context.Context, input domain.IngestionInput, _ domain.JobType) (string, error) {
	f.lastInput = input
	return "44444444-4444-4444-8444-444444444444", nil
}

type fakeJobs struct {
	byKey  domain.IngestionRecord
	getErr bool
	scanID string
}

func (f *fakeJobs) FindByIdempotencyKey(_ context.Context, key string) (domain.IngestionRecord, bool, error) {
	if f.byKey.IdempotencyKey != "" && f.byKey.IdempotencyKey == key {
		return f.byKey, true, nil
	}
	return domain.IngestionRecord{}, false, nil
}
func (f *fakeJobs) Create(context.Context, domain.IngestionRecord) error { return nil }
func (f *fakeJobs) UpdateStatus(context.Context, string, domain.IngestionStatus, string, string) error {
	return nil
}
func (f *fakeJobs) Get(context.Context, string) (domain.IngestionRecord, error) {
	if f.getErr {
		return domain.IngestionRecord{}, errNotFound
	}
	return domain.IngestionRecord{
		ID:        "11111111-1111-4111-8111-111111111111",
		Status:    domain.IngestionStatusCorrelating,
		CreatedAt: time.Now(),
		ScanID:    f.scanID,
	}, nil
}

type fakeCatalog struct {
	products         []domain.Product
	listProductsErr  error
}

func (f *fakeCatalog) CreateProduct(context.Context, string, string) (domain.Product, error) {
	return domain.Product{ID: "p1", Name: "app"}, nil
}
func (f *fakeCatalog) ListProducts(_ context.Context, _ domain.PageRequest, productScope string) ([]domain.Product, domain.PageResult, error) {
	if f.listProductsErr != nil {
		return nil, domain.PageResult{}, f.listProductsErr
	}
	items := f.products
	if productScope != "" {
		filtered := make([]domain.Product, 0, 1)
		for _, p := range items {
			if p.ID == productScope {
				filtered = append(filtered, p)
			}
		}
		items = filtered
	}
	if len(items) > 0 {
		return items, domain.PageResult{}, nil
	}
	return nil, domain.PageResult{}, nil
}
func (f *fakeCatalog) GetProduct(context.Context, string) (domain.Product, error) {
	return domain.Product{}, errNotFound
}
func (f *fakeCatalog) CreateProject(context.Context, string, string, string) (domain.Project, error) {
	return domain.Project{}, nil
}
func (f *fakeCatalog) ListProjects(context.Context, string, domain.PageRequest) ([]domain.Project, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}
func (f *fakeCatalog) ListProductVersions(context.Context, string, domain.PageRequest) ([]domain.ProductVersion, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}

type fakeTriageRepo struct {
	productID string
}

func (f *fakeTriageRepo) GetFindingScope(context.Context, string) (string, error) {
	return f.productID, nil
}
func (f *fakeTriageRepo) GetFindingContext(context.Context, string) (domain.TriageFindingContext, error) {
	return domain.TriageFindingContext{}, errNotFound
}
func (f *fakeTriageRepo) AppendHistory(context.Context, domain.TriageHistoryRecord) error { return nil }
func (f *fakeTriageRepo) UpdateRiskContext(context.Context, domain.RiskContextTriageUpdate) error {
	return errNotFound
}
func (f *fakeTriageRepo) ListExpiredAcceptedRiskFindings(context.Context, time.Time) ([]string, error) {
	return nil, nil
}
func (f *fakeTriageRepo) LatestDecision(context.Context, string) (string, error) { return "", nil }
func (f *fakeTriageRepo) ListHistory(context.Context, string, domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	return nil, domain.PageResult{}, nil
}

type fakeKeys struct {
	keys []domain.APIKeyRecord
}

func (f *fakeKeys) FindByHashPrefix(context.Context) ([]domain.APIKeyRecord, error) { return f.keys, nil }
func (f *fakeKeys) FindActiveKeys(context.Context) ([]domain.APIKeyRecord, error)  { return f.keys, nil }
func (f *fakeKeys) Create(context.Context, domain.APIKeyCreateInput) (domain.APIKeyRecord, error) {
	return domain.APIKeyRecord{}, nil
}
func (f *fakeKeys) Revoke(context.Context, string) error { return nil }

var errNotFound = errString("not found")

type errString string

func (e errString) Error() string { return string(e) }

func multipartWriter(t *testing.T, body *bytes.Buffer, content []byte) *multipart.Writer {
	t.Helper()
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("document", "sbom.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	_ = writer.WriteField("format", "cyclonedx")
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return writer
}
