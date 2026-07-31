package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	reghttp "github.com/themis-project/themis/internal/registry/adapters/http"
	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// fakeRepo is an in-memory Repository backing the handler tests.
type fakeRepo struct {
	products      map[string]bool
	projects      map[string]bool
	releases      map[string]domain.Release
	microservices map[string]bool
	customers     map[string]bool
	blast         int
	blastErr      error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		products: map[string]bool{}, projects: map[string]bool{}, releases: map[string]domain.Release{},
		microservices: map[string]bool{}, customers: map[string]bool{},
	}
}

func (r *fakeRepo) SaveCustomer(_ context.Context, c domain.Customer) error {
	r.customers[string(c.ID())] = true
	return nil
}
func (r *fakeRepo) SaveMicroservice(_ context.Context, m domain.Microservice) error {
	r.microservices[string(m.ID())] = true
	return nil
}
func (r *fakeRepo) SaveDeployment(_ context.Context, _ domain.Deployment) error { return nil }
func (r *fakeRepo) MicroserviceExists(_ context.Context, id string) (bool, error) {
	return r.microservices[id], nil
}
func (r *fakeRepo) CustomerExists(_ context.Context, id string) (bool, error) {
	return r.customers[id], nil
}
func (r *fakeRepo) BlastRadiusCustomers(_ context.Context, _ string) (int, error) {
	return r.blast, r.blastErr
}

func (r *fakeRepo) SaveProduct(_ context.Context, p domain.Product) error {
	r.products[string(p.ID())] = true
	return nil
}
func (r *fakeRepo) SaveProject(_ context.Context, p domain.Project) error {
	r.projects[string(p.ID())] = true
	return nil
}
func (r *fakeRepo) SaveRelease(_ context.Context, rel domain.Release) error {
	r.releases[string(rel.ID())] = rel
	return nil
}
func (r *fakeRepo) GetRelease(_ context.Context, id domain.ReleaseID) (domain.Release, error) {
	rel, ok := r.releases[string(id)]
	if !ok {
		return domain.Release{}, store.ErrNotFound
	}
	return rel, nil
}
func (r *fakeRepo) ListReleases(_ context.Context, _ domain.ProjectID) ([]domain.Release, error) {
	out := make([]domain.Release, 0, len(r.releases))
	for _, rel := range r.releases {
		out = append(out, rel)
	}
	return out, nil
}
func (r *fakeRepo) ProductExists(_ context.Context, id string) (bool, error) {
	return r.products[id], nil
}
func (r *fakeRepo) ProjectExists(_ context.Context, id string) (bool, error) {
	return r.projects[id], nil
}
func (r *fakeRepo) ReleaseExists(_ context.Context, id string) (bool, error) {
	_, ok := r.releases[id]
	return ok, nil
}

type seqIDs struct{ n int }

func (s *seqIDs) NewID() string {
	s.n++
	return []string{"", "id-1", "id-2", "id-3"}[s.n]
}

func newServer(t *testing.T, repo app.Repository) *httptest.Server {
	t.Helper()
	svc := app.NewRegistryService(repo, &seqIDs{})
	srv := httptest.NewServer(reghttp.NewHandler(svc).Router())
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	switch b := body.(type) {
	case string:
		rdr = bytes.NewReader([]byte(b))
	default:
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	}
	resp, err := http.Post(url, "application/json", rdr)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func idOf(t *testing.T, raw []byte) string {
	t.Helper()
	var out struct {
		Id string `json:"id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode id: %v", err)
	}
	return out.Id
}

func TestRegisterFlow(t *testing.T) {
	repo := newFakeRepo()
	srv := newServer(t, repo)

	// Product.
	status, raw := post(t, srv.URL+"/products", map[string]string{"name": "Themis"})
	if status != http.StatusCreated {
		t.Fatalf("register product status = %d: %s", status, raw)
	}
	prodID := idOf(t, raw)

	// Project under the product.
	status, raw = post(t, srv.URL+"/projects", map[string]string{"product_id": prodID, "name": "api"})
	if status != http.StatusCreated {
		t.Fatalf("register project status = %d: %s", status, raw)
	}
	projID := idOf(t, raw)

	// Release under the project.
	status, raw = post(t, srv.URL+"/releases", map[string]string{"project_id": projID, "version": "1.0.0"})
	if status != http.StatusCreated {
		t.Fatalf("register release status = %d: %s", status, raw)
	}
	relID := idOf(t, raw)

	// Get the release back.
	resp, err := http.Get(srv.URL + "/releases/" + relID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get release status = %d", resp.StatusCode)
	}
	var rel struct{ Id, ProjectId, Version string }
	_ = json.NewDecoder(resp.Body).Decode(&rel)
	if rel.Id != relID || rel.Version != "1.0.0" {
		t.Errorf("release = %+v", rel)
	}

	// List by project.
	lresp, err := http.Get(srv.URL + "/releases?project=" + projID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lresp.Body.Close() }()
	var list []map[string]any
	_ = json.NewDecoder(lresp.Body).Decode(&list)
	if len(list) != 1 {
		t.Errorf("list len = %d, want 1", len(list))
	}
}

func TestRegisterErrors(t *testing.T) {
	srv := newServer(t, newFakeRepo())

	// Unknown product → 422.
	if status, _ := post(t, srv.URL+"/projects", map[string]string{"product_id": "nope", "name": "api"}); status != http.StatusUnprocessableEntity {
		t.Errorf("unknown product status = %d, want 422", status)
	}
	// Unknown project → 422.
	if status, _ := post(t, srv.URL+"/releases", map[string]string{"project_id": "nope", "version": "1.0"}); status != http.StatusUnprocessableEntity {
		t.Errorf("unknown project status = %d, want 422", status)
	}
	// Invalid product (empty name) → 400.
	if status, _ := post(t, srv.URL+"/products", map[string]string{"name": ""}); status != http.StatusBadRequest {
		t.Errorf("empty name status = %d, want 400", status)
	}
	// Malformed JSON → 400 (exercise each register handler's decode path).
	for _, path := range []string{"/products", "/projects", "/releases"} {
		if status, _ := post(t, srv.URL+path, "{not json"); status != http.StatusBadRequest {
			t.Errorf("%s malformed body status = %d, want 400", path, status)
		}
	}
}

func TestEstateEndpoints(t *testing.T) {
	repo := newFakeRepo()
	repo.products["prod-1"] = true
	repo.blast = 3
	srv := newServer(t, repo)

	code, body := post(t, srv.URL+"/customers", map[string]any{"name": "Acme"})
	if code != http.StatusCreated {
		t.Fatalf("customer = %d: %s", code, body)
	}
	custID := idOf(t, body)

	code, body = post(t, srv.URL+"/products/prod-1/microservices", map[string]any{"name": "payments"})
	if code != http.StatusCreated {
		t.Fatalf("microservice = %d: %s", code, body)
	}
	msID := idOf(t, body)

	code, body = post(t, srv.URL+"/microservices/"+msID+"/deployments",
		map[string]any{"customer_id": custID, "environment": "prod"})
	if code != http.StatusCreated {
		t.Fatalf("deployment = %d: %s", code, body)
	}

	resp, err := http.Get(srv.URL + "/releases/rel-1/blast-radius")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blast status = %d", resp.StatusCode)
	}
	var br struct {
		ReleaseId       string `json:"release_id"`
		UniqueCustomers int    `json:"unique_customers"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&br)
	if br.ReleaseId != "rel-1" || br.UniqueCustomers != 3 {
		t.Errorf("blast = %+v, want rel-1 / 3", br)
	}
}

func TestEstateErrors(t *testing.T) {
	srv := newServer(t, newFakeRepo())
	if code, _ := post(t, srv.URL+"/products/nope/microservices", map[string]any{"name": "x"}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown-product microservice = %d, want 422", code)
	}
	if code, _ := post(t, srv.URL+"/microservices/nope/deployments", map[string]any{"customer_id": "c", "environment": "prod"}); code != http.StatusUnprocessableEntity {
		t.Errorf("unknown-microservice deployment = %d, want 422", code)
	}
	// Malformed body → 400 on every estate register handler (exercise each decode path).
	for _, path := range []string{"/customers", "/products/prod-1/microservices", "/microservices/ms-1/deployments"} {
		if code, _ := post(t, srv.URL+path, "{bad"); code != http.StatusBadRequest {
			t.Errorf("%s malformed body = %d, want 400", path, code)
		}
	}
	// Invalid customer name → 400 (domain validation via writeRegisterError).
	if code, _ := post(t, srv.URL+"/customers", map[string]any{"name": ""}); code != http.StatusBadRequest {
		t.Errorf("empty customer name = %d, want 400", code)
	}
	// A traversal store error → 500.
	repo := newFakeRepo()
	repo.blastErr = errors.New("db down")
	esrv := newServer(t, repo)
	resp, err := http.Get(esrv.URL + "/releases/rel-1/blast-radius")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("blast error = %d, want 500", resp.StatusCode)
	}
}

func TestGetReleaseNotFound(t *testing.T) {
	srv := newServer(t, newFakeRepo())
	resp, err := http.Get(srv.URL + "/releases/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get missing release status = %d, want 404", resp.StatusCode)
	}
}
