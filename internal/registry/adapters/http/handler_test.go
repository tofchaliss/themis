package http_test

import (
	"bytes"
	"context"
	"encoding/json"
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
	products map[string]bool
	projects map[string]bool
	releases map[string]domain.Release
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{products: map[string]bool{}, projects: map[string]bool{}, releases: map[string]domain.Release{}}
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
func (r *fakeRepo) ProductExists(_ context.Context, id string) (bool, error) { return r.products[id], nil }
func (r *fakeRepo) ProjectExists(_ context.Context, id string) (bool, error) { return r.projects[id], nil }
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
