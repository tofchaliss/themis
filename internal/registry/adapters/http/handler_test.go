package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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
	projectObjs   map[string]domain.Project
	productObjs   map[string]domain.Product
	projErr       error
	prodErr       error
	microservices map[string]bool
	customers     map[string]bool
	blast         int
	blastErr      error
	listErr       error

	// Name indexes mirroring the store's unique indexes (B4).
	productIDs map[string]string
	projectIDs map[string]string
	releaseIDs map[string]string
	rows       int

	tags     map[string][]string // "kind/id" → own tags (EDR-REMEDIATION-01 D7)
	tagsErr  error
	tagsErr2 error
}

func (r *fakeRepo) SetTags(_ context.Context, kind domain.TagEntity, id string, tags []string) error {
	if r.tagsErr != nil {
		return r.tagsErr
	}
	if r.tags == nil {
		r.tags = map[string][]string{}
	}
	r.tags[string(kind)+"/"+id] = tags
	return nil
}

func (r *fakeRepo) TagsOf(_ context.Context, kind domain.TagEntity, ids []string) (map[string][]string, error) {
	if r.tagsErr != nil {
		return nil, r.tagsErr
	}
	out := map[string][]string{}
	for _, id := range ids {
		if t, ok := r.tags[string(kind)+"/"+id]; ok {
			out[id] = t
		}
	}
	return out, nil
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		products: map[string]bool{}, projects: map[string]bool{}, releases: map[string]domain.Release{},
		microservices: map[string]bool{}, customers: map[string]bool{},
		productIDs: map[string]string{}, projectIDs: map[string]string{}, releaseIDs: map[string]string{},
		projectObjs: map[string]domain.Project{},
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

// The three find-or-creates, standing in for the store's unique indexes (EDR-INTAKE-01 B4):
// products and projects fold case, a version is matched exactly, and only the caller that
// minted the row is told created=true.
func (r *fakeRepo) UpsertProduct(_ context.Context, name string) (string, bool, error) {
	id, created := r.findOrCreate(r.productIDs, strings.ToLower(name))
	if created {
		r.products[id] = true
	}
	return id, created, nil
}
func (r *fakeRepo) UpsertProject(_ context.Context, productID, name string) (string, bool, error) {
	id, created := r.findOrCreate(r.projectIDs, productID+"\x00"+strings.ToLower(name))
	if created {
		r.projects[id] = true
		// The upward hop (and the tag inheritance that rides it) sees what the upsert wrote.
		if r.projectObjs != nil {
			if p, err := domain.NewProject(domain.ProjectID(id), domain.ProductID(productID), name); err == nil {
				r.projectObjs[id] = p
			}
		}
	}
	return id, created, nil
}
func (r *fakeRepo) UpsertRelease(_ context.Context, projectID, version string) (string, bool, error) {
	id, created := r.findOrCreate(r.releaseIDs, projectID+"\x00"+version)
	if created {
		rel, err := domain.NewRelease(domain.ReleaseID(id), domain.ProjectID(projectID), version)
		if err != nil {
			return "", false, err
		}
		r.releases[id] = rel
	}
	return id, created, nil
}
func (r *fakeRepo) findOrCreate(index map[string]string, key string) (string, bool) {
	if id, ok := index[key]; ok {
		return id, false
	}
	r.rows++
	id := fmt.Sprintf("row-%d", r.rows)
	index[key] = id
	return id, true
}
func (r *fakeRepo) GetRelease(_ context.Context, id domain.ReleaseID) (domain.Release, error) {
	rel, ok := r.releases[string(id)]
	if !ok {
		return domain.Release{}, store.ErrNotFound
	}
	return rel, nil
}
func (r *fakeRepo) GetProject(_ context.Context, id domain.ProjectID) (domain.Project, error) {
	if r.projErr != nil {
		return domain.Project{}, r.projErr
	}
	p, ok := r.projectObjs[string(id)]
	if !ok {
		return domain.Project{}, store.ErrNotFound
	}
	return p, nil
}
func (r *fakeRepo) GetProduct(_ context.Context, id domain.ProductID) (domain.Product, error) {
	if r.prodErr != nil {
		return domain.Product{}, r.prodErr
	}
	p, ok := r.productObjs[string(id)]
	if !ok {
		return domain.Product{}, store.ErrNotFound
	}
	return p, nil
}
func (r *fakeRepo) ListProducts(_ context.Context, name string) ([]domain.Product, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := make([]domain.Product, 0, len(r.products))
	for id := range r.products {
		p, err := domain.NewProduct(domain.ProductID(id), "product-"+id)
		if err != nil {
			return nil, err
		}
		if name != "" && p.Name() != name {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
func (r *fakeRepo) ListProjects(_ context.Context, product domain.ProductID, name string) ([]domain.Project, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	out := make([]domain.Project, 0, len(r.projects))
	for id := range r.projects {
		p, err := domain.NewProject(domain.ProjectID(id), product, "project-"+id)
		if err != nil {
			return nil, err
		}
		if name != "" && p.Name() != name {
			continue
		}
		out = append(out, p)
	}
	return out, nil
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
	return fmt.Sprintf("id-%d", s.n)
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

// createdOf decodes a find-or-create response. It returns BOTH halves because the whole point
// of the tests below is that the status line and the body agree.
func createdOf(t *testing.T, raw []byte) (string, bool) {
	t.Helper()
	var out struct {
		Id      string `json:"id"`
		Created bool   `json:"created"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode find-or-create response: %v (%s)", err, raw)
	}
	return out.Id, out.Created
}

// assertFindOrCreate POSTs the same body twice and asserts B4's contract at the HTTP edge:
// `201` + `created=true` first, `200` + `created=false` second, one id throughout. It returns
// that id so a caller can build the next level on it.
//
// Consumer compatibility, re-verified 2026-10-12 for this step
// (`rg -n 'api/v1/(products|projects|releases)' scripts tests cmd internal`, frozen legacy tree
// excluded): the only WRITERS of the three routes are scripts/gf-upload-sbom.sh (curl
// `--fail-with-body`, reads `.id` and never inspects the status — `200` is success),
// tests/pipeline/pipeline_test.go (one create per fresh database — still `201`) and these
// tests. scripts/run-alpine-e2e-local.sh posts to the FROZEN v0.3.x monolith on `:8080`
// (`POST /products/{id}/projects`, a route the greenfield Registry does not serve), so it is
// not a consumer of this change. Governance, Communication, Intelligence and the dashboard
// only READ Registry.
func assertFindOrCreate(t *testing.T, url string, body map[string]string) string {
	t.Helper()
	status, raw := post(t, url, body)
	id, created := createdOf(t, raw)
	if status != http.StatusCreated || !created {
		t.Fatalf("first POST %s = %d created=%v, want 201 created=true: %s", url, status, created, raw)
	}
	if id == "" {
		t.Fatalf("first POST %s returned an empty id: %s", url, raw)
	}

	status, raw = post(t, url, body)
	again, created := createdOf(t, raw)
	if status != http.StatusOK || created {
		t.Fatalf("second POST %s = %d created=%v, want 200 created=false: %s", url, status, created, raw)
	}
	if again != id {
		t.Fatalf("second POST %s id = %q, want the existing %q", url, again, id)
	}
	return id
}

func TestCreateProductIs201NewAnd200Existing(t *testing.T) {
	srv := newServer(t, newFakeRepo())
	assertFindOrCreate(t, srv.URL+"/products", map[string]string{"name": "OAMP"})
}

func TestCreateProjectIs201NewAnd200Existing(t *testing.T) {
	srv := newServer(t, newFakeRepo())
	prodID := assertFindOrCreate(t, srv.URL+"/products", map[string]string{"name": "OAMP"})
	assertFindOrCreate(t, srv.URL+"/projects", map[string]string{"product_id": prodID, "name": "core"})
}

func TestCreateReleaseIs201NewAnd200Existing(t *testing.T) {
	srv := newServer(t, newFakeRepo())
	prodID := assertFindOrCreate(t, srv.URL+"/products", map[string]string{"name": "OAMP"})
	projID := assertFindOrCreate(t, srv.URL+"/projects", map[string]string{"product_id": prodID, "name": "core"})
	assertFindOrCreate(t, srv.URL+"/releases", map[string]string{"project_id": projID, "version": "R1917.256"})
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

// DASH-1: the product → project → release traversal a human actually has.
//
// Before this, a release's posture was reachable only by a caller that already held the UUID
// `POST /releases` printed. Every runbook in the repo worked around it by capturing that id, and an
// operator who knew "product mrf, release 20.1.0" had to query Postgres directly — exactly the
// coupling a read API exists to remove.
func TestTraversalEndpoints(t *testing.T) {
	srv := newServer(t, newFakeRepo())

	status, raw := post(t, srv.URL+"/products", map[string]string{"name": "Themis"})
	if status != http.StatusCreated {
		t.Fatalf("register product: %d %s", status, raw)
	}
	prodID := idOf(t, raw)
	status, raw = post(t, srv.URL+"/projects", map[string]string{"product_id": prodID, "name": "api"})
	if status != http.StatusCreated {
		t.Fatalf("register project: %d %s", status, raw)
	}
	projID := idOf(t, raw)
	if status, raw = post(t, srv.URL+"/releases", map[string]string{"project_id": projID, "version": "1.0.0"}); status != http.StatusCreated {
		t.Fatalf("register release: %d %s", status, raw)
	}

	getJSON := func(path string) (int, []map[string]any) {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, nil
		}
		var out []map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode %s: %v (%s)", path, err, body)
		}
		return resp.StatusCode, out
	}

	if code, list := getJSON("/products"); code != http.StatusOK || len(list) != 1 {
		t.Errorf("GET /products = %d %v", code, list)
	}
	if code, list := getJSON("/products/" + prodID + "/projects"); code != http.StatusOK || len(list) != 1 {
		t.Errorf("GET projects = %d %v", code, list)
	}
	if code, list := getJSON("/projects/" + projID + "/releases"); code != http.StatusOK || len(list) != 1 {
		t.Errorf("GET releases = %d %v", code, list)
	}
	// The version filter completes the traversal: "product mrf, release 20.1.0" becomes reachable
	// without anyone holding a UUID.
	if code, list := getJSON("/projects/" + projID + "/releases?version=1.0.0"); code != http.StatusOK || len(list) != 1 {
		t.Errorf("GET releases?version = %d %v", code, list)
	}
	if code, list := getJSON("/projects/" + projID + "/releases?version=9.9.9"); code != http.StatusOK || len(list) != 0 {
		t.Errorf("a non-matching version must return an empty list, got %d %v", code, list)
	}

	// A missing parent is a 404, not an empty 200. "This product has no projects" and "there is no
	// such product" are different answers, and collapsing them sends a caller hunting for a typo
	// in the wrong place.
	if code, _ := getJSON("/products/no-such/projects"); code != http.StatusNotFound {
		t.Errorf("unknown product = %d, want 404", code)
	}
	if code, _ := getJSON("/projects/no-such/releases"); code != http.StatusNotFound {
		t.Errorf("unknown project = %d, want 404", code)
	}
}

// A store failure must surface as a 500 rather than an empty list — an empty list reads as "you
// have no products", which is a very different thing to tell someone.
func TestTraversalEndpoints_StoreFailure(t *testing.T) {
	repo := newFakeRepo()
	repo.listErr = errors.New("db down")
	srv := newServer(t, repo)

	resp, err := http.Get(srv.URL + "/products")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", resp.StatusCode)
	}
}

// The upward name-chain hops (EDR-COMMUNICATION-01 D13.4): a release rollup resolves
// release -> project -> product by name, so both single-item GETs must serve, 404 cleanly,
// and surface store faults as 500s.
func TestGetProjectAndProduct(t *testing.T) {
	repo := newFakeRepo()
	proj, err := domain.NewProject("proj-1", "prod-1", "cdmrf-oamp")
	if err != nil {
		t.Fatal(err)
	}
	prod, err := domain.NewProduct("prod-1", "MRF")
	if err != nil {
		t.Fatal(err)
	}
	repo.projectObjs = map[string]domain.Project{"proj-1": proj}
	repo.productObjs = map[string]domain.Product{"prod-1": prod}
	srv := newServer(t, repo)

	resp, err := http.Get(srv.URL + "/projects/proj-1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get project: %v %d", err, resp.StatusCode)
	}
	var pv struct {
		ID        string `json:"id"`
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pv); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if pv.ID != "proj-1" || pv.ProductID != "prod-1" || pv.Name != "cdmrf-oamp" {
		t.Errorf("project view = %+v", pv)
	}

	resp, err = http.Get(srv.URL + "/products/prod-1")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("get product: %v %d", err, resp.StatusCode)
	}
	var prv struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&prv); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if prv.Name != "MRF" {
		t.Errorf("product view = %+v", prv)
	}

	// Unknowns 404.
	for _, path := range []string{"/projects/ghost", "/products/ghost"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %v %d, want 404", path, err, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func TestGetProjectAndProduct_StoreFaults(t *testing.T) {
	repo := newFakeRepo()
	repo.projErr = errors.New("db down")
	repo.prodErr = errors.New("db down")
	srv := newServer(t, repo)
	for _, path := range []string{"/projects/x", "/products/x"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil || resp.StatusCode != http.StatusInternalServerError {
			t.Errorf("%s: %v %d, want 500", path, err, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

func (r *fakeRepo) TaggedReleases(_ context.Context, tag string) ([]domain.Release, error) {
	if r.tagsErr2 != nil {
		return nil, r.tagsErr2
	}
	var out []domain.Release
	for id, rel := range r.releases {
		for _, t := range r.tags["release/"+id] {
			if t == tag {
				out = append(out, rel)
			}
		}
	}
	return out, nil
}
