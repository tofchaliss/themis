package http_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/platform/auth"
	reghttp "github.com/themis-project/themis/internal/registry/adapters/http"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

// estate is a two-product Registry: the key under test owns MRF, and OAMP is someone else's.
type estate struct {
	repo                    *fakeRepo
	mrf, oamp               string // product ids
	mrfProject, oampProject string
}

// seedEstate registers both products and one project under each, then mirrors them into the
// fake's read maps so GetProduct / GetProject see what the upserts wrote.
func seedEstate(t *testing.T) estate {
	t.Helper()
	repo := newFakeRepo()
	repo.productObjs = map[string]domain.Product{}
	repo.projectObjs = map[string]domain.Project{}
	srv := newServer(t, repo)

	e := estate{repo: repo}
	_, raw := post(t, srv.URL+"/products", map[string]string{"name": "MRF"})
	e.mrf = idOf(t, raw)
	_, raw = post(t, srv.URL+"/products", map[string]string{"name": "OAMP"})
	e.oamp = idOf(t, raw)
	_, raw = post(t, srv.URL+"/projects", map[string]string{"product_id": e.mrf, "name": "cdmrf-oamp"})
	e.mrfProject = idOf(t, raw)
	_, raw = post(t, srv.URL+"/projects", map[string]string{"product_id": e.oamp, "name": "core"})
	e.oampProject = idOf(t, raw)

	for id, name := range map[string]string{e.mrf: "MRF", e.oamp: "OAMP"} {
		p, err := domain.NewProduct(domain.ProductID(id), name)
		if err != nil {
			t.Fatal(err)
		}
		repo.productObjs[id] = p
	}
	for id, prod := range map[string]string{e.mrfProject: e.mrf, e.oampProject: e.oamp} {
		p, err := domain.NewProject(domain.ProjectID(id), domain.ProductID(prod), "p-"+id)
		if err != nil {
			t.Fatal(err)
		}
		repo.projectObjs[id] = p
	}
	return e
}

// serverAs serves the Registry with every request authenticated as p, standing in for the
// RequireAPIKey middleware the composition root mounts in front of it.
func serverAs(t *testing.T, repo app.Repository, p auth.Principal) *httptest.Server {
	t.Helper()
	inner := reghttp.NewHandler(app.NewRegistryService(repo, &seqIDs{})).Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), p)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func productKey(productID string) auth.Principal {
	return auth.Principal{KeyID: "k-1", Name: "jenkins", Scopes: []string{auth.ProductScopePrefix + productID}}
}

func wantForbidden(t *testing.T, what string, status int, raw []byte) {
	t.Helper()
	if status != http.StatusForbidden {
		t.Fatalf("%s = %d, want 403: %s", what, status, raw)
	}
}

// TestProductKeyRegistersOnlyUnderItsOwnProduct is the gap this closes: a product:<MRF> key
// could create projects, releases and microservices under ANY product, because Registry
// checked only that the key could write at all.
func TestProductKeyRegistersOnlyUnderItsOwnProduct(t *testing.T) {
	e := seedEstate(t)
	srv := serverAs(t, e.repo, productKey(e.mrf))

	// Its own product: find-or-create works exactly as for an admin.
	assertFindOrCreate(t, srv.URL+"/projects", map[string]string{"product_id": e.mrf, "name": "new-image"})
	assertFindOrCreate(t, srv.URL+"/releases", map[string]string{"project_id": e.mrfProject, "version": "oamp_1917_258_1"})
	if status, raw := post(t, srv.URL+"/products/"+e.mrf+"/microservices", map[string]string{"name": "oamp-svc"}); status != http.StatusCreated {
		t.Fatalf("own microservice = %d, want 201: %s", status, raw)
	}

	// Someone else's product: refused, and nothing is written.
	rows := e.repo.rows
	status, raw := post(t, srv.URL+"/projects", map[string]string{"product_id": e.oamp, "name": "sneaky"})
	wantForbidden(t, "project under a foreign product", status, raw)
	status, raw = post(t, srv.URL+"/releases", map[string]string{"project_id": e.oampProject, "version": "R1"})
	wantForbidden(t, "release under a foreign project", status, raw)
	status, raw = post(t, srv.URL+"/products/"+e.oamp+"/microservices", map[string]string{"name": "sneaky"})
	wantForbidden(t, "microservice under a foreign product", status, raw)
	if e.repo.rows != rows {
		t.Fatalf("a refused write created %d row(s)", e.repo.rows-rows)
	}
}

// TestProductKeyRefusalLeaksNoExistence: for a confined key, a product or project that does
// not exist is the SAME answer, byte for byte, as one that belongs to someone else — the rule
// the intake door already keeps (EDR-INTAKE-01 B3).
func TestProductKeyRefusalLeaksNoExistence(t *testing.T) {
	e := seedEstate(t)
	srv := serverAs(t, e.repo, productKey(e.mrf))

	_, foreign := post(t, srv.URL+"/projects", map[string]string{"product_id": e.oamp, "name": "x"})
	status, missing := post(t, srv.URL+"/projects", map[string]string{"product_id": "no-such-product", "name": "x"})
	wantForbidden(t, "project under a missing product", status, missing)
	if string(foreign) != string(missing) {
		t.Fatalf("foreign and missing product differ:\n%s\n%s", foreign, missing)
	}

	_, foreignProj := post(t, srv.URL+"/releases", map[string]string{"project_id": e.oampProject, "version": "R1"})
	status, missingProj := post(t, srv.URL+"/releases", map[string]string{"project_id": "no-such-project", "version": "R1"})
	wantForbidden(t, "release under a missing project", status, missingProj)
	if string(foreignProj) != string(missingProj) {
		t.Fatalf("foreign and missing project differ:\n%s\n%s", foreignProj, missingProj)
	}
	if string(foreign) != string(foreignProj) {
		t.Fatalf("the product and project refusals differ:\n%s\n%s", foreign, foreignProj)
	}

	status, raw := post(t, srv.URL+"/projects", map[string]string{"product_id": "", "name": "x"})
	wantForbidden(t, "project under an empty product id", status, raw)
}

// TestProductKeyNeverCreatesAProduct: naming its own product (any case) is find-or-create's
// 200 with the existing id, so gf-upload-sbom.sh keeps working with a product key; any other
// name is 403 whether or not it exists, and nothing is created.
func TestProductKeyNeverCreatesAProduct(t *testing.T) {
	e := seedEstate(t)
	srv := serverAs(t, e.repo, productKey(e.mrf))

	status, raw := post(t, srv.URL+"/products", map[string]string{"name": " mrf "})
	id, created := createdOf(t, raw)
	if status != http.StatusOK || created || id != e.mrf {
		t.Fatalf("own product = %d created=%v id=%q, want 200 created=false id=%q: %s", status, created, id, e.mrf, raw)
	}

	rows := e.repo.rows
	_, foreign := post(t, srv.URL+"/products", map[string]string{"name": "OAMP"})
	status, missing := post(t, srv.URL+"/products", map[string]string{"name": "Brand-New"})
	wantForbidden(t, "a new product", status, missing)
	if string(foreign) != string(missing) {
		t.Fatalf("existing and new foreign product differ:\n%s\n%s", foreign, missing)
	}
	if e.repo.rows != rows {
		t.Fatalf("a product key created %d product(s)", e.repo.rows-rows)
	}

	// A key whose product cannot be read is refused, not waved through.
	e.repo.prodErr = errors.New("db down")
	status, raw = post(t, srv.URL+"/products", map[string]string{"name": "MRF"})
	wantForbidden(t, "own product while the store is failing", status, raw)
}

// TestProductKeyIsRefusedEstateWideWrites: customers and deployments belong to no single
// product, so only an admin key may write them.
func TestProductKeyIsRefusedEstateWideWrites(t *testing.T) {
	e := seedEstate(t)
	srv := serverAs(t, e.repo, productKey(e.mrf))

	status, raw := post(t, srv.URL+"/customers", map[string]string{"name": "acme"})
	wantForbidden(t, "customer", status, raw)
	if !strings.Contains(string(raw), "admin key") {
		t.Fatalf("estate-wide refusal should say an admin key is needed: %s", raw)
	}
	status, raw = post(t, srv.URL+"/microservices/ms-1/deployments", map[string]string{"customer_id": "c-1", "environment": "prod"})
	wantForbidden(t, "deployment", status, raw)
}

// TestAdminKeyIsUnconfined: an admin key keeps every write, including the 422s that name an
// unknown parent — confinement changes nothing for it.
func TestAdminKeyIsUnconfined(t *testing.T) {
	e := seedEstate(t)
	srv := serverAs(t, e.repo, auth.Principal{KeyID: "k-0", Scopes: []string{auth.ScopeAdmin}})

	assertFindOrCreate(t, srv.URL+"/products", map[string]string{"name": "Third"})
	assertFindOrCreate(t, srv.URL+"/projects", map[string]string{"product_id": e.oamp, "name": "admin-made"})
	if status, raw := post(t, srv.URL+"/projects", map[string]string{"product_id": "no-such-product", "name": "x"}); status != http.StatusUnprocessableEntity {
		t.Fatalf("admin, missing product = %d, want 422: %s", status, raw)
	}
	if status, raw := post(t, srv.URL+"/customers", map[string]string{"name": "acme"}); status != http.StatusCreated {
		t.Fatalf("admin customer = %d, want 201: %s", status, raw)
	}
}
