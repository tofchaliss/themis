package registry_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/registry"
	"github.com/themis-project/themis/internal/communication/app"
)

// nameChain serves the three-hop walk, with per-path overrides for the failure cases.
func nameChain(t *testing.T, overrides map[string]string) *httptest.Server {
	t.Helper()
	bodies := map[string]string{
		"/api/v1/releases/rel-1":  `{"id":"rel-1","project_id":"proj-1","version":"20.1.0.0-118"}`,
		"/api/v1/projects/proj-1": `{"id":"proj-1","product_id":"prod-1","name":"cdmrf-oamp"}`,
		"/api/v1/products/prod-1": `{"id":"prod-1","name":"MRF"}`,
	}
	for k, v := range overrides {
		bodies[k] = v
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := bodies[r.URL.Path]
		if !ok || body == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestReleaseIdentity(t *testing.T) {
	srv := nameChain(t, nil)
	ref, err := registry.NewClient(srv.URL, srv.Client()).ReleaseIdentity(context.Background(), "rel-1")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if ref.Product != "MRF" || ref.Project != "cdmrf-oamp" || ref.Version != "20.1.0.0-118" || ref.ReleaseID != "rel-1" {
		t.Errorf("ref = %+v", ref)
	}
	if ref.PURL() != "pkg:generic/MRF/cdmrf-oamp@20.1.0.0-118" {
		t.Errorf("purl = %q", ref.PURL())
	}
}

// D13.4 fail-closed: ANY missing hop or blank name refuses the whole identity, and the error
// carries ErrIncompleteIdentity so the transport layer can say why with a 422.
func TestReleaseIdentity_FailsClosed(t *testing.T) {
	for name, overrides := range map[string]map[string]string{
		"release missing": {"/api/v1/releases/rel-1": ""},
		"project missing": {"/api/v1/projects/proj-1": ""},
		"product missing": {"/api/v1/products/prod-1": ""},
		"blank product name": {"/api/v1/products/prod-1": `{"id":"prod-1","name":"  "}`},
		"blank version":      {"/api/v1/releases/rel-1": `{"id":"rel-1","project_id":"proj-1","version":""}`},
		"malformed hop":      {"/api/v1/projects/proj-1": `{`},
	} {
		srv := nameChain(t, overrides)
		_, err := registry.NewClient(srv.URL, srv.Client()).ReleaseIdentity(context.Background(), "rel-1")
		if !errors.Is(err, app.ErrIncompleteIdentity) {
			t.Errorf("%s: err = %v, want ErrIncompleteIdentity", name, err)
		}
	}
	// A dead Registry fails closed too.
	if _, err := registry.NewClient("http://127.0.0.1:1", nil).ReleaseIdentity(context.Background(), "rel-1"); !errors.Is(err, app.ErrIncompleteIdentity) {
		t.Errorf("dead registry: %v", err)
	}
}

// --- Auth-enabled estate: the name chain carries X-API-Key -----------------------------------

const readKey = "read-scoped-key-abc123"

// authedNameChain answers 401 to any hop that does not carry the expected key — a Registry node
// running with THEMIS_AUTH_REQUIRED=1.
func authedNameChain(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	refused := 0
	bodies := map[string]string{
		"/api/v1/releases/rel-1":  `{"id":"rel-1","project_id":"proj-1","version":"20.1.0.0-118"}`,
		"/api/v1/projects/proj-1": `{"id":"proj-1","product_id":"prod-1","name":"cdmrf-oamp"}`,
		"/api/v1/products/prod-1": `{"id":"prod-1","name":"MRF"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != readKey {
			refused++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &refused
}

// WITH the key all three hops authenticate, so a release can still be named on an auth-enabled
// estate. All three matter: the walk fails closed, so one unauthenticated hop refuses the identity.
func TestReleaseIdentityCarriesTheAPIKeyWhenAuthIsOn(t *testing.T) {
	srv, refused := authedNameChain(t)
	ref, err := registry.NewClient(srv.URL, srv.Client()).WithAPIKey(readKey).
		ReleaseIdentity(context.Background(), "rel-1")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if ref.Product != "MRF" || ref.Project != "cdmrf-oamp" || ref.Version != "20.1.0.0-118" {
		t.Errorf("ref = %+v", ref)
	}
	if *refused != 0 {
		t.Errorf("%d hop(s) were refused — the walk fails closed, so one is all it takes", *refused)
	}
}

// WITHOUT the key the identity refuses — fail-closed, as D13.4 requires — and the error says that
// the hop was UNAUTHENTICATED. A 401 read as "this product has no name" is the worst reading
// available: it looks like estate data is missing when a variable is unset.
func TestReleaseIdentityWithoutTheAPIKeyFailsClosedAndSaysWhy(t *testing.T) {
	srv, _ := authedNameChain(t)
	_, err := registry.NewClient(srv.URL, srv.Client()).ReleaseIdentity(context.Background(), "rel-1")
	if !errors.Is(err, app.ErrIncompleteIdentity) {
		t.Fatalf("err = %v, want ErrIncompleteIdentity", err)
	}
	for _, want := range []string{"401", "sent no X-API-Key", "THEMIS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}

	stale, err := registry.NewClient(srv.URL, srv.Client()).WithAPIKey("stale-key").
		ReleaseIdentity(context.Background(), "rel-1")
	if err == nil {
		t.Fatalf("a refused key must fail, got %+v", stale)
	}
	if !strings.Contains(err.Error(), "Registry refused") {
		t.Errorf("err = %v, want it to distinguish a refused key from an absent one", err)
	}
	if strings.Contains(err.Error(), "stale-key") {
		t.Errorf("err = %v leaked the credential", err)
	}
}
