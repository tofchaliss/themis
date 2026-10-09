package registry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/governance/adapters/registry"
)

func TestClient_BlastRadius(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/releases/rel-1/blast-radius" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"release_id":"rel-1","unique_customers":7}`))
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL, srv.Client())
	n, err := c.BlastRadius(context.Background(), "rel-1")
	if err != nil {
		t.Fatalf("BlastRadius: %v", err)
	}
	if n != 7 {
		t.Errorf("unique customers = %d, want 7", n)
	}

	// A non-200 surfaces as an error (the read side then fail-safes to a 1.0× multiplier).
	if _, err := c.BlastRadius(context.Background(), "missing"); err == nil {
		t.Error("non-200 must return an error")
	}
}

func TestClient_DefaultHTTPClientAndDecodeError(t *testing.T) {
	// nil http client → the default is used (no panic); a malformed body → a decode error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL, nil) // nil hc → http.DefaultClient
	if _, err := c.BlastRadius(context.Background(), "rel-1"); err == nil {
		t.Error("malformed JSON must return a decode error")
	}
}

func TestClient_TransportError(t *testing.T) {
	// Point at a server that is already closed → connection refused → the Do error propagates
	// (the read side then fail-safes to a 1.0× multiplier).
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	if _, err := registry.NewClient(url, nil).BlastRadius(context.Background(), "rel-1"); err == nil {
		t.Error("transport error must propagate")
	}
}

// The release → project → product hop under product-scope confinement (EDR-DELIVERY-01 N-M0).
// It fails CLOSED at every step: a blank hop must be an error, never an empty product id, which
// would compare equal to a blank scope at the authorization site.
func TestClient_ProductOfRelease(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/releases/rel-1":
			_, _ = w.Write([]byte(`{"id":"rel-1","project_id":"prj-1","version":"1.2.3"}`))
		case "/api/v1/projects/prj-1":
			_, _ = w.Write([]byte(`{"id":"prj-1","product_id":"prod-1","name":"payments"}`))
		case "/api/v1/releases/rel-blank":
			_, _ = w.Write([]byte(`{"id":"rel-blank"}`))
		case "/api/v1/releases/rel-2":
			_, _ = w.Write([]byte(`{"id":"rel-2","project_id":"prj-blank"}`))
		case "/api/v1/projects/prj-blank":
			_, _ = w.Write([]byte(`{"id":"prj-blank","name":"orphan"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL, srv.Client())
	got, err := c.ProductOfRelease(context.Background(), "rel-1")
	if err != nil {
		t.Fatalf("ProductOfRelease: %v", err)
	}
	if got != "prod-1" {
		t.Errorf("product = %q, want prod-1", got)
	}
	if len(paths) != 2 || paths[0] != "/api/v1/releases/rel-1" || paths[1] != "/api/v1/projects/prj-1" {
		t.Errorf("hops = %v, want release then project", paths)
	}

	for _, tc := range []struct{ name, release string }{
		{"no release id", ""},
		{"release unknown", "missing"},
		{"release without a project", "rel-blank"},
		{"project without a product", "rel-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := c.ProductOfRelease(context.Background(), tc.release)
			if err == nil {
				t.Fatalf("want an error, got product %q", p)
			}
			if p != "" {
				t.Errorf("a failed resolution must return no product, got %q", p)
			}
		})
	}
}

// ProductAndProjectOfRelease is the same two hops returning BOTH ids (EDR-DELIVERY-01 N-M2b):
// `governance.release_evaluated.v1` names the project as well as the product, and the project id
// is read on the way to the product anyway. It fails closed identically — a release-evaluation
// published with a blank id would state that the Release belongs to nothing.
func TestClient_ProductAndProjectOfRelease(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/api/v1/releases/rel-1":
			_, _ = w.Write([]byte(`{"id":"rel-1","project_id":"prj-1","version":"1.2.3"}`))
		case "/api/v1/projects/prj-1":
			_, _ = w.Write([]byte(`{"id":"prj-1","product_id":"prod-1","name":"payments"}`))
		case "/api/v1/releases/rel-blank":
			_, _ = w.Write([]byte(`{"id":"rel-blank"}`))
		case "/api/v1/releases/rel-2":
			_, _ = w.Write([]byte(`{"id":"rel-2","project_id":"prj-blank"}`))
		case "/api/v1/projects/prj-blank":
			_, _ = w.Write([]byte(`{"id":"prj-blank","name":"orphan"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL, srv.Client())
	product, project, err := c.ProductAndProjectOfRelease(context.Background(), "rel-1")
	if err != nil {
		t.Fatalf("ProductAndProjectOfRelease: %v", err)
	}
	if product != "prod-1" || project != "prj-1" {
		t.Errorf("ids = %q/%q, want prod-1/prj-1", product, project)
	}
	// Two hops, no third: the project id comes from the release read that was needed anyway.
	if len(paths) != 2 || paths[0] != "/api/v1/releases/rel-1" || paths[1] != "/api/v1/projects/prj-1" {
		t.Errorf("hops = %v, want release then project", paths)
	}

	for _, tc := range []struct{ name, release string }{
		{"no release id", ""},
		{"release unknown", "missing"},
		{"release without a project", "rel-blank"},
		{"project without a product", "rel-2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			product, project, err := c.ProductAndProjectOfRelease(context.Background(), tc.release)
			if err == nil {
				t.Fatalf("want an error, got %q/%q", product, project)
			}
			if product != "" || project != "" {
				t.Errorf("a failed resolution must return no ids, got %q/%q", product, project)
			}
		})
	}
}

func TestClient_ProductAndProjectOfRelease_TransportAndDecodeErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer bad.Close()
	if _, _, err := registry.NewClient(bad.URL, nil).ProductAndProjectOfRelease(context.Background(), "rel-1"); err == nil {
		t.Error("malformed JSON must return a decode error")
	}

	// The SECOND hop's failures, separately: the release read succeeds and the project read
	// does not, which is the path a blanket error never reaches.
	var projectBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/releases/rel-1" {
			_, _ = w.Write([]byte(`{"project_id":"prj-1"}`))
			return
		}
		_, _ = w.Write([]byte(projectBody))
	}))
	defer srv.Close()
	projectBody = `{not-json`
	if _, _, err := registry.NewClient(srv.URL, srv.Client()).ProductAndProjectOfRelease(context.Background(), "rel-1"); err == nil {
		t.Error("a malformed project body must return a decode error")
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := closed.URL
	closed.Close()
	if _, _, err := registry.NewClient(url, nil).ProductAndProjectOfRelease(context.Background(), "rel-1"); err == nil {
		t.Error("transport error must propagate")
	}
}

func TestClient_ProductOfRelease_TransportAndDecodeErrors(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer bad.Close()
	if _, err := registry.NewClient(bad.URL, nil).ProductOfRelease(context.Background(), "rel-1"); err == nil {
		t.Error("malformed JSON must return a decode error")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	if _, err := registry.NewClient(url, nil).ProductOfRelease(context.Background(), "rel-1"); err == nil {
		t.Error("transport error must propagate")
	}
}
