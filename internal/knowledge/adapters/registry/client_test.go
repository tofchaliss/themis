package registry_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/registry"
)

// EDR-PSIRT-01 P2: the walk maps every release to its product, carries the key, and any failed
// hop is an error (a partial estate would read as "no product matched").
func TestReleaseProducts(t *testing.T) {
	var keys []string
	fail := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("X-API-Key"))
		if fail != "" && strings.HasPrefix(r.URL.Path, fail) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		switch r.URL.Path {
		case "/api/v1/products":
			_, _ = w.Write([]byte(`[{"id":"p1","name":"product-a"}]`))
		case "/api/v1/products/p1/projects":
			_, _ = w.Write([]byte(`[{"id":"j1","name":"project-a"},{"id":"j2","name":"project-b"}]`))
		case "/api/v1/projects/j1/releases":
			_, _ = w.Write([]byte(`[{"id":"r1"},{"id":"r2"}]`))
		case "/api/v1/projects/j2/releases":
			_, _ = w.Write([]byte(`[{"id":"r3"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := registry.NewClient(srv.URL+"/", nil).WithAPIKey(" k1 ")
	got, err := c.ReleaseProducts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["r1"].ID != "p1" || got["r3"].Name != "product-a" {
		t.Errorf("releases = %+v", got)
	}
	for _, k := range keys {
		if k != "k1" {
			t.Fatalf("every read carries the trimmed key, got %q", k)
		}
	}
	for _, path := range []string{"/api/v1/products/p1", "/api/v1/projects/j2", "/api/v1/products"} {
		fail = path
		if _, err := c.ReleaseProducts(context.Background()); err == nil {
			t.Errorf("a failing %s must be an error", path)
		}
	}
}

// A 401/403 names the likely cause: no key sent, or a key Registry refused.
func TestReleaseProductsCredentialHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := registry.NewClient(srv.URL, nil).ReleaseProducts(context.Background()); err == nil || !strings.Contains(err.Error(), "sent no X-API-Key") {
		t.Errorf("no key: %v", err)
	}
	if _, err := registry.NewClient(srv.URL, nil).WithAPIKey("k").ReleaseProducts(context.Background()); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("refused key: %v", err)
	}
	if _, err := registry.NewClient("http://127.0.0.1:0", nil).ReleaseProducts(context.Background()); err == nil {
		t.Error("an unreachable Registry must be an error")
	}
	if _, err := registry.NewClient("http://bad host", nil).ReleaseProducts(context.Background()); err == nil {
		t.Error("an unbuildable request must be an error")
	}
}
