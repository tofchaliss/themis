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
