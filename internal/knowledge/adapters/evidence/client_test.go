package evidence_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/evidence"
)

func fakeEvidence(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/evidence/ev-1/inventory":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"components":[
				{"purl":"pkg:deb/debian/openssl@3.0.11","name":"openssl","version":"3.0.11","ecosystem":"deb"},
				{"purl":"pkg:deb/debian/zlib@1.3","name":"zlib","version":"1.3","ecosystem":"deb"}
			]}`))
		case "/api/v1/evidence/malformed/inventory":
			_, _ = w.Write([]byte(`{not json`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestClient_GetInventory(t *testing.T) {
	srv := fakeEvidence(t)
	defer srv.Close()
	c := evidence.NewClient(srv.URL+"/", srv.Client()) // trailing slash is trimmed

	inv, err := c.GetInventory(context.Background(), "ev-1")
	if err != nil {
		t.Fatalf("get inventory: %v", err)
	}
	if len(inv.Components) != 2 {
		t.Fatalf("components = %d, want 2", len(inv.Components))
	}
	if inv.Components[0].PURL != "pkg:deb/debian/openssl@3.0.11" || inv.Components[0].Ecosystem != "deb" {
		t.Errorf("component[0] = %+v", inv.Components[0])
	}
}

func TestClient_Errors(t *testing.T) {
	srv := fakeEvidence(t)
	defer srv.Close()

	// Non-200 (unknown id) → error.
	if _, err := evidence.NewClient(srv.URL, srv.Client()).GetInventory(context.Background(), "missing"); err == nil {
		t.Error("missing evidence: expected error")
	}
	// Malformed JSON → decode error.
	if _, err := evidence.NewClient(srv.URL, srv.Client()).GetInventory(context.Background(), "malformed"); err == nil {
		t.Error("malformed body: expected error")
	}
	// Transport error (unreachable) — nil client falls back to the default client.
	if _, err := evidence.NewClient("http://127.0.0.1:1", nil).GetInventory(context.Background(), "ev-1"); err == nil {
		t.Error("unreachable evidence: expected error")
	}
}
