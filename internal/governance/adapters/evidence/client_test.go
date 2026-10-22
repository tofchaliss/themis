package evidence_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/governance/adapters/evidence"
)

func TestClient_HasEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/evidence" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.URL.Query().Get("release") {
		case "rel-with":
			_, _ = w.Write([]byte(`[{"id":"ev-1","kind":"sbom"}]`))
		case "rel-without":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()

	c := evidence.NewClient(srv.URL, srv.Client())
	if has, err := c.HasEvidence(context.Background(), "rel-with"); err != nil || !has {
		t.Errorf("rel-with: has=%v err=%v", has, err)
	}
	if has, err := c.HasEvidence(context.Background(), "rel-without"); err != nil || has {
		t.Errorf("rel-without: has=%v err=%v", has, err)
	}
	// A non-200 is an error, never a false — the compare guard fails closed on it.
	if _, err := c.HasEvidence(context.Background(), "rel-err"); err == nil {
		t.Error("non-200 must return an error")
	}
}

func TestClient_DefaultHTTPClientAndDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not-json`))
	}))
	defer srv.Close()

	c := evidence.NewClient(srv.URL, nil) // nil hc → http.DefaultClient
	if _, err := c.HasEvidence(context.Background(), "rel-1"); err == nil {
		t.Error("malformed JSON must return a decode error")
	}
}

func TestClient_TransportError(t *testing.T) {
	c := evidence.NewClient("http://127.0.0.1:1", nil) // nothing listens here
	if _, err := c.HasEvidence(context.Background(), "rel-1"); err == nil {
		t.Error("transport failure must return an error")
	}
}

func TestClient_SBOMsAndInventory(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/evidence":
			_, _ = w.Write([]byte(`[{"id":"sb-1","kind":"sbom","filed_at":"2026-10-01T00:00:00Z"},{"id":"sr-1","kind":"scanner-report","filed_at":"2026-10-02T00:00:00Z"},{"id":"","kind":"sbom"}]`))
		case "/api/v1/evidence/sb-1/inventory":
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:a@1"},{"purl":""},{"purl":"pkg:b@2"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := evidence.NewClient(srv.URL, srv.Client())
	refs, err := c.SBOMsOfRelease(context.Background(), "rel-1")
	if err != nil || len(refs) != 1 || refs[0].ID != "sb-1" || refs[0].FiledAt.Day() != 1 {
		t.Fatalf("refs = %+v %v", refs, err)
	}
	inv, err := c.InventoryPURLs(context.Background(), "sb-1")
	if err != nil || len(inv) != 2 || !inv["pkg:a@1"] || !inv["pkg:b@2"] {
		t.Fatalf("inventory = %v %v", inv, err)
	}
	if _, err := c.InventoryPURLs(context.Background(), "missing"); err == nil {
		t.Fatal("404 must be an error")
	}
	bad := evidence.NewClient("http://127.0.0.1:1", nil)
	if _, err := bad.SBOMsOfRelease(context.Background(), "rel-1"); err == nil {
		t.Fatal("transport error swallowed")
	}
	if _, err := evidence.NewClient("://bad", nil).InventoryPURLs(context.Background(), "x"); err == nil {
		t.Fatal("bad URL swallowed")
	}
	dec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{not-json`)) }))
	defer dec.Close()
	if _, err := evidence.NewClient(dec.URL, nil).SBOMsOfRelease(context.Background(), "rel-1"); err == nil {
		t.Fatal("decode error swallowed")
	}
}
