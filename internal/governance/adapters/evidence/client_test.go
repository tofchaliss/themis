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
