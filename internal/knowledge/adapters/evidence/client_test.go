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
			],"dependencies":[
				{"from":"pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10","to":"pkg:pypi/setuptools@39.2.0","relationship":"ownership-by-file-overlap"},
				{"from":"pkg:deb/debian/openssl@3.0.11","to":"pkg:deb/debian/zlib@1.3","relationship":"depends_on"}
			]}`))
		case "/api/v1/evidence/malformed/inventory":
			_, _ = w.Write([]byte(`{not json`))
		case "/api/v1/evidence/ev-1/document":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"kind":"vex","document":"{\"statements\":[]}"}`))
		case "/api/v1/evidence/malformed/document":
			_, _ = w.Write([]byte(`{not json`))
		case "/api/v1/evidence/ev-1":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"kind":"scanner-report","subject_release_id":"rel-1"}`))
		case "/api/v1/evidence/malformed":
			_, _ = w.Write([]byte(`{not json`))
		case "/api/v1/evidence/broken":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestClient_GetDocument(t *testing.T) {
	srv := fakeEvidence(t)
	defer srv.Close()
	c := evidence.NewClient(srv.URL, srv.Client())

	raw, kind, err := c.GetDocument(context.Background(), "ev-1")
	if err != nil {
		t.Fatalf("get document: %v", err)
	}
	if kind != "vex" || string(raw) != `{"statements":[]}` {
		t.Errorf("document = %q kind=%q", raw, kind)
	}
	// An unknown id → non-200 → error (drives the caller's fail-safe).
	if _, _, err := c.GetDocument(context.Background(), "nope"); err == nil {
		t.Error("unknown document must error")
	}
	// A malformed body → decode error.
	if _, _, err := c.GetDocument(context.Background(), "malformed"); err == nil {
		t.Error("malformed document body must error")
	}
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
	// Only ownership edges populate Owners (EDR-VERDICT-01 D3) — depends_on is not ownership.
	if len(inv.Owners) != 1 || inv.Owners["pkg:pypi/setuptools@39.2.0"] != "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10" {
		t.Errorf("owners = %+v, want the one ownership edge, owned->owner", inv.Owners)
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

// EvidenceFacts resolves an evidence id to its kind and subject release (EDR-IDENTITY-01 D6),
// so the unresolved-components query needs only the id the upload already returned.
func TestClient_EvidenceFacts(t *testing.T) {
	srv := fakeEvidence(t)
	defer srv.Close()
	c := evidence.NewClient(srv.URL, srv.Client())

	kind, release, found, err := c.EvidenceFacts(context.Background(), "ev-1")
	if err != nil || !found {
		t.Fatalf("facts = %v/%v, want found", found, err)
	}
	if kind != "scanner-report" || release != "rel-1" {
		t.Errorf("kind=%q release=%q, want scanner-report/rel-1", kind, release)
	}
	// An unknown id is NOT an error: the caller must distinguish "no such document" from "the
	// document has nothing unresolved", and a 404 answered as an error would collapse the two.
	if _, _, found, err := c.EvidenceFacts(context.Background(), "nope"); err != nil || found {
		t.Errorf("unknown id = %v/%v, want found=false with no error", found, err)
	}
	// Any other non-200 IS an error — a broken Evidence must never read as "all clear".
	if _, _, _, err := c.EvidenceFacts(context.Background(), "broken"); err == nil {
		t.Error("a 500 from Evidence must surface as an error")
	}
	if _, _, _, err := c.EvidenceFacts(context.Background(), "malformed"); err == nil {
		t.Error("a malformed body must surface as an error")
	}
}
