package evidence_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
		case "/api/v1/evidence":
			switch r.URL.Query().Get("release") {
			case "rel-1":
				// Deliberately OLDEST first and with a non-SBOM newest, so the pick is by
				// kind + filed_at, not by list position.
				_, _ = w.Write([]byte(`[
					{"id":"ev-old","kind":"sbom","filed_at":"2026-10-01T00:00:00Z"},
					{"id":"ev-new","kind":"sbom","filed_at":"2026-10-27T00:00:00Z"},
					{"id":"ev-report","kind":"scanner-report","filed_at":"2026-10-28T00:00:00Z"}
				]`))
			case "rel-scan-only":
				_, _ = w.Write([]byte(`[{"id":"ev-report","kind":"scanner-report","filed_at":"2026-10-28T00:00:00Z"}]`))
			case "malformed":
				_, _ = w.Write([]byte(`{not json`))
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
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

// --- Auth-enabled estate: every read carries X-API-Key ---------------------------------------

const readKey = "read-scoped-key-abc123"

// authedEvidence answers 401 to any request that does not carry the expected key — an Evidence
// node running with THEMIS_AUTH_DATABASE_DSN set (EDR-SECURITY-01 F1). It records the header it
// saw on each request, so the absent-key case can be asserted as an ABSENT header rather than
// merely a refused call.
func authedEvidence(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("X-API-Key"))
		if r.Header.Get("X-API-Key") != readKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/v1/evidence/ev-1/inventory":
			_, _ = w.Write([]byte(`{"components":[{"purl":"pkg:deb/debian/openssl@3.0.11"}]}`))
		case "/api/v1/evidence/ev-1/document":
			_, _ = w.Write([]byte(`{"kind":"vex","document":"{}"}`))
		case "/api/v1/evidence/ev-1":
			_, _ = w.Write([]byte(`{"kind":"sbom","subject_release_id":"rel-1"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// WITH the key every read authenticates, so correlation still gets its inventory on an
// auth-enabled estate. All three reads matter: they are the inputs of correlation, of the
// uploaded-VEX fold and of the unresolved-components query, and one unauthenticated read is
// enough to make an upload correlate to nothing.
func TestClientSendsAPIKeyWhenSet(t *testing.T) {
	srv, seen := authedEvidence(t)
	c := evidence.NewClient(srv.URL, srv.Client()).WithAPIKey("  " + readKey + "\n") // whitespace is trimmed

	if _, err := c.GetInventory(context.Background(), "ev-1"); err != nil {
		t.Errorf("inventory: %v", err)
	}
	if _, _, err := c.GetDocument(context.Background(), "ev-1"); err != nil {
		t.Errorf("document: %v", err)
	}
	if _, _, found, err := c.EvidenceFacts(context.Background(), "ev-1"); err != nil || !found {
		t.Errorf("facts = %v/%v", found, err)
	}
	if len(*seen) != 3 {
		t.Fatalf("saw %d requests, want 3", len(*seen))
	}
	for i, got := range *seen {
		if got != readKey {
			t.Errorf("request %d sent X-API-Key %q, want the configured key", i, got)
		}
	}
}

// WITHOUT the key the header is ABSENT (not present-and-empty), the reads fail, and the error
// says the read was unauthenticated and names the variable. A 401 read as "this release has no
// inventory" is the worst reading available: the estate looks clean while nothing correlates.
func TestClientSendsNoAPIKeyWhenUnsetAndSaysWhyOn401(t *testing.T) {
	srv, seen := authedEvidence(t)
	c := evidence.NewClient(srv.URL, srv.Client())

	_, err := c.GetInventory(context.Background(), "ev-1")
	if err == nil {
		t.Fatal("an unauthenticated inventory read must fail")
	}
	for _, want := range []string{"401", "sent no X-API-Key", "THEMIS_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
	if len(*seen) != 1 || (*seen)[0] != "" {
		t.Errorf("headers seen = %q, want one request carrying no X-API-Key", *seen)
	}
	// The other two reads say the same thing, because the remedy is the same variable.
	if _, _, derr := c.GetDocument(context.Background(), "ev-1"); derr == nil ||
		!strings.Contains(derr.Error(), "THEMIS_API_KEY") {
		t.Errorf("document err = %v, want the credential hint", derr)
	}
	if _, _, _, ferr := c.EvidenceFacts(context.Background(), "ev-1"); ferr == nil ||
		!strings.Contains(ferr.Error(), "THEMIS_API_KEY") {
		t.Errorf("facts err = %v, want the credential hint", ferr)
	}

	// A key Evidence REFUSES is a different operator problem from an absent one, and the error
	// distinguishes them — without ever echoing the credential.
	_, err = evidence.NewClient(srv.URL, srv.Client()).WithAPIKey("stale-key").
		GetInventory(context.Background(), "ev-1")
	if err == nil || !strings.Contains(err.Error(), "Evidence refused") {
		t.Errorf("err = %v, want it to distinguish a refused key from an absent one", err)
	}
	if strings.Contains(err.Error(), "stale-key") {
		t.Errorf("err = %v leaked the credential", err)
	}
}

// A 404 or a 500 carries NO credential hint: naming a variable that is already set correctly
// would send an operator after the wrong thing.
func TestClientCredentialHintOnlyOnAuthFailures(t *testing.T) {
	srv := fakeEvidence(t)
	defer srv.Close()
	_, err := evidence.NewClient(srv.URL, srv.Client()).WithAPIKey(readKey).
		GetInventory(context.Background(), "missing")
	if err == nil || strings.Contains(err.Error(), "THEMIS_API_KEY") {
		t.Errorf("err = %v, want a plain 404 with no credential advice", err)
	}
}

// SBOMForRelease (KN-SCAN-RACE-1) names the release's newest filed SBOM from Evidence's list
// read, so a scanner report that arrives before correlation completes still has candidates.
func TestClient_SBOMForRelease(t *testing.T) {
	srv := fakeEvidence(t)
	defer srv.Close()
	c := evidence.NewClient(srv.URL, srv.Client())

	id, found, err := c.SBOMForRelease(context.Background(), "rel-1")
	if err != nil || !found || id != "ev-new" {
		t.Fatalf("SBOMForRelease = %q/%v/%v, want ev-new (newest SBOM, not the newest document)", id, found, err)
	}
	// A release with only a scanner report is NOT an error: found=false is the scanner-only case.
	if _, found, err := c.SBOMForRelease(context.Background(), "rel-scan-only"); err != nil || found {
		t.Errorf("scanner-only release = %v/%v, want found=false with no error", found, err)
	}
	if _, _, err := c.SBOMForRelease(context.Background(), "malformed"); err == nil {
		t.Error("a malformed body must surface as an error")
	}
	if _, _, err := c.SBOMForRelease(context.Background(), "broken"); err == nil {
		t.Error("a 500 from Evidence must surface as an error")
	}
	if _, _, err := evidence.NewClient("http://127.0.0.1:1", nil).SBOMForRelease(context.Background(), "rel-1"); err == nil {
		t.Error("unreachable evidence: expected error")
	}
}
