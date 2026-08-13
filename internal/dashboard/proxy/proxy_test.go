package proxy_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/dashboard/proxy"
)

// echoBackend records what the proxy actually sent — path, query, and the key header —
// and answers with a recognizable body plus the AI reason header the frontend depends on.
type echoBackend struct {
	gotPath  string
	gotQuery string
	gotKey   string
}

func (b *echoBackend) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.gotPath = r.URL.Path
		b.gotQuery = r.URL.RawQuery
		b.gotKey = r.Header.Get("X-API-Key")
		w.Header().Set("X-Themis-AI-Reason", "insufficient")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

func newProxy(t *testing.T, targets map[string]string, key string) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(proxy.Config{Targets: targets, APIKey: key})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

// The rewrite seam: /api/<node>/x → <target>/api/v1/x, query preserved. This is the
// path the spike's first live defect hid in (the capability-id 404) — the exact class
// D7 says a proxy test must kill.
func TestProxy_RewritesPathAndPreservesQuery(t *testing.T) {
	be := &echoBackend{}
	srv := httptest.NewServer(be.handler())
	defer srv.Close()
	p := newProxy(t, map[string]string{"knowledge": srv.URL}, "")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/knowledge/faultlines?cve=CVE-2020-10543", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if be.gotPath != "/api/v1/faultlines" {
		t.Errorf("backend path = %q, want /api/v1/faultlines", be.gotPath)
	}
	if be.gotQuery != "cve=CVE-2020-10543" {
		t.Errorf("backend query = %q, want the query preserved", be.gotQuery)
	}
}

// Key custody (D4): the configured NODE key goes out, and a browser-supplied key is
// dropped — never forwarded, never merged. The browser must not be able to speak to a
// node with a credential of its own choosing.
func TestProxy_InjectsNodeKeyAndDropsBrowserKey(t *testing.T) {
	be := &echoBackend{}
	srv := httptest.NewServer(be.handler())
	defer srv.Close()
	p := newProxy(t, map[string]string{"governance": srv.URL}, "node-secret")

	req := httptest.NewRequest(http.MethodGet, "/api/governance/findings/f-1", nil)
	req.Header.Set("X-API-Key", "browser-supplied-lie")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if be.gotKey != "node-secret" {
		t.Errorf("backend saw key %q, want the node key and never the browser's", be.gotKey)
	}
}

// With no key configured (auth-off dev), the browser's key is STILL dropped — key
// custody does not depend on a key existing.
func TestProxy_NoKeyConfiguredStillDropsBrowserKey(t *testing.T) {
	be := &echoBackend{}
	srv := httptest.NewServer(be.handler())
	defer srv.Close()
	p := newProxy(t, map[string]string{"evidence": srv.URL}, "")

	req := httptest.NewRequest(http.MethodGet, "/api/evidence/inventory/e-1", nil)
	req.Header.Set("X-API-Key", "browser-supplied")
	p.ServeHTTP(httptest.NewRecorder(), req)

	if be.gotKey != "" {
		t.Errorf("backend saw key %q, want none", be.gotKey)
	}
}

// The AI honesty contract rides a response header (AI-204-1); the proxy must pass it
// through untouched or every no-answer reads as a blank refusal (D6).
func TestProxy_PassesAIReasonHeaderThrough(t *testing.T) {
	be := &echoBackend{}
	srv := httptest.NewServer(be.handler())
	defer srv.Close()
	p := newProxy(t, map[string]string{"intelligence": srv.URL}, "")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/intelligence/capabilities/recommend_position/invoke", nil))

	if got := rec.Header().Get("X-Themis-AI-Reason"); got != "insufficient" {
		t.Errorf("X-Themis-AI-Reason = %q, want passed through", got)
	}
}

// A dead node is a 502 JSON problem naming the node — the frontend renders "node
// unreachable", never a parse error on an empty reply.
func TestProxy_DeadNodeAnswersProblemJSON(t *testing.T) {
	p := newProxy(t, map[string]string{"knowledge": "http://127.0.0.1:1"}, "")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/knowledge/faultlines/x", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	var body struct{ Title, Detail string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	if body.Title != "node unreachable" || body.Detail != "knowledge" {
		t.Errorf("problem = %+v, want node unreachable/knowledge", body)
	}
}

// An unknown node is a 404 problem listing the valid names — a frontend typo should
// read as a typo, not as a missing card.
func TestProxy_UnknownNodeIs404WithValidNames(t *testing.T) {
	p := newProxy(t, map[string]string{"knowledge": "http://localhost:1", "registry": "http://localhost:1"}, "")

	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/knowlege/faultlines/x", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	var body struct{ Title, Detail string }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.Title != "unknown node" || body.Detail != "valid: knowledge, registry" {
		t.Errorf("problem = %+v, want the sorted valid-node list", body)
	}
}

// A malformed target URL fails the BOOT, not the first request: deployment errors
// belong at startup.
func TestProxy_BadTargetURLFailsConstruction(t *testing.T) {
	if _, err := proxy.New(proxy.Config{Targets: map[string]string{"knowledge": "http://bad url with spaces"}}); err == nil {
		t.Fatal("New accepted an unparseable target URL")
	}
}
