package proxy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/dashboard/proxy"
	"github.com/themis-project/themis/internal/platform/auth"
)

var (
	adminOp = auth.Principal{KeyID: "k-1", Name: "alice", Scopes: []string{"admin"}}
	readOp  = auth.Principal{KeyID: "k-2", Name: "bob", Scopes: []string{"read"}}
)

// gateFor wires a Gate whose session and reverify outcomes are scripted, in front of a
// backend that records whether the request got through and what body arrived.
func gateFor(p auth.Principal, hasSession, keyActive bool) (http.Handler, *string) {
	var forwarded string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		forwarded = "hit:" + string(b)
		w.WriteHeader(http.StatusOK)
	})
	g := proxy.Gate{
		Principal: func(*http.Request) (auth.Principal, bool) { return p, hasSession },
		Reverify:  func(*http.Request) (auth.Principal, bool) { return p, keyActive },
	}
	return g.Wrap(backend), &forwarded
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// The D11 route-class matrix, the grill's question 1 made executable: without this gate
// a read-only operator's restriction is enforced NOWHERE (the nodes only ever see the
// admin node key).
func TestGate_ScopeMatrix(t *testing.T) {
	cases := []struct {
		name     string
		p        auth.Principal
		method   string
		path     string
		wantCode int
	}{
		{"read op reads", readOp, http.MethodGet, "/api/governance/findings/f-1", http.StatusOK},
		{"read op runs plan_remediation (Information, T7)", readOp, http.MethodPost,
			"/api/intelligence/capabilities/plan_remediation/invoke", http.StatusOK},
		{"read op runs explain_vulnerability (Information, T7)", readOp, http.MethodPost,
			"/api/intelligence/capabilities/explain_vulnerability/invoke", http.StatusOK},
		{"read op previews a render (non-recording, D9)", readOp, http.MethodPost,
			"/api/communication/previews", http.StatusOK},
		{"read op CANNOT publish — a Publication is recorded", readOp, http.MethodPost,
			"/api/communication/publications", http.StatusForbidden},
		{"read op CANNOT invoke recommend_position — it records a Proposal", readOp, http.MethodPost,
			"/api/intelligence/capabilities/recommend_position/invoke", http.StatusForbidden},
		{"read op CANNOT accept", readOp, http.MethodPost,
			"/api/governance/findings/f-1/proposals/p-1/accept", http.StatusForbidden},
		{"admin writes", adminOp, http.MethodPost,
			"/api/governance/findings/f-1/proposals/p-1/accept", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := gateFor(tc.p, true, true)
			if rec := do(h, tc.method, tc.path, ""); rec.Code != tc.wantCode {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.wantCode)
			}
		})
	}
}

// No session → 401 JSON, never a login redirect: a fetch cannot follow a redirect to an
// HTML form, and the SPA turns the 401 into the redirect itself.
func TestGate_NoSessionIs401JSON(t *testing.T) {
	h, forwarded := gateFor(auth.Principal{}, false, true)
	rec := do(h, http.MethodGet, "/api/governance/findings/f-1", "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "authentication required") {
		t.Fatalf("no session = %d %q, want 401 problem JSON", rec.Code, rec.Body.String())
	}
	if *forwarded != "" {
		t.Error("an unauthenticated request reached the backend")
	}
}

// D13: a body claiming someone else's identity is refused and never forwarded — a lie
// must not reach an append-only audit trail. A matching claim passes with the body
// intact (the backend needs it back after the check read it).
func TestGate_IdentityValidation(t *testing.T) {
	t.Run("mismatch is 403, not forwarded", func(t *testing.T) {
		h, forwarded := gateFor(adminOp, true, true)
		rec := do(h, http.MethodPost, "/api/governance/findings/f-1/proposals",
			`{"proposer_id":"mallory","proposer_kind":"human"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "identity mismatch") {
			t.Fatalf("mismatch = %d %q, want 403 identity mismatch", rec.Code, rec.Body.String())
		}
		if *forwarded != "" {
			t.Error("a lying body reached the backend")
		}
	})
	t.Run("actor_id mismatch on accept", func(t *testing.T) {
		h, _ := gateFor(adminOp, true, true)
		rec := do(h, http.MethodPost, "/api/governance/findings/f-1/proposals/p-1/accept",
			`{"actor_id":"mallory","actor_kind":"human"}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("actor mismatch = %d, want 403", rec.Code)
		}
	})
	t.Run("matching identity forwards with the body intact", func(t *testing.T) {
		h, forwarded := gateFor(adminOp, true, true)
		body := `{"actor_id":"alice","actor_kind":"human"}`
		if rec := do(h, http.MethodPost, "/api/governance/findings/f-1/proposals/p-1/accept", body); rec.Code != http.StatusOK {
			t.Fatalf("match = %d, want 200", rec.Code)
		}
		if *forwarded != "hit:"+body {
			t.Errorf("backend saw %q — the checked body must be restored byte-for-byte", *forwarded)
		}
	})
	t.Run("a body without identity fields passes", func(t *testing.T) {
		h, _ := gateFor(adminOp, true, true)
		if rec := do(h, http.MethodPost, "/api/communication/publications", `{"position_ref":"p-1"}`); rec.Code != http.StatusOK {
			t.Fatalf("no-claims body = %d, want 200 — route validation owns its shape", rec.Code)
		}
	})
	t.Run("a non-JSON body passes untouched", func(t *testing.T) {
		h, _ := gateFor(adminOp, true, true)
		if rec := do(h, http.MethodPost, "/api/evidence/evidence", "raw-sbom-bytes"); rec.Code != http.StatusOK {
			t.Fatalf("non-JSON body = %d, want 200", rec.Code)
		}
	})
}

// D12 at the gate: a write on a session whose key was revoked answers 401 — reads were
// already served upstream of this check, which is exactly the decided damage bound.
func TestGate_WriteReverifiesKey(t *testing.T) {
	h, forwarded := gateFor(adminOp, true, false) // session live, key revoked
	if rec := do(h, http.MethodGet, "/api/governance/findings/f-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("read on revoked key = %d, want 200 (reads ride the session until expiry)", rec.Code)
	}
	rec := do(h, http.MethodPost, "/api/governance/findings/f-1/proposals/p-1/accept", `{"actor_id":"alice"}`)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "no longer active") {
		t.Fatalf("write on revoked key = %d %q, want 401 key-no-longer-active", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(*forwarded, "hit:") {
		t.Log("backend saw only the read, as intended")
	}
}

// A nil Reverify hook skips the re-check (composition choice), everything else holds.
func TestGate_NilReverify(t *testing.T) {
	g := proxy.Gate{Principal: func(*http.Request) (auth.Principal, bool) { return adminOp, true }}
	backend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := do(g.Wrap(backend), http.MethodPost, "/api/governance/findings/f-1/proposals/p-1/accept", `{"actor_id":"alice"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("nil reverify write = %d, want 200", rec.Code)
	}
}

// GUI-14, measured live 2026-08-19: the identity buffer used to hand the proxy a
// TRUNCATED body under a full-length Content-Length, so every SBOM over 1 MiB died
// mid-forward as a fake 502. Document routes stream through intact; oversized decision
// bodies refuse honestly.
func TestGate_LargeBodies(t *testing.T) {
	big := strings.Repeat("x", (1<<20)+64) // just over the identity cap

	// A document route forwards the FULL body — byte-for-byte, however large.
	h, forwarded := gateFor(adminOp, true, true)
	rec := do(h, http.MethodPost, "/api/evidence/evidence", `{"kind":"sbom","document":"`+big+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("document upload = %d, want 200", rec.Code)
	}
	if wantLen := len(`{"kind":"sbom","document":"`+big+`"}`) + len("hit:"); len(*forwarded) != wantLen {
		t.Errorf("forwarded body truncated: got %d bytes, want %d", len(*forwarded), wantLen)
	}

	// A decision route refuses an oversized body with 413 — never a truncated forward,
	// and never a skipped identity check a padded body could hide a claim behind.
	h, forwarded = gateFor(adminOp, true, true)
	rec = do(h, http.MethodPost, "/api/governance/findings/f-1/proposals", `{"actor_id":"mallory","pad":"`+big+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized decision = %d, want 413", rec.Code)
	}
	if *forwarded != "" {
		t.Error("an oversized decision body must never reach the backend")
	}

	// A document route is still a WRITE: scope and session are enforced before it streams.
	h, _ = gateFor(readOp, true, true)
	if rec = do(h, http.MethodPost, "/api/evidence/evidence", `{"kind":"sbom"}`); rec.Code != http.StatusForbidden {
		t.Errorf("read-only operator upload = %d, want 403", rec.Code)
	}
}
