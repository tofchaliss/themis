package session_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/platform/auth"
)

func newHandler(valid map[string]auth.Principal) session.Handler {
	return session.Handler{Manager: session.NewManager(&fakeVerifier{valid: valid}, 0, nil)}
}

func postLogin(h session.Handler, key string, tls bool) *httptest.ResponseRecorder {
	form := url.Values{"key": {key}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if tls {
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == session.CookieName {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

// The login POST: a valid key mints the session cookie with the D3 flags — HttpOnly
// (script never reads it) and SameSite=Strict (no cross-site ride-along).
func TestLogin_SetsHardenedCookie(t *testing.T) {
	h := newHandler(map[string]auth.Principal{"good-key": alice})
	rec := postLogin(h, "good-key", false)

	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("login = %d → %q, want a redirect to /", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionCookie(t, rec)
	if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags = HttpOnly:%v SameSite:%v, want HttpOnly + Strict", c.HttpOnly, c.SameSite)
	}
	if c.Secure {
		t.Error("Secure set on a plain-HTTP request — it would make the cookie unusable there")
	}
}

// Behind the TLS-terminating proxy D3 expects in production, X-Forwarded-Proto is the
// proxy's voice and the cookie turns Secure.
func TestLogin_SecureCookieBehindTLS(t *testing.T) {
	h := newHandler(map[string]auth.Principal{"good-key": alice})
	if c := sessionCookie(t, postLogin(h, "good-key", true)); !c.Secure {
		t.Error("cookie not Secure behind X-Forwarded-Proto: https")
	}
}

// A refused key re-serves the form with a flag — and deliberately no diagnosis of WHY.
func TestLogin_BadKeyRedirectsToFailedForm(t *testing.T) {
	h := newHandler(map[string]auth.Principal{})
	rec := postLogin(h, "wrong", false)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?failed=1" {
		t.Fatalf("bad login = %d → %q, want /login?failed=1", rec.Code, rec.Header().Get("Location"))
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("a failed login set a cookie")
	}
}

func TestPrincipalAndLogout(t *testing.T) {
	h := newHandler(map[string]auth.Principal{"good-key": alice})
	c := sessionCookie(t, postLogin(h, "good-key", false))

	req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	req.AddCookie(c)
	if p, ok := h.Principal(req); !ok || p.Name != "alice" {
		t.Fatalf("Principal = (%+v, %v), want alice", p, ok)
	}
	if _, ok := h.Principal(httptest.NewRequest(http.MethodGet, "/", nil)); ok {
		t.Error("a cookie-less request resolved a principal")
	}

	rec := httptest.NewRecorder()
	lreq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	lreq.AddCookie(c)
	h.Logout(rec, lreq)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("logout = %d, want redirect", rec.Code)
	}
	if p, ok := h.Principal(req); ok {
		t.Errorf("session %v survived logout", p)
	}
}

// Reverify through the HTTP hook: same cookie, key revoked between requests → dead.
func TestReverifyHook(t *testing.T) {
	valid := map[string]auth.Principal{"good-key": alice}
	h := newHandler(valid)
	c := sessionCookie(t, postLogin(h, "good-key", false))

	req := httptest.NewRequest(http.MethodPost, "/api/governance/x", nil)
	req.AddCookie(c)
	if _, ok := h.Reverify(req); !ok {
		t.Fatal("Reverify failed on an active key")
	}
	delete(valid, "good-key")
	if _, ok := h.Reverify(req); ok {
		t.Fatal("Reverify passed a revoked key")
	}
	if _, ok := h.Reverify(httptest.NewRequest(http.MethodPost, "/x", nil)); ok {
		t.Error("Reverify accepted a cookie-less request")
	}
}

// The SPA shell gate: no session → the login form; with one → the page. (The API routes
// answer 401 JSON instead — that is the proxy Gate's contract, tested there.)
func TestRequireSession(t *testing.T) {
	h := newHandler(map[string]auth.Principal{"good-key": alice})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	gated := h.RequireSession(next)

	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("no session = %d → %q, want redirect to /login", rec.Code, rec.Header().Get("Location"))
	}

	c := sessionCookie(t, postLogin(h, "good-key", false))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	rec = httptest.NewRecorder()
	gated.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("with session = %d, want 200", rec.Code)
	}
}

// The login page itself is reachable without a session and self-contained (inline
// styles: it must render exactly when every other asset is gated).
func TestLoginPage(t *testing.T) {
	h := newHandler(nil)
	rec := httptest.NewRecorder()
	h.LoginPage(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `name="key"`) {
		t.Fatalf("login page = %d, want the key form", rec.Code)
	}
}
