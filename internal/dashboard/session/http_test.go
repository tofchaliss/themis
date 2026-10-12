package session_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/dashboard/session"
	"github.com/themis-project/themis/internal/dashboard/userstore"
	"github.com/themis-project/themis/internal/platform/auth"
)

func newHandler(valid map[string]auth.Principal) session.Handler {
	return session.Handler{Manager: session.NewManager(&fakeVerifier{valid: valid}, nil, 0, nil)}
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
// styles: it must render exactly when every other asset is gated). It carries BOTH doors:
// username/password as the primary form, and the API-key paste kept beside it so an
// operator who already has a key is never locked out (D3 amendment 2026-10-12).
func TestLoginPage(t *testing.T) {
	h := newHandler(nil)
	rec := httptest.NewRecorder()
	h.LoginPage(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("login page = %d, want 200", rec.Code)
	}
	for _, want := range []string{`name="username"`, `name="password"`, `name="key"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("login page is missing %s", want)
		}
	}
}

/* ---------- password sign-in + the Admin routes (D3 amendment 2026-10-12) ---------- */

// adminHandler wires a Handler over both doors: the fake key verifier knows alice's key, and
// the fake directory holds the seeded admin account.
func adminHandler(t *testing.T, password string, isDefault bool) (session.Handler, *fakeUsers) {
	t.Helper()
	users := newFakeUsers(t, userstore.AdminUsername, password, isDefault)
	v := &fakeVerifier{valid: map[string]auth.Principal{"good-key": alice, "read-key": bob}}
	return session.Handler{Manager: session.NewManager(v, users, 0, nil)}, users
}

var bob = auth.Principal{KeyID: "k-2", Name: "bob", Scopes: []string{auth.ScopeRead}}

// postPasswordLogin posts the PRIMARY login form (username + password) to the one /login
// route — there is deliberately no second JSON login endpoint.
func postPasswordLogin(h session.Handler, username, password string) *httptest.ResponseRecorder {
	form := url.Values{"username": {username}, "password": {password}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Login(rec, req)
	return rec
}

// One route, two doors: which path /login takes is decided by which fields arrived.
func TestLogin_PasswordAndAPIKeyOnOneRoute(t *testing.T) {
	h, _ := adminHandler(t, "Themis@123", true)

	t.Run("password succeeds", func(t *testing.T) {
		rec := postPasswordLogin(h, "admin", "Themis@123")
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Fatalf("login = %d → %q, want a redirect to /", rec.Code, rec.Header().Get("Location"))
		}
		c := sessionCookie(t, rec)
		if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie flags = HttpOnly:%v SameSite:%v, want HttpOnly + Strict", c.HttpOnly, c.SameSite)
		}
		req := httptest.NewRequest(http.MethodGet, "/whoami", nil)
		req.AddCookie(c)
		if p, ok := h.Principal(req); !ok || p.Name != "admin" || !p.IsAdmin() {
			t.Errorf("session principal = (%+v, %v), want the admin-scoped `admin` operator", p, ok)
		}
	})

	t.Run("wrong password redirects to the same flagged form", func(t *testing.T) {
		rec := postPasswordLogin(h, "admin", "nope")
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?failed=1" {
			t.Fatalf("bad password = %d → %q, want /login?failed=1", rec.Code, rec.Header().Get("Location"))
		}
		if len(rec.Result().Cookies()) != 0 {
			t.Error("a failed login set a cookie")
		}
	})

	t.Run("an unknown user is the same undiagnosed answer", func(t *testing.T) {
		rec := postPasswordLogin(h, "mallory", "Themis@123")
		if rec.Header().Get("Location") != "/login?failed=1" {
			t.Errorf("unknown user → %q, want the same /login?failed=1", rec.Header().Get("Location"))
		}
	})

	t.Run("the API-key paste still works", func(t *testing.T) {
		rec := postLogin(h, "good-key", false)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Fatalf("key login = %d → %q, want a redirect to /", rec.Code, rec.Header().Get("Location"))
		}
	})

	// A password posted with no username must NOT fall through to the key door.
	t.Run("a password with no username does not become a key attempt", func(t *testing.T) {
		rec := postPasswordLogin(h, "", "good-key")
		if rec.Header().Get("Location") != "/login?failed=1" {
			t.Errorf("→ %q, want /login?failed=1", rec.Header().Get("Location"))
		}
	})
}

// adminRouter mounts the two dashboard-local Admin routes the way cmd/dashboard does:
// behind RequireAdmin, and nowhere near the proxy.
func adminRouter(h session.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/dashboard/admin/status", h.RequireAdmin(http.HandlerFunc(h.AdminStatus)))
	mux.Handle("/api/dashboard/admin/password", h.RequireAdmin(http.HandlerFunc(h.ChangePassword)))
	return mux
}

func signIn(t *testing.T, h session.Handler, username, password string) *http.Cookie {
	t.Helper()
	return sessionCookie(t, postPasswordLogin(h, username, password))
}

func changePassword(h session.Handler, c *http.Cookie, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/dashboard/admin/password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	adminRouter(h).ServeHTTP(rec, req)
	return rec
}

func TestAdminStatus(t *testing.T) {
	t.Run("auth enabled, default password still in use", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		c := signIn(t, h, "admin", "Themis@123")
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard/admin/status", nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		adminRouter(h).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		var got struct {
			AuthEnabled       bool `json:"auth_enabled"`
			IsDefaultPassword bool `json:"is_default_password"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !got.AuthEnabled || !got.IsDefaultPassword {
			t.Errorf("status = %+v, want auth on and the default-password notice", got)
		}
	})

	t.Run("the notice clears after a change", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		c := signIn(t, h, "admin", "Themis@123")
		if rec := changePassword(h, c, `{"current":"Themis@123","new":"n","confirm":"n"}`); rec.Code != http.StatusNoContent {
			t.Fatalf("change = %d, want 204", rec.Code)
		}
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard/admin/status", nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		adminRouter(h).ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), `"is_default_password":true`) {
			t.Errorf("status still reports the default password: %s", rec.Body.String())
		}
	})

	// A store that cannot answer reports no notice rather than crying wolf; the change
	// attempt is what states the problem honestly.
	t.Run("an unreadable store reports no notice", func(t *testing.T) {
		h, users := adminHandler(t, "Themis@123", true)
		c := signIn(t, h, "admin", "Themis@123")
		users.err = userstore.ErrTableMissing
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard/admin/status", nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		adminRouter(h).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"is_default_password":true`) {
			t.Errorf("status = %d %s, want 200 with no notice", rec.Code, rec.Body.String())
		}
	})

	t.Run("no session is 401 JSON", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		rec := httptest.NewRecorder()
		adminRouter(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/admin/status", nil))
		if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "authentication required") {
			t.Fatalf("no session = %d %q, want 401 problem JSON", rec.Code, rec.Body.String())
		}
	})

	// The Admin tab administers the dashboard: a read-scoped operator may not even look.
	t.Run("a read-scoped operator is 403", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		c := sessionCookie(t, postLogin(h, "read-key", false))
		req := httptest.NewRequest(http.MethodGet, "/api/dashboard/admin/status", nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		adminRouter(h).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin scope required") {
			t.Fatalf("read operator = %d %q, want 403", rec.Code, rec.Body.String())
		}
	})
}

// With no auth DSN there is no login and no password, so the tab is told exactly that and
// offers no form — and the endpoint needs no session, because there are none.
func TestDisabledAdminStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	session.DisabledAdminStatus(rec, httptest.NewRequest(http.MethodGet, "/api/dashboard/admin/status", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"auth_enabled":false`) {
		t.Fatalf("disabled status = %d %q, want 200 {auth_enabled:false}", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "is_default_password") {
		t.Error("the disabled answer must not imply a password exists")
	}

	// And a password posted anyway is refused here rather than forwarded anywhere.
	rec = httptest.NewRecorder()
	session.DisabledAdminPassword(rec, httptest.NewRequest(http.MethodPost, "/api/dashboard/admin/password", nil))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "authentication is disabled") {
		t.Fatalf("disabled password = %d %q, want 503 authentication-is-disabled", rec.Code, rec.Body.String())
	}
}

func TestChangePassword_HappyPath(t *testing.T) {
	h, _ := adminHandler(t, "Themis@123", true)
	c := signIn(t, h, "admin", "Themis@123")

	rec := changePassword(h, c, `{"current":"Themis@123","new":"quiet-mountain","confirm":"quiet-mountain"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("change = %d %q, want 204", rec.Code, rec.Body.String())
	}
	// The session is reissued under a fresh cookie, so the operator is not logged out by
	// their own change.
	fresh := sessionCookie(t, rec)
	if fresh.Value == c.Value {
		t.Error("the session cookie was not reissued")
	}
	probe := httptest.NewRequest(http.MethodGet, "/whoami", nil)
	probe.AddCookie(fresh)
	if _, ok := h.Principal(probe); !ok {
		t.Error("the reissued cookie does not resolve a session")
	}
	// And the new password is the one that works from now on.
	if postPasswordLogin(h, "admin", "quiet-mountain").Header().Get("Location") != "/" {
		t.Error("the new password does not sign in")
	}
	if postPasswordLogin(h, "admin", "Themis@123").Header().Get("Location") != "/login?failed=1" {
		t.Error("the old password still signs in")
	}
}

func TestChangePassword_Refusals(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"empty new", `{"current":"Themis@123","new":"","confirm":""}`, http.StatusBadRequest},
		{"mismatched confirm", `{"current":"Themis@123","new":"a","confirm":"b"}`, http.StatusBadRequest},
		{"unreadable body", `not json`, http.StatusBadRequest},
		{"wrong current", `{"current":"nope","new":"a","confirm":"a"}`, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, users := adminHandler(t, "Themis@123", true)
			c := signIn(t, h, "admin", "Themis@123")
			if rec := changePassword(h, c, tc.body); rec.Code != tc.want {
				t.Fatalf("= %d %q, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			// A refused change must leave the stored password alone.
			if postPasswordLogin(h, "admin", "Themis@123").Header().Get("Location") != "/" {
				t.Error("a refused change altered the stored password")
			}
			if u, _ := users.GetUser(context.Background(), "admin"); !u.IsDefaultPassword {
				t.Error("a refused change cleared the default-password flag")
			}
		})
	}

	t.Run("unauthenticated is 401 and never reaches the handler", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		rec := changePassword(h, nil, `{"current":"Themis@123","new":"a","confirm":"a"}`)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("= %d, want 401", rec.Code)
		}
	})

	t.Run("a read-scoped operator is 403", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		c := sessionCookie(t, postLogin(h, "read-key", false))
		rec := changePassword(h, c, `{"current":"Themis@123","new":"a","confirm":"a"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "admin scope required") {
			t.Fatalf("= %d %q, want 403", rec.Code, rec.Body.String())
		}
	})

	// An ADMIN-scoped key session clears RequireAdmin but has no GUI password of its own:
	// 403 naming the actual situation, not a misleading "wrong password".
	t.Run("a key session has no GUI password", func(t *testing.T) {
		h, _ := adminHandler(t, "Themis@123", true)
		c := sessionCookie(t, postLogin(h, "good-key", false))
		rec := changePassword(h, c, `{"current":"Themis@123","new":"a","confirm":"a"}`)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "not a password session") {
			t.Fatalf("= %d %q, want 403 not-a-password-session", rec.Code, rec.Body.String())
		}
	})

	// The un-migrated deployment: 503 naming the flag, never "wrong password" — an operator
	// told the latter would never find the former.
	t.Run("a missing table is 503 naming the migration flag", func(t *testing.T) {
		h, users := adminHandler(t, "Themis@123", true)
		c := signIn(t, h, "admin", "Themis@123")
		users.err = userstore.ErrTableMissing
		rec := changePassword(h, c, `{"current":"Themis@123","new":"a","confirm":"a"}`)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "THEMIS_DASHBOARD_MIGRATE=1") {
			t.Fatalf("= %d %q, want 503 naming THEMIS_DASHBOARD_MIGRATE=1", rec.Code, rec.Body.String())
		}
	})
}

// The whole point of the 204: the other browser signed in as the same user stops being able
// to decide anything the moment the password changes (D12).
func TestChangePassword_EndsOtherSessions(t *testing.T) {
	h, _ := adminHandler(t, "Themis@123", true)
	elsewhere := signIn(t, h, "admin", "Themis@123")
	here := signIn(t, h, "admin", "Themis@123")

	mutation := httptest.NewRequest(http.MethodPost, "/api/governance/findings/f-1/proposals", nil)
	mutation.AddCookie(elsewhere)
	if _, ok := h.Reverify(mutation); !ok {
		t.Fatal("the other session could not write before the change")
	}
	if rec := changePassword(h, here, `{"current":"Themis@123","new":"n","confirm":"n"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("change = %d, want 204", rec.Code)
	}
	if _, ok := h.Reverify(mutation); ok {
		t.Error("the other session could still write after the password change")
	}
}
