package session

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/platform/auth"
)

// CookieName carries the opaque session token — a random number, never a credential.
const CookieName = "themis_session"

// Handler serves the login/logout edge and the session middleware. It owns the one
// moment the operator's key transits the wire (the login POST), which is why D3 requires
// production deployments to front the dashboard with TLS — no cookie flag protects a paste.
type Handler struct {
	Manager *Manager
}

// LoginPage serves the self-contained login form. Inline styles on purpose: every other
// asset sits behind the session, and a login page that needs a gated stylesheet is a
// login page that renders unstyled exactly when it matters.
func (h Handler) LoginPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(loginHTML))
}

// Login handles the form POST for BOTH sign-in paths (EDR-GUI-01 D3 amendment 2026-10-12).
// There is one route, and which path it takes is decided by which fields arrived: a username
// (or a password) means the dashboard's own directory; otherwise the pasted API key. One
// route rather than two because the browser already posts a form here and a second JSON login
// endpoint would be a second place for the session rules to drift.
//
// Failure always redirects to the same flagged form and deliberately does not say WHY, nor
// which half was wrong — an un-migrated password table and a wrong password are one answer.
func (h Handler) Login(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostFormValue("username"))
	password := r.PostFormValue("password")
	key := strings.TrimSpace(r.PostFormValue("key"))

	var token string
	var ok bool
	if username != "" || password != "" {
		token, _, ok = h.Manager.LoginPassword(r.Context(), username, password)
	} else {
		token, _, ok = h.Manager.Login(r.Context(), key)
	}
	if !ok {
		http.Redirect(w, r, "/login?failed=1", http.StatusSeeOther)
		return
	}
	h.setSessionCookie(w, r, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// setSessionCookie writes the one cookie the browser holds: a random token, never a
// credential.
func (h Handler) setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		// Secure when the request arrived over TLS — directly or via the fronting
		// proxy D3 expects in production (X-Forwarded-Proto is that proxy's voice).
		Secure:  r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		Expires: time.Now().Add(DefaultIdleExpiry),
	})
}

// Logout kills the session server-side and clears the cookie.
func (h Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		h.Manager.Logout(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// Principal resolves the request's session cookie to its operator (the hook the proxy
// Gate and /whoami share).
func (h Handler) Principal(r *http.Request) (auth.Principal, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return auth.Principal{}, false
	}
	return h.Manager.Principal(c.Value)
}

// Reverify is the mutation-path hook (D12): the session key must still be active.
func (h Handler) Reverify(r *http.Request) (auth.Principal, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return auth.Principal{}, false
	}
	return h.Manager.Reverify(r.Context(), c.Value)
}

// RequireSession gates the SPA shell: without a session, a page request is sent to the
// login form (the API routes answer 401 JSON instead — the proxy Gate's job, because a
// fetch cannot follow a redirect to an HTML form).
func (h Handler) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := h.Principal(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin gates the dashboard's OWN admin routes. It answers JSON like the proxy Gate
// (never a redirect — a fetch cannot follow one to an HTML form): 401 without a session,
// 403 for an operator whose scope is not admin. These routes are dashboard-local and are
// mounted BEFORE the /api/* proxy, so nothing here is ever forwarded to a node.
func (h Handler) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := h.Principal(r)
		if !ok {
			problem(w, http.StatusUnauthorized, "authentication required", "sign in at /login")
			return
		}
		if !p.IsAdmin() {
			problem(w, http.StatusForbidden, "admin scope required",
				"the Admin tab administers this dashboard and is restricted to admin-scope operators")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AdminStatus answers what the Admin tab needs to render itself: auth is on, and whether the
// seeded admin account still holds the shipped default password. `is_default_password` is
// false when the password store is unavailable — the tab's change attempt is what reports
// that honestly, because a status endpoint that cried wolf on every DB hiccup would be
// ignored.
func (h Handler) AdminStatus(w http.ResponseWriter, r *http.Request) {
	isDefault, err := h.Manager.DefaultPasswordInUse(r.Context())
	if err != nil {
		isDefault = false
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_enabled":        true,
		"is_default_password": isDefault,
	})
}

// DisabledAdminStatus is what the Admin tab reads when the dashboard runs with no auth DSN:
// there is no login and no password, so the tab says exactly that and offers no form. It
// needs no session, because with auth disabled there are none.
func DisabledAdminStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"auth_enabled": false})
}

// DisabledAdminPassword is the open edge's answer on the change-password route. It is mounted
// even though there is nothing to change, and mounted BEFORE the proxy, so a password posted
// to an auth-disabled dashboard is refused HERE — not forwarded to a node as an unknown-node
// 404. A credential must never leave this process by accident.
func DisabledAdminPassword(w http.ResponseWriter, _ *http.Request) {
	problem(w, http.StatusServiceUnavailable, "authentication is disabled",
		"this dashboard requires no sign-in, so it has no password to change; set THEMIS_AUTH_DATABASE_DSN to require sign-in")
}

// changePasswordRequest is the Admin tab's form, on the wire. `confirm` is checked HERE and
// not only in the browser: a typo that reaches the store would lock the operator out of the
// GUI, and the server is the only side that cannot be skipped.
type changePasswordRequest struct {
	Current string `json:"current"`
	New     string `json:"new"`
	Confirm string `json:"confirm"`
}

// ChangePassword is the one mutating dashboard-local route: it changes the signed-in
// operator's own GUI password and is handled here, never proxied to a node (no node owns
// this table). On success the session is reissued under a fresh cookie and every other
// session of the same user is ended (D12).
func (h Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		problem(w, http.StatusUnauthorized, "authentication required", "sign in at /login")
		return
	}
	var req changePasswordRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req) != nil {
		problem(w, http.StatusBadRequest, "unreadable request", "expected a JSON body with current, new and confirm")
		return
	}
	if req.New != req.Confirm {
		problem(w, http.StatusBadRequest, "passwords do not match", "the new password and its confirmation differ")
		return
	}
	token, err := h.Manager.ChangePassword(r.Context(), c.Value, req.Current, req.New)
	switch {
	case errors.Is(err, ErrEmptyPassword):
		problem(w, http.StatusBadRequest, "empty password", "the new password cannot be empty")
	case errors.Is(err, ErrWrongPassword):
		problem(w, http.StatusUnauthorized, "current password does not match",
			"the password was not changed")
	case errors.Is(err, ErrNoPasswordSession):
		problem(w, http.StatusForbidden, "not a password session",
			"this session signed in with an API key, which has no GUI password; sign in with a username and password to change it, or rotate the key with authadmin")
	case errors.Is(err, ErrPasswordsUnavailable):
		problem(w, http.StatusServiceUnavailable, "password store unavailable",
			"the dashboard_users table is missing or unreadable; run the dashboard with THEMIS_DASHBOARD_MIGRATE=1 against the auth database")
	case err != nil:
		problem(w, http.StatusInternalServerError, "password change failed", "the password was not changed")
	default:
		h.setSessionCookie(w, r, token)
		w.WriteHeader(http.StatusNoContent)
	}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// problem writes the same {title, detail} shape the proxy answers with, so the SPA has one
// error reader for its own routes and the proxied ones.
func problem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, map[string]string{"title": title, "detail": detail})
}

// loginHTML is the whole login surface: no framework, inline styles, and TWO ways in posting
// to the one /login route — a username and password (the primary form, EDR-GUI-01 D3
// amendment 2026-10-12) and the API-key paste that was v1's only door, kept as a disclosure
// below it so no operator who already has a key is locked out. The palette mirrors the app's
// Midnight theme so the first and second screens feel like one product.
const loginHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Themis — sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#e6edf3;
       font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
  .box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:2rem;width:20rem}
  form{margin:0}
  h1{font-size:1.1rem;margin:0 0 .25rem}
  p{color:#8b949e;font-size:.85rem;margin:.25rem 0 1rem}
  label{display:block;font-size:.75rem;font-weight:600;color:#8b949e;margin:.6rem 0 .25rem}
  input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;
        border-radius:6px;padding:.55rem .7rem}
  input[name="key"]{font-family:ui-monospace,monospace}
  button{width:100%;margin-top:1rem;padding:.55rem;border:0;border-radius:6px;background:#238636;
         color:#fff;font-weight:600;cursor:pointer}
  details{margin-top:1.25rem;border-top:1px solid #30363d;padding-top:.75rem}
  summary{cursor:pointer;font-size:.8rem;color:#8b949e}
  .failed{color:#f85149;font-size:.85rem;margin-top:.75rem;display:none}
</style></head><body>
<div class="box">
  <h1>Themis</h1>
  <p>Sign in with your dashboard username and password. The first sign-in of a new deployment
     uses the default <b>admin</b> account — change its password in the Admin tab straight away.</p>
  <form method="post" action="/login" autocomplete="off">
    <label for="username">Username</label>
    <input id="username" type="text" name="username" autocomplete="username" autofocus required>
    <label for="password">Password</label>
    <input id="password" type="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
  <div class="failed" id="failed">Sign-in not accepted.</div>
  <details>
    <summary>Sign in with an operator API key instead</summary>
    <p>Paste your own key: it is exchanged for a session, never stored in the browser, and your
       key's scope decides what the GUI lets you do.</p>
    <form method="post" action="/login" autocomplete="off">
      <input type="password" name="key" placeholder="API key" required>
      <button type="submit">Sign in with key</button>
    </form>
  </details>
</div>
<script>if(new URLSearchParams(location.search).get("failed"))document.getElementById("failed").style.display="block";</script>
</body></html>`
