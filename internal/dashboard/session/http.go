package session

import (
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

// Login handles the form POST: verify the pasted key, mint the session, set the cookie,
// send the browser to the app. Failure re-serves the form with a flag the page renders —
// and deliberately does not say WHY the key was refused.
func (h Handler) Login(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.PostFormValue("key"))
	token, _, ok := h.Manager.Login(r.Context(), key)
	if !ok {
		http.Redirect(w, r, "/login?failed=1", http.StatusSeeOther)
		return
	}
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
	http.Redirect(w, r, "/", http.StatusSeeOther)
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

// loginHTML is the whole login surface: one field, one claim, no framework. The palette
// mirrors the app's Midnight theme so the first and second screens feel like one product.
const loginHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Themis — sign in</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#e6edf3;
       font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
  form{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:2rem;width:20rem}
  h1{font-size:1.1rem;margin:0 0 .25rem}
  p{color:#8b949e;font-size:.85rem;margin:.25rem 0 1rem}
  input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;color:#e6edf3;
        border-radius:6px;padding:.55rem .7rem;font-family:ui-monospace,monospace}
  button{width:100%;margin-top:1rem;padding:.55rem;border:0;border-radius:6px;background:#238636;
         color:#fff;font-weight:600;cursor:pointer}
  .failed{color:#f85149;font-size:.85rem;margin-top:.75rem;display:none}
</style></head><body>
<form method="post" action="/login" autocomplete="off">
  <h1>Themis</h1>
  <p>Paste your operator API key. It is exchanged for a session and never stored in the browser.</p>
  <input type="password" name="key" placeholder="API key" autofocus required>
  <button type="submit">Sign in</button>
  <div class="failed" id="failed">Key not accepted.</div>
</form>
<script>if(new URLSearchParams(location.search).get("failed"))document.getElementById("failed").style.display="block";</script>
</body></html>`
