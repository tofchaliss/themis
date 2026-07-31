package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// APIKeyHeader is the header carrying the bearer token (D3).
const APIKeyHeader = "X-API-Key"

type principalCtxKey struct{}

// WithPrincipal stores the authenticated principal on the context.
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, p)
}

// PrincipalFrom returns the authenticated principal, if any.
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalCtxKey{}).(Principal)
	return p, ok
}

// Authenticator validates X-API-Key headers against the identity store and attaches the
// resolved Principal to the request context. Now and Compare are injectable for tests; they
// default to time.Now and bcrypt.CompareHashAndPassword.
type Authenticator struct {
	Keys    KeyStore
	Now     func() time.Time
	Compare func(hashedPassword, password []byte) error
}

// RequireAPIKey is the authentication middleware: it rejects any request without a valid,
// non-expired, non-revoked key (401), otherwise runs the next handler with the principal on
// the context. Ported from the monolith's APIKeyAuth.Middleware.
func (a Authenticator) RequireAPIKey(next http.Handler) http.Handler {
	now := a.Now
	if now == nil {
		now = time.Now
	}
	compare := a.Compare
	if compare == nil {
		compare = bcrypt.CompareHashAndPassword
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get(APIKeyHeader))
		if raw == "" {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "missing "+APIKeyHeader+" header")
			return
		}
		keys, err := a.Keys.ActiveKeys(r.Context())
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}
		for _, key := range keys {
			if compare([]byte(key.KeyHash), []byte(raw)) != nil {
				continue
			}
			if key.ExpiresAt != nil && !key.ExpiresAt.After(now()) {
				continue
			}
			principal := Principal{KeyID: key.ID, Name: key.Name, Scopes: key.Scopes}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
			return
		}
		writeProblem(w, http.StatusUnauthorized, "Unauthorized", "invalid API key")
	})
}

// RequireScope is the authorization middleware: it must run *after* RequireAPIKey and rejects
// (403) any principal that does not satisfy the required scope (admin always satisfies). A
// request with no principal on the context is treated as unauthenticated (401) — a wiring
// guard, since RequireAPIKey should always precede this.
func RequireScope(required string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				writeProblem(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
				return
			}
			if !p.AuthorizeScope(required) {
				writeProblem(w, http.StatusForbidden, "Forbidden", "requires scope "+required)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireWriteScope is the method-based authorization middleware. Because oapi-codegen does
// not emit per-operation security from the OpenAPI `security`/`securitySchemes` blocks, scope
// enforcement is applied at mount time here rather than per route: read methods (GET/HEAD/
// OPTIONS) pass for any authenticated principal (the `read` floor), while mutating methods
// require a write-capable key (admin or product-scoped — not a read-only key). It must run
// after RequireAPIKey. Product-scope *isolation* to a specific product is a later refinement
// (greenfield routes key on release/finding, not product), tracked as a follow-up.
func RequireWriteScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "authentication required")
			return
		}
		if !p.AuthorizeWrite() {
			writeProblem(w, http.StatusForbidden, "Forbidden", "a write-capable key is required for this operation")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// writeProblem renders an RFC-7807 problem+json error (mirrors the per-context handlers'
// writeProblem, kept local so the platform package imports no bounded context).
func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"title":  title,
		"detail": detail,
		"status": status,
	})
}
