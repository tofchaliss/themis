package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/domain"
)

type authContextKey struct{}

// WithAuth stores the authenticated principal on the context.
func WithAuth(ctx context.Context, principal domain.AuthPrincipal) context.Context {
	return context.WithValue(ctx, authContextKey{}, principal)
}

// AuthFromContext returns the authenticated principal.
func AuthFromContext(ctx context.Context) (domain.AuthPrincipal, bool) {
	principal, ok := ctx.Value(authContextKey{}).(domain.AuthPrincipal)
	return principal, ok
}

// APIKeyAuth validates X-API-Key headers.
type APIKeyAuth struct {
	Keys      domain.APIKeyRepository
	Now       func() time.Time
	CompareFn func(hashedPassword, password []byte) error
}

// Middleware validates API keys and attaches the principal to the request context.
func (a APIKeyAuth) Middleware(next http.Handler) http.Handler {
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.CompareFn == nil {
		a.CompareFn = bcrypt.CompareHashAndPassword
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/webhooks/scan") {
			next.ServeHTTP(w, r)
			return
		}
		raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if raw == "" {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing X-API-Key header")
			return
		}
		keys, err := a.Keys.FindActiveKeys(r.Context())
		if err != nil {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}
		for _, key := range keys {
			if err := a.CompareFn([]byte(key.KeyHash), []byte(raw)); err != nil {
				continue
			}
			if key.ExpiresAt != nil && key.ExpiresAt.Before(a.Now()) {
				continue
			}
			principal := domain.AuthPrincipal{KeyID: key.ID, Scopes: key.Scopes}
			next.ServeHTTP(w, r.WithContext(WithAuth(r.Context(), principal)))
			return
		}
		writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
	})
}

// WebhookAuth validates HMAC signatures for CI webhooks.
type WebhookAuth struct {
	Secret string
	Verify func(secret string, r *http.Request) bool
}

// Middleware validates webhook signatures.
func (w WebhookAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.Secret == "" {
			writeProblem(rw, r, http.StatusUnauthorized, "Unauthorized", "webhook secret not configured")
			return
		}
		verify := w.Verify
		if verify == nil {
			verify = defaultWebhookVerify
		}
		if !verify(w.Secret, r) {
			writeProblem(rw, r, http.StatusUnauthorized, "Unauthorized", "invalid webhook signature")
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// MaxBytes limits request body size.
func MaxBytes(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}
