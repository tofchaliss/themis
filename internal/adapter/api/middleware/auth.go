package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/domain"
)

type authContextKey struct{}
type clientIPContextKey struct{}

// WithAuth stores the authenticated principal on the context.
func WithAuth(ctx context.Context, principal domain.AuthPrincipal) context.Context {
	return context.WithValue(ctx, authContextKey{}, principal)
}

// AuthFromContext returns the authenticated principal.
func AuthFromContext(ctx context.Context) (domain.AuthPrincipal, bool) {
	principal, ok := ctx.Value(authContextKey{}).(domain.AuthPrincipal)
	return principal, ok
}

// WithClientIP stores the request's client IP on the context (no-op if empty).
func WithClientIP(ctx context.Context, ip string) context.Context {
	if ip == "" {
		return ctx
	}
	return context.WithValue(ctx, clientIPContextKey{}, ip)
}

// ClientIPFromContext returns the captured client IP, or "".
func ClientIPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPContextKey{}).(string)
	return ip
}

// ClientIP extracts a validated client IP from a request: the first
// X-Forwarded-For entry if valid, otherwise the RemoteAddr host.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.Split(xff, ",")[0])
		if net.ParseIP(first) != nil {
			return first
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) != nil {
		return host
	}
	return ""
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
		principal, ok, err := a.resolve(r.Context(), raw)
		if err != nil || !ok {
			writeProblem(w, r, http.StatusUnauthorized, "Unauthorized", "invalid API key")
			return
		}
		ctx := WithClientIP(WithAuth(r.Context(), principal), ClientIP(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolve authenticates a raw key. It first tries the O(1) prefix lookup; if that
// query succeeds, the fallback scan is limited to legacy (prefix-less) keys, so a
// wrong key no longer forces a bcrypt comparison against every active key. If the
// prefix query errors (or the key is too short to have a prefix), the fallback
// does a full scan as a correctness safety net.
func (a APIKeyAuth) resolve(ctx context.Context, raw string) (domain.AuthPrincipal, bool, error) {
	prefixTried := false
	if prefix := domain.APIKeyPrefix(raw); prefix != "" {
		if keys, err := a.Keys.FindByPrefix(ctx, prefix); err == nil {
			prefixTried = true
			if principal, ok := a.match(keys, raw, false); ok {
				return principal, true, nil
			}
		}
	}
	keys, err := a.Keys.FindActiveKeys(ctx)
	if err != nil {
		return domain.AuthPrincipal{}, false, err
	}
	principal, ok := a.match(keys, raw, prefixTried)
	return principal, ok, nil
}

// match returns the principal of the first key whose hash matches raw and is not
// expired. When onlyLegacy is set, keys carrying a stored prefix are skipped —
// they were already checked by the prefix lookup.
func (a APIKeyAuth) match(keys []domain.APIKeyRecord, raw string, onlyLegacy bool) (domain.AuthPrincipal, bool) {
	for _, key := range keys {
		if onlyLegacy && key.KeyPrefix != "" {
			continue
		}
		if a.CompareFn([]byte(key.KeyHash), []byte(raw)) != nil {
			continue
		}
		if key.ExpiresAt != nil && key.ExpiresAt.Before(a.Now()) {
			continue
		}
		return domain.AuthPrincipal{KeyID: key.ID, Scopes: key.Scopes}, true
	}
	return domain.AuthPrincipal{}, false
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
