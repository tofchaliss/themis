package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/domain"
)

// prefixKeys lets each lookup path be controlled independently.
type prefixKeys struct {
	byPrefix    map[string][]domain.APIKeyRecord
	byPrefixErr error
	active      []domain.APIKeyRecord
	activeErr   error
}

func (p *prefixKeys) FindByPrefix(_ context.Context, prefix string) ([]domain.APIKeyRecord, error) {
	if p.byPrefixErr != nil {
		return nil, p.byPrefixErr
	}
	return p.byPrefix[prefix], nil
}
func (p *prefixKeys) FindActiveKeys(context.Context) ([]domain.APIKeyRecord, error) {
	return p.active, p.activeErr
}
func (p *prefixKeys) Create(context.Context, domain.APIKeyCreateInput) (domain.APIKeyRecord, error) {
	return domain.APIKeyRecord{}, nil
}
func (p *prefixKeys) Revoke(context.Context, string) error { return nil }

func mustHash(t *testing.T, raw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func runAuth(t *testing.T, auth middleware.APIKeyAuth, rawKey string) int {
	t.Helper()
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", rawKey)
	handler.ServeHTTP(rec, req)
	return rec.Code
}

func TestAPIKeyAuthPrefixFastPath(t *testing.T) {
	raw := "abcd1234deadbeef"
	key := domain.APIKeyRecord{ID: "k1", KeyHash: mustHash(t, raw), KeyPrefix: "abcd1234", Scopes: []string{domain.ScopeAdmin}}
	// active is nil: the fast path must authenticate without a full scan.
	keys := &prefixKeys{byPrefix: map[string][]domain.APIKeyRecord{"abcd1234": {key}}}
	if code := runAuth(t, middleware.APIKeyAuth{Keys: keys}, raw); code != http.StatusNoContent {
		t.Fatalf("fast path status=%d, want 204", code)
	}
}

func TestAPIKeyAuthLegacyFallback(t *testing.T) {
	raw := "legacykey0000000"
	legacy := domain.APIKeyRecord{ID: "k2", KeyHash: mustHash(t, raw), KeyPrefix: ""}
	// FindByPrefix returns nothing (legacy key has no stored prefix); fallback finds it.
	keys := &prefixKeys{byPrefix: map[string][]domain.APIKeyRecord{}, active: []domain.APIKeyRecord{legacy}}
	if code := runAuth(t, middleware.APIKeyAuth{Keys: keys}, raw); code != http.StatusNoContent {
		t.Fatalf("legacy fallback status=%d, want 204", code)
	}
}

func TestAPIKeyAuthWrongKeySkipsPrefixedInFallback(t *testing.T) {
	prefixed := domain.APIKeyRecord{ID: "kp", KeyHash: mustHash(t, "realkey123456789"), KeyPrefix: "realkey1"}
	var compared []string
	auth := middleware.APIKeyAuth{
		Keys: &prefixKeys{byPrefix: map[string][]domain.APIKeyRecord{}, active: []domain.APIKeyRecord{prefixed}},
		CompareFn: func(hash, pw []byte) error {
			compared = append(compared, string(hash))
			return bcrypt.CompareHashAndPassword(hash, pw)
		},
	}
	if code := runAuth(t, auth, "wrongkey00000000"); code != http.StatusUnauthorized {
		t.Fatalf("wrong key status=%d, want 401", code)
	}
	// The prefixed key must NOT have been bcrypt-compared in the fallback (DoS bound).
	for _, h := range compared {
		if h == prefixed.KeyHash {
			t.Fatal("prefixed key was compared during fallback scan")
		}
	}
}

func TestAPIKeyAuthPrefixErrorFullScanSafetyNet(t *testing.T) {
	raw := "abcd1234deadbeef"
	key := domain.APIKeyRecord{ID: "k1", KeyHash: mustHash(t, raw), KeyPrefix: "abcd1234"}
	// FindByPrefix errors -> fallback must do a full scan (including prefixed keys).
	keys := &prefixKeys{byPrefixErr: errors.New("db blip"), active: []domain.APIKeyRecord{key}}
	if code := runAuth(t, middleware.APIKeyAuth{Keys: keys}, raw); code != http.StatusNoContent {
		t.Fatalf("safety-net status=%d, want 204", code)
	}
}

func TestAPIKeyAuthExpiredPrefixedKey(t *testing.T) {
	raw := "abcd1234deadbeef"
	past := time.Now().Add(-time.Hour)
	key := domain.APIKeyRecord{ID: "k1", KeyHash: mustHash(t, raw), KeyPrefix: "abcd1234", ExpiresAt: &past}
	keys := &prefixKeys{byPrefix: map[string][]domain.APIKeyRecord{"abcd1234": {key}}, active: []domain.APIKeyRecord{key}}
	if code := runAuth(t, middleware.APIKeyAuth{Keys: keys}, raw); code != http.StatusUnauthorized {
		t.Fatalf("expired key status=%d, want 401", code)
	}
}

func TestAPIKeyAuthFallbackError(t *testing.T) {
	keys := &prefixKeys{byPrefix: map[string][]domain.APIKeyRecord{}, activeErr: errors.New("db down")}
	if code := runAuth(t, middleware.APIKeyAuth{Keys: keys}, "somekey123456789"); code != http.StatusUnauthorized {
		t.Fatalf("fallback error status=%d, want 401", code)
	}
}
