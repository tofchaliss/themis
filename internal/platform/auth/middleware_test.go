package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeKeys is an in-memory KeyStore for middleware unit tests.
type fakeKeys struct {
	keys []APIKey
	err  error
}

func (f fakeKeys) ActiveKeys(context.Context) ([]APIKey, error) { return f.keys, f.err }

// matchHash is a stand-in Compare: KeyHash "H:<raw>" matches raw, so tests need no bcrypt.
func matchHash(hash, pw []byte) error {
	if string(hash) == "H:"+string(pw) {
		return nil
	}
	return errors.New("mismatch")
}

func at(ts time.Time) *time.Time { return &ts }

func newAuth(store KeyStore) Authenticator {
	return Authenticator{
		Keys:    store,
		Now:     func() time.Time { return time.Unix(1000, 0) },
		Compare: matchHash,
	}
}

func TestRequireAPIKey(t *testing.T) {
	past := time.Unix(500, 0)
	future := time.Unix(5000, 0)

	tests := []struct {
		name       string
		header     string
		store      fakeKeys
		wantStatus int
		wantKeyID  string
	}{
		{"missing header", "", fakeKeys{keys: []APIKey{{ID: "k", KeyHash: "H:secret"}}}, http.StatusUnauthorized, ""},
		{"store error", "secret", fakeKeys{err: errors.New("db down")}, http.StatusUnauthorized, ""},
		{"valid no expiry", "secret", fakeKeys{keys: []APIKey{{ID: "k1", Name: "ci", KeyHash: "H:secret", Scopes: []string{ScopeAdmin}}}}, http.StatusOK, "k1"},
		{"valid future expiry", "secret", fakeKeys{keys: []APIKey{{ID: "k2", KeyHash: "H:secret", ExpiresAt: at(future)}}}, http.StatusOK, "k2"},
		{"expired key", "secret", fakeKeys{keys: []APIKey{{ID: "k3", KeyHash: "H:secret", ExpiresAt: at(past)}}}, http.StatusUnauthorized, ""},
		{"wrong key", "nope", fakeKeys{keys: []APIKey{{ID: "k", KeyHash: "H:secret"}}}, http.StatusUnauthorized, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var seen Principal
			var sawPrincipal bool
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen, sawPrincipal = PrincipalFrom(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			h := newAuth(tt.store).RequireAPIKey(next)

			req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
			if tt.header != "" {
				req.Header.Set(APIKeyHeader, tt.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantKeyID != "" {
				if !sawPrincipal {
					t.Fatalf("handler saw no principal")
				}
				if seen.KeyID != tt.wantKeyID {
					t.Errorf("principal KeyID = %q, want %q", seen.KeyID, tt.wantKeyID)
				}
			}
		})
	}
}

func TestRequireWriteScope(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		principal  *Principal
		wantStatus int
	}{
		{"GET passes without principal", http.MethodGet, nil, http.StatusOK},
		{"GET passes read-only", http.MethodGet, &Principal{Scopes: []string{ScopeRead}}, http.StatusOK},
		{"POST admin passes", http.MethodPost, &Principal{Scopes: []string{ScopeAdmin}}, http.StatusOK},
		{"POST product-scoped passes", http.MethodPost, &Principal{Scopes: []string{ProductScopePrefix + "p1"}}, http.StatusOK},
		{"POST read-only forbidden", http.MethodPost, &Principal{Scopes: []string{ScopeRead}}, http.StatusForbidden},
		{"DELETE no principal unauthorized", http.MethodDelete, nil, http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
			h := RequireWriteScope(next)
			req := httptest.NewRequest(tt.method, "/x", nil)
			if tt.principal != nil {
				req = req.WithContext(WithPrincipal(req.Context(), *tt.principal))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestRequireScope(t *testing.T) {
	tests := []struct {
		name        string
		principal   *Principal
		required    string
		wantStatus  int
	}{
		{"no principal", nil, ScopeRead, http.StatusUnauthorized},
		{"admin passes any", &Principal{KeyID: "k", Scopes: []string{ScopeAdmin}}, "whatever", http.StatusOK},
		{"exact scope passes", &Principal{KeyID: "k", Scopes: []string{ScopeRead}}, ScopeRead, http.StatusOK},
		{"missing scope forbidden", &Principal{KeyID: "k", Scopes: []string{ScopeRead}}, ScopeAdmin, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
			h := RequireScope(tt.required)(next)

			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			if tt.principal != nil {
				req = req.WithContext(WithPrincipal(req.Context(), *tt.principal))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}
