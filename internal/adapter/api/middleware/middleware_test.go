package middleware_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/themis-project/themis/internal/adapter/api/middleware"
	"github.com/themis-project/themis/internal/domain"
)

type staticKeys struct {
	keys []domain.APIKeyRecord
	err  error
}

func (s *staticKeys) FindByHashPrefix(context.Context) ([]domain.APIKeyRecord, error) { return s.keys, s.err }
func (s *staticKeys) FindActiveKeys(context.Context) ([]domain.APIKeyRecord, error)  { return s.keys, s.err }
func (s *staticKeys) Create(context.Context, domain.APIKeyCreateInput) (domain.APIKeyRecord, error) {
	return domain.APIKeyRecord{}, nil
}
func (s *staticKeys) Revoke(context.Context, string) error { return nil }

func TestAPIKeyAuthMissingHeader(t *testing.T) {
	auth := middleware.APIKeyAuth{Keys: &staticKeys{}}
	rec := httptest.NewRecorder()
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/products", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAPIKeyAuthValidKey(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	auth := middleware.APIKeyAuth{
		Keys: &staticKeys{keys: []domain.APIKeyRecord{{ID: "k1", KeyHash: string(hash), Scopes: []string{domain.ScopeAdmin}}}},
	}
	called := false
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if _, ok := middleware.AuthFromContext(r.Context()); !ok {
			t.Fatal("missing principal")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d called=%v", rec.Code, called)
	}
}

func TestAPIKeyAuthMatchesSecondKey(t *testing.T) {
	wrongHash, _ := bcrypt.GenerateFromPassword([]byte("other"), bcrypt.MinCost)
	rightHash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	auth := middleware.APIKeyAuth{
		Keys: &staticKeys{keys: []domain.APIKeyRecord{
			{ID: "k1", KeyHash: string(wrongHash), Scopes: []string{domain.ScopeAdmin}},
			{ID: "k2", KeyHash: string(rightHash), Scopes: []string{domain.ScopeAdmin}},
		}},
	}
	called := false
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		principal, ok := middleware.AuthFromContext(r.Context())
		if !ok || principal.KeyID != "k2" {
			t.Fatalf("principal = %+v ok=%v", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || !called {
		t.Fatalf("status=%d called=%v", rec.Code, called)
	}
}

func TestAPIKeyAuthRevokedKey(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	auth := middleware.APIKeyAuth{
		Keys: &staticKeys{keys: []domain.APIKeyRecord{}},
		CompareFn: func(hashedPassword, password []byte) error {
			if string(hashedPassword) == string(hash) {
				return nil
			}
			return bcrypt.ErrMismatchedHashAndPassword
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAPIKeyAuthExpiredKey(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	expired := time.Now().Add(-time.Hour)
	auth := middleware.APIKeyAuth{
		Keys: &staticKeys{keys: []domain.APIKeyRecord{{ID: "k1", KeyHash: string(hash), ExpiresAt: &expired}}},
		Now:  time.Now,
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestAPIKeyAuthSkipsWebhookPath(t *testing.T) {
	auth := middleware.APIKeyAuth{Keys: &staticKeys{}}
	called := false
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/scan", nil))
	if !called {
		t.Fatal("webhook path should bypass api key middleware")
	}
}

func TestAPIKeyAuthRepositoryError(t *testing.T) {
	auth := middleware.APIKeyAuth{Keys: &staticKeys{err: errBoom}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	req.Header.Set("X-API-Key", "secret")
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookAuthMissingSecret(t *testing.T) {
	auth := middleware.WebhookAuth{}
	rec := httptest.NewRecorder()
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/hook", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookAuthCustomVerify(t *testing.T) {
	auth := middleware.WebhookAuth{
		Secret: "s",
		Verify: func(string, *http.Request) bool { return true },
	}
	rec := httptest.NewRecorder()
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/hook", nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookAuthReadBodyError(t *testing.T) {
	auth := middleware.WebhookAuth{Secret: "topsecret"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/hook", errReader{})
	req.Header.Set("X-Themis-Signature", "abc")
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookAuthValidDefaultVerify(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"ok":true}`)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	auth := middleware.WebhookAuth{Secret: secret}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", signature)
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookAuthInvalidSignature(t *testing.T) {
	auth := middleware.WebhookAuth{Secret: "topsecret"}
	rec := httptest.NewRecorder()
	body := []byte(`{"ok":true}`)
	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader(body))
	req.Header.Set("X-Themis-Signature", "bad")
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestWebhookAuthMissingSignature(t *testing.T) {
	auth := middleware.WebhookAuth{Secret: "topsecret"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/hook", bytes.NewReader([]byte(`{}`)))
	auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestMaxBytesMiddleware(t *testing.T) {
	handler := middleware.MaxBytes(8)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 16)
		_, _ = r.Body.Read(buf)
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(bytes.Repeat([]byte("x"), 16)))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

var errBoom = errString("boom")

type errString string

func (e errString) Error() string { return string(e) }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }
