package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sign(secret, body string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestWebhookVerify(t *testing.T) {
	body := `{"scan":"result"}`
	v := WebhookVerifier{Secret: "s3cr3t"}

	if !v.Verify([]byte(body), sign("s3cr3t", body)) {
		t.Error("valid signature rejected")
	}
	if v.Verify([]byte(body), sign("wrong", body)) {
		t.Error("wrong-secret signature accepted")
	}
	if v.Verify([]byte(body), "not-hex-zz") {
		t.Error("malformed hex signature accepted")
	}
	if (WebhookVerifier{Secret: ""}).Verify([]byte(body), sign("", body)) {
		t.Error("empty secret accepted a signature")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestWebhookMiddleware(t *testing.T) {
	body := `{"scan":"result"}`
	secret := "s3cr3t"

	t.Run("valid re-injects body", func(t *testing.T) {
		var got string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			got = string(b)
			w.WriteHeader(http.StatusOK)
		})
		h := WebhookVerifier{Secret: secret}.Middleware(next)
		req := httptest.NewRequest(http.MethodPost, "/webhooks/scan", strings.NewReader(body))
		req.Header.Set(SignatureHeader, sign(secret, body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if got != body {
			t.Errorf("handler read body %q, want %q", got, body)
		}
	})

	t.Run("no secret configured", func(t *testing.T) {
		h := WebhookVerifier{Secret: ""}.Middleware(http.NotFoundHandler())
		req := httptest.NewRequest(http.MethodPost, "/webhooks/scan", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		h := WebhookVerifier{Secret: secret}.Middleware(http.NotFoundHandler())
		req := httptest.NewRequest(http.MethodPost, "/webhooks/scan", strings.NewReader(body))
		req.Header.Set(SignatureHeader, sign("wrong", body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("unreadable body", func(t *testing.T) {
		h := WebhookVerifier{Secret: secret}.Middleware(http.NotFoundHandler())
		req := httptest.NewRequest(http.MethodPost, "/webhooks/scan", errReader{})
		req.Header.Set(SignatureHeader, sign(secret, body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}
