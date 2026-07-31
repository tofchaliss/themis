package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
)

// SignatureHeader carries the hex HMAC-SHA256 of the raw request body for webhook ingest (D5).
const SignatureHeader = "X-Themis-Signature"

// WebhookVerifier authenticates CI webhook requests by a shared-secret HMAC over the raw body
// — a trust path distinct from X-API-Key (D5). A zero Secret rejects every request (never
// open by default).
type WebhookVerifier struct {
	Secret string
}

// Verify reports whether signature is a valid hex HMAC-SHA256(body, secret), compared in
// constant time. An empty secret or malformed signature always fails.
func (v WebhookVerifier) Verify(body []byte, signature string) bool {
	if v.Secret == "" {
		return false
	}
	want, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(v.Secret))
	mac.Write(body)
	return hmac.Equal(want, mac.Sum(nil))
}

// Middleware validates the webhook signature over the (fully buffered) request body and, on
// success, re-injects the body so the downstream handler can read it. Failure returns 401.
func (v WebhookVerifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v.Secret == "" {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "webhook secret not configured")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, "Bad Request", "cannot read request body")
			return
		}
		_ = r.Body.Close()
		if !v.Verify(body, r.Header.Get(SignatureHeader)) {
			writeProblem(w, http.StatusUnauthorized, "Unauthorized", "invalid webhook signature")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		next.ServeHTTP(w, r)
	})
}
