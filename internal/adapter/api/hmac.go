package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// VerifyHMACSignature validates the X-Themis-Signature header for a request body.
func VerifyHMACSignature(secret string, r *http.Request) bool {
	signature := strings.TrimSpace(r.Header.Get("X-Themis-Signature"))
	if signature == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))

	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(strings.ToLower(signature)), []byte(strings.ToLower(expected)))
}

// SignHMAC computes an HMAC signature for tests and CI integrations.
func SignHMAC(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
