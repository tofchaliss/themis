package api_test

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/adapter/api"
)

func TestHMACRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.StringMatching(`[ -~]{1,32}`).Draw(t, "secret")
		body := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "body")

		sig := api.SignHMAC(secret, body)

		req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
		req.Header.Set("X-Themis-Signature", sig)
		if !api.VerifyHMACSignature(secret, req) {
			t.Fatalf("valid signature rejected (secret=%q len(body)=%d)", secret, len(body))
		}

		// Case-insensitive on the hex header.
		req2 := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
		req2.Header.Set("X-Themis-Signature", strings.ToUpper(sig))
		if !api.VerifyHMACSignature(secret, req2) {
			t.Fatalf("uppercase signature rejected (secret=%q)", secret)
		}
	})
}

func TestHMACRejectsTamperProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.StringMatching(`[ -~]{1,32}`).Draw(t, "secret")
		body := rapid.SliceOfN(rapid.Byte(), 0, 256).Draw(t, "body")
		sig := api.SignHMAC(secret, body)

		// Wrong secret must fail.
		otherSecret := secret + "x"
		reqSecret := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
		reqSecret.Header.Set("X-Themis-Signature", sig)
		if api.VerifyHMACSignature(otherSecret, reqSecret) {
			t.Fatalf("wrong secret accepted (secret=%q)", secret)
		}

		// Mutated body must fail.
		mutated := append([]byte{0x00}, body...)
		reqBody := httptest.NewRequest("POST", "/webhook", bytes.NewReader(mutated))
		reqBody.Header.Set("X-Themis-Signature", sig)
		if api.VerifyHMACSignature(secret, reqBody) {
			t.Fatalf("mutated body accepted (secret=%q)", secret)
		}

		// Missing signature header must fail.
		reqEmpty := httptest.NewRequest("POST", "/webhook", bytes.NewReader(body))
		if api.VerifyHMACSignature(secret, reqEmpty) {
			t.Fatalf("missing signature accepted (secret=%q)", secret)
		}
	})
}
