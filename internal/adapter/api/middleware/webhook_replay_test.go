package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/api/middleware"
)

func webhookReq(tsHeader, sig string, body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(string(body)))
	if tsHeader != "" {
		req.Header.Set("X-Themis-Timestamp", tsHeader)
	}
	if sig != "" {
		req.Header.Set("X-Themis-Signature", sig)
	}
	return req
}

func runWebhook(req *http.Request) int {
	auth := middleware.WebhookAuth{Secret: "topsecret"}
	rec := httptest.NewRecorder()
	auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rec, req)
	return rec.Code
}

func TestWebhookReplayProtection(t *testing.T) {
	secret := "topsecret"
	body := []byte(`{"ok":true}`)
	now := time.Now().Unix()
	sig := func(ts int64) string { return middleware.SignWebhook(secret, ts, body) }

	cases := []struct {
		name string
		ts   string
		sig  string
		want int
	}{
		{"unparseable timestamp", "not-a-number", "abc", http.StatusUnauthorized},
		{"stale timestamp", strconv.FormatInt(now-3600, 10), sig(now - 3600), http.StatusUnauthorized},
		{"future beyond tolerance", strconv.FormatInt(now+3600, 10), sig(now + 3600), http.StatusUnauthorized},
		{"valid timestamp, missing signature", strconv.FormatInt(now, 10), "", http.StatusUnauthorized},
		{"valid", strconv.FormatInt(now, 10), sig(now), http.StatusAccepted},
		{"near-future within tolerance", strconv.FormatInt(now+10, 10), sig(now + 10), http.StatusAccepted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code := runWebhook(webhookReq(c.ts, c.sig, body)); code != c.want {
				t.Fatalf("status=%d, want %d", code, c.want)
			}
		})
	}
}
