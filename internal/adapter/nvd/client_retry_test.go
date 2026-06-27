package nvd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newTestClient builds a client with a no-op backoff sleep so retry tests run instantly.
func newTestClient(baseURL string) *Client {
	c := NewClient(ClientConfig{BaseURL: baseURL, RateLimiter: NewTokenBucket(1000, 1000)})
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

const validCVSSBody = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-1234",` +
	`"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5,"vectorString":"CVSS:3.1/AV:N/AC:L","baseSeverity":"HIGH"}}]}}}]}`

// cloudflare503 mimics NVD's Cloudflare challenge body so the truncation path is exercised.
var cloudflare503 = "<html><body><h1>503 Service Unavailable</h1>\nNo server is available to handle this request.\n" +
	"<script>" + strings.Repeat("x", 4000) + "</script></body></html>"

func TestFetchByCVEIDRetriesTransient503ThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(cloudflare503))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validCVSSBody))
	}))
	t.Cleanup(srv.Close)

	client := newTestClient(srv.URL)
	data, found, err := client.FetchByCVEID(context.Background(), "CVE-2021-1234")
	if err != nil || !found {
		t.Fatalf("expected success after retries: found=%v err=%v", found, err)
	}
	if data.Score != 7.5 || data.Severity != "high" {
		t.Fatalf("unexpected cvss: %+v", data)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 attempts (2×503 + 1×200), got %d", got)
	}
}

func TestFetchByCVEIDExhaustsRetriesAndTruncatesBody(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(cloudflare503))
	}))
	t.Cleanup(srv.Close)

	client := newTestClient(srv.URL)
	_, _, err := client.FetchByCVEID(context.Background(), "CVE-2021-1234")
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&calls); got != nvdMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", nvdMaxAttempts, got)
	}
	// The multi-kilobyte Cloudflare HTML blob must not flood the log line: the
	// message is bounded and the large script payload is dropped.
	if len(err.Error()) > 200 {
		t.Fatalf("error body not truncated (%d bytes): %q", len(err.Error()), err.Error())
	}
	if strings.Contains(err.Error(), strings.Repeat("x", 200)) {
		t.Fatalf("error body still contains the cloudflare script blob: %q", err.Error())
	}
	if !strings.HasSuffix(err.Error(), "…") {
		t.Fatalf("expected truncation ellipsis: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("error should report status 503: %q", err.Error())
	}
}

func TestParseRetryAfterAndBackoff(t *testing.T) {
	if got := parseRetryAfter("5"); got != 5*time.Second {
		t.Fatalf("parseRetryAfter(5)=%v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Fatalf("parseRetryAfter(empty)=%v", got)
	}
	if got := parseRetryAfter("Wed, 21 Oct 2026 07:28:00 GMT"); got != 0 {
		t.Fatalf("parseRetryAfter(http-date)=%v", got)
	}
	// Retry-After wins over exponential backoff.
	if got := backoffDelay(0, 9*time.Second); got != 9*time.Second {
		t.Fatalf("backoffDelay honoring retry-after=%v", got)
	}
	// Exponential, capped at 30s.
	if got := backoffDelay(1, 0); got != 2*time.Second {
		t.Fatalf("backoffDelay(1)=%v", got)
	}
	if got := backoffDelay(10, 0); got != 30*time.Second {
		t.Fatalf("backoffDelay cap=%v", got)
	}
}

func TestIsTransientNVDStatus(t *testing.T) {
	for _, s := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout} {
		if !isTransientNVDStatus(s) {
			t.Fatalf("status %d should be transient", s)
		}
	}
	for _, s := range []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError, http.StatusForbidden} {
		if isTransientNVDStatus(s) {
			t.Fatalf("status %d should not be transient", s)
		}
	}
}
