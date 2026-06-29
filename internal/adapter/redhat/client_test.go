package redhat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const ncursesJSON = `{
  "name": "CVE-2022-29458",
  "threat_severity": "Low",
  "cvss3": {"cvss3_base_score": "6.1"},
  "statement": "vulnerable code is the build-time tic",
  "package_state": [
    {"product_name":"Red Hat Enterprise Linux 8","fix_state":"Not affected","package_name":"ncurses","cpe":"cpe:/o:redhat:enterprise_linux:8"}
  ],
  "affected_release": [
    {"product_name":"Red Hat Enterprise Linux 9","package":"ncurses-0:6.2-10.20210508.el9_6.2","cpe":"cpe:/o:redhat:enterprise_linux:9","advisory":"RHSA-2025:12876"}
  ]
}`

func newTestClient(url string) *Client {
	c := NewClient(ClientConfig{BaseURL: url})
	c.sleep = func(context.Context, time.Duration) error { return nil } // no real backoff in tests
	return c
}

func TestFetchCVEParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cve/CVE-2022-29458.json" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(ncursesJSON))
	}))
	t.Cleanup(srv.Close)

	report, found, err := newTestClient(srv.URL).FetchCVE(context.Background(), "CVE-2022-29458")
	if err != nil || !found {
		t.Fatalf("FetchCVE found=%v err=%v", found, err)
	}
	if report.ThreatSeverity != "Low" || report.CVSS3 != "6.1" {
		t.Fatalf("severity/cvss = %+v", report)
	}
	if v := report.VerdictForStream("ncurses", "8"); !v.NotAffected {
		t.Fatalf("el8 verdict = %+v", v)
	}
	if v := report.VerdictForStream("ncurses", "9"); v.FixedEVR != "0:6.2-10.20210508.el9_6.2" {
		t.Fatalf("el9 fix = %+v", v)
	}
}

func TestFetchCVENotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	if _, found, err := newTestClient(srv.URL).FetchCVE(context.Background(), "CVE-1999-9999"); err != nil || found {
		t.Fatalf("404 found=%v err=%v", found, err)
	}
}

func TestFetchCVEEmptyID(t *testing.T) {
	if _, found, err := newTestClient("http://unused").FetchCVE(context.Background(), "  "); err != nil || found {
		t.Fatalf("empty id found=%v err=%v", found, err)
	}
}

func TestFetchCVETransientThenSuccess(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits == 1 {
			http.Error(w, "throttled", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(ncursesJSON))
	}))
	t.Cleanup(srv.Close)
	_, found, err := newTestClient(srv.URL).FetchCVE(context.Background(), "CVE-2022-29458")
	if err != nil || !found || hits != 2 {
		t.Fatalf("retry: found=%v err=%v hits=%d", found, err, hits)
	}
}

func TestFetchCVEErrorStatusExhausted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	if _, _, err := newTestClient(srv.URL).FetchCVE(context.Background(), "CVE-2022-29458"); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
}

func TestFetchCVEBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{not json"))
	}))
	t.Cleanup(srv.Close)
	if _, _, err := newTestClient(srv.URL).FetchCVE(context.Background(), "CVE-2022-29458"); err == nil {
		t.Fatal("expected decode error")
	}
}

type errLimiter struct{}

func (errLimiter) Wait(context.Context) error { return errors.New("rate limited") }

func TestFetchCVELimiterError(t *testing.T) {
	c := NewClient(ClientConfig{BaseURL: "http://unused", RateLimiter: errLimiter{}})
	if _, _, err := c.FetchCVE(context.Background(), "CVE-2022-29458"); err == nil {
		t.Fatal("expected limiter error")
	}
}

func TestFetchCVENetworkErrorRetries(t *testing.T) {
	// Connection refused on every attempt → retried then returned as an error.
	c := newTestClient("http://127.0.0.1:1")
	if _, _, err := c.FetchCVE(context.Background(), "CVE-2022-29458"); err == nil {
		t.Fatal("expected network error")
	}
}

func TestParseCVENameFallback(t *testing.T) {
	// A document with no "name" falls back to the requested CVE id.
	report, err := parseCVE([]byte(`{"threat_severity":"Important"}`), "CVE-2024-0001")
	if err != nil || report.CVEID != "CVE-2024-0001" || report.ThreatSeverity != "Important" {
		t.Fatalf("name fallback = %+v err=%v", report, err)
	}
}

func TestSleepContext(t *testing.T) {
	if err := sleepContext(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("elapsed sleep = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepContext(ctx, time.Hour); err == nil {
		t.Fatal("cancelled sleep must return ctx error")
	}
}
