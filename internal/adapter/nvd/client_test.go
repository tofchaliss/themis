package nvd_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/adapter/nvd"
)

func TestClientFetchModifiedSince(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2021-23337",
					"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "v", "baseSeverity": "HIGH"}}]},
					"configurations": [{"nodes": [{"cpeMatch": [{
						"vulnerable": true,
						"criteria": "cpe:2.3:a:lodash:lodash:*:*:*:*:*:*:*:*",
						"versionEndExcluding": "4.17.21"
					}]}]}]
				}
			}]
		}`))
	}))
	t.Cleanup(srv.Close)

	client := nvd.NewClient(nvd.ClientConfig{
		BaseURL:     srv.URL,
		RateLimiter: nvd.NewTokenBucket(100, 100),
	})
	vulns, err := client.FetchModifiedSince(context.Background(), time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatalf("FetchModifiedSince() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].CVEID != "CVE-2021-23337" {
		t.Fatalf("vulns = %#v", vulns)
	}
}

// TestClientFetchRangeAndCVSSFallback covers the CR-6/CR-5 NVD fixes: a CPE
// range [2.0, 2.5) becomes a single AND group (no lower-bound drop), CVSS is read
// from cvssMetricV30 when v3.1 is absent, and a self-named vendor/product no
// longer fabricates the npm ecosystem.
func TestClientFetchRangeAndCVSSFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"vulnerabilities": [{
				"cve": {
					"id": "CVE-2020-0001",
					"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 9.8, "vectorString": "v30", "baseSeverity": "CRITICAL"}}]},
					"configurations": [{"nodes": [{"cpeMatch": [{
						"vulnerable": true,
						"criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
						"versionStartIncluding": "2.0",
						"versionEndExcluding": "2.5"
					}]}]}]
				}
			}]
		}`))
	}))
	t.Cleanup(srv.Close)

	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})
	vulns, err := client.FetchModifiedSince(context.Background(), time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatalf("FetchModifiedSince() error = %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("want 1 vuln, got %#v", vulns)
	}
	v := vulns[0]
	if v.Severity != "critical" || v.CVSSScore != 9.8 || v.CVSSVector != "v30" {
		t.Fatalf("v3.0 CVSS not read: %+v", v)
	}
	if len(v.AffectedVersions) != 1 || v.AffectedVersions[0] != ">= 2.0, < 2.5" {
		t.Fatalf("range not a single AND group: %#v", v.AffectedVersions)
	}
	if v.Ecosystem == "npm" {
		t.Fatalf("openssl:openssl must not be classified npm, got %q", v.Ecosystem)
	}
}

func TestClientFetchByCVEID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("cveId") != "CVE-2020-0001" {
			http.Error(w, "bad query", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"totalResults": 1,
			"vulnerabilities": [{"cve": {"id": "CVE-2020-0001",
				"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "v31", "baseSeverity": "CRITICAL"}}]}}}]
		}`))
	}))
	t.Cleanup(srv.Close)
	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})

	data, found, err := client.FetchByCVEID(context.Background(), "CVE-2020-0001")
	if err != nil || !found {
		t.Fatalf("FetchByCVEID() found=%v err=%v", found, err)
	}
	if data.Severity != "critical" || data.Score != 9.8 || data.Vector != "v31" {
		t.Fatalf("data = %+v", data)
	}

	// Empty id → not found, no request.
	if _, found, err := client.FetchByCVEID(context.Background(), "  "); err != nil || found {
		t.Fatalf("empty id found=%v err=%v", found, err)
	}
}

func TestClientFetchByCVEIDNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults": 0, "vulnerabilities": []}`))
	}))
	t.Cleanup(srv.Close)
	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})
	if _, found, err := client.FetchByCVEID(context.Background(), "CVE-1999-9999"); err != nil || found {
		t.Fatalf("not-found found=%v err=%v", found, err)
	}
}

func TestClientFetchByCVEID404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})
	if _, found, err := client.FetchByCVEID(context.Background(), "CVE-2020-0001"); err != nil || found {
		t.Fatalf("404 found=%v err=%v", found, err)
	}
}

func TestClientFetchByCVEIDNoCVSS(t *testing.T) {
	// A record present but with no CVSS metrics → not found (so backfill marks it
	// checked and retries later rather than storing severity=unknown/score=0).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2020-0001", "metrics": {}}}]}`))
	}))
	t.Cleanup(srv.Close)
	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})
	if _, found, err := client.FetchByCVEID(context.Background(), "CVE-2020-0001"); err != nil || found {
		t.Fatalf("no-cvss found=%v err=%v", found, err)
	}
}

func TestClientFetchByCVEIDErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})
	if _, _, err := client.FetchByCVEID(context.Background(), "CVE-2020-0001"); err == nil {
		t.Fatal("expected error status")
	}
}

func TestClientFetchErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	client := nvd.NewClient(nvd.ClientConfig{BaseURL: srv.URL, RateLimiter: nvd.NewTokenBucket(100, 100)})
	if _, err := client.FetchModifiedSince(context.Background(), time.Now().UTC()); err == nil {
		t.Fatal("expected error")
	}
}
