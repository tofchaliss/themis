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
