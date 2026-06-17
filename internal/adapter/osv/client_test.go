package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/domain"
)

func TestClientAlpineCVENormalizationAndCVSSVector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"results": [{
				"vulns": [{
					"id": "ALPINE-CVE-2024-0001",
					"aliases": ["CVE-2024-0001"],
					"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
					"affected": [{
						"package": {"ecosystem": "Alpine", "name": "busybox"},
						"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.36.1-r0"}]}]
					}]
				}]
			}]
		}`))
	}))
	t.Cleanup(srv.Close)

	client := osv.NewClient(osv.ClientConfig{BaseURL: srv.URL, RateLimiter: osv.NewTokenBucket(100, 100)})
	vulns, err := client.QueryByEcosystem(context.Background(), "apk", []domain.OSVPackageQuery{{Name: "busybox"}})
	if err != nil {
		t.Fatalf("QueryByEcosystem() error = %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("vulns = %#v", vulns)
	}
	if vulns[0].CVEID != "CVE-2024-0001" {
		t.Fatalf("CVEID = %q", vulns[0].CVEID)
	}
	if vulns[0].CVSSScore < 9.0 {
		t.Fatalf("CVSSScore = %v, want >= 9", vulns[0].CVSSScore)
	}
	if vulns[0].Severity != "critical" {
		t.Fatalf("Severity = %q", vulns[0].Severity)
	}
}

func TestNormalizeAlpinePackageName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"so:libssl3", "libssl3"},
		{"py3-requests", "python3-requests"},
		{"busybox", "busybox"},
	}
	for _, tc := range tests {
		if got := osv.NormalizeAlpinePackageName(tc.in); got != tc.want {
			t.Errorf("NormalizeAlpinePackageName(%q) = %q", tc.in, got)
		}
	}
}

func TestComponentFetcherUnsupportedEcosystemSummary(t *testing.T) {
	log := &osv.CaptureCorrelationLogger{}
	fetcher := &osv.ComponentFetcher{Logger: log}
	_, err := fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		PURL: "pkg:rpm/openssl@1.0", Ecosystem: "rpm", Name: "openssl", Version: "1.0",
	})
	if err != nil {
		t.Fatalf("FetchForComponent() error = %v", err)
	}
	if log.Unsupported != 1 {
		t.Fatalf("Unsupported = %d", log.Unsupported)
	}
	fetcher.EmitCorrelationSummary()
	if log.SummaryCounts["rpm"] != 1 {
		t.Fatalf("SummaryCounts = %#v", log.SummaryCounts)
	}
}

func TestComponentFetcherMalformedPURL(t *testing.T) {
	log := &osv.CaptureCorrelationLogger{}
	fetcher := &osv.ComponentFetcher{Logger: log}
	_, err := fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "apk", Version: "1.0",
	})
	if err != nil {
		t.Fatalf("FetchForComponent() error = %v", err)
	}
	if len(log.Malformed) != 1 {
		t.Fatalf("Malformed = %#v", log.Malformed)
	}
}
