package osv_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/adapter/osv"
	"github.com/themis-project/themis/internal/domain"
)

func TestClientQueryByEcosystem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"results": [{
				"vulns": [{
					"id": "CVE-2021-23337",
					"severity": [{"type": "CVSS_V3", "score": "7.5"}],
					"affected": [{
						"package": {"ecosystem": "npm", "name": "lodash"},
						"ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]
					}]
				}]
			}]
		}`))
	}))
	t.Cleanup(srv.Close)

	client := osv.NewClient(osv.ClientConfig{BaseURL: srv.URL, RateLimiter: osv.NewTokenBucket(100, 100)})
	vulns, err := client.QueryByEcosystem(context.Background(), "npm", []domain.OSVPackageQuery{{Name: "lodash"}})
	if err != nil {
		t.Fatalf("QueryByEcosystem() error = %v", err)
	}
	if len(vulns) != 1 || vulns[0].PackageName != "lodash" {
		t.Fatalf("vulns = %#v", vulns)
	}
}
