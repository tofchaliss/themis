package feed_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// osvServer returns an httptest server that replies to /v1/query with the given raw
// records and records the last request body for assertions.
func osvServer(t *testing.T, records ...string) (*httptest.Server, *[]byte) {
	t.Helper()
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		lastBody, _ = io.ReadAll(r.Body)
		vulns := make([]json.RawMessage, 0, len(records))
		for _, rec := range records {
			vulns = append(vulns, json.RawMessage(rec))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": vulns})
	}))
	t.Cleanup(srv.Close)
	return srv, &lastBody
}

const osvVulnCVE = `{
  "id": "CVE-2024-1000",
  "modified": "2024-01-02T00:00:00Z",
  "database_specific": {"severity": "HIGH", "cvss_score": 7.5},
  "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]
}`

func TestOSVClient_VulnsForPackage_PyPI(t *testing.T) {
	srv, body := osvServer(t, osvVulnCVE)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	got, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL: "pkg:pypi/urllib3@1.26.20", Name: "urllib3", Version: "1.26.20", Ecosystem: "PyPI",
	})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1", len(got))
	}
	if got[0].CVE.String() != "CVE-2024-1000" {
		t.Errorf("cve = %s, want CVE-2024-1000", got[0].CVE.String())
	}
	vf, ok := got[0].Proposal.VulnFacts()
	if !ok || vf.Severity != "high" {
		t.Errorf("vuln facts = %+v ok=%v, want severity high", vf, ok)
	}

	// The request must target PyPI/urllib3 at the component version.
	var req struct {
		Version string `json:"version"`
		Package struct {
			Name, Ecosystem string
		} `json:"package"`
	}
	if err := json.Unmarshal(*body, &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if req.Package.Ecosystem != "PyPI" || req.Package.Name != "urllib3" || req.Version != "1.26.20" {
		t.Errorf("query = %+v, want PyPI/urllib3@1.26.20", req)
	}
}

func TestOSVClient_MavenNameMapping(t *testing.T) {
	srv, body := osvServer(t) // no records; we only assert the request shape
	c := feed.NewOSVClient(srv.URL, srv.Client())

	if _, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL: "pkg:maven/io.prometheus/prometheus-metrics-tracer-common@1.3.10", Name: "prometheus-metrics-tracer-common",
	}); err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	var req struct {
		Package struct{ Name, Ecosystem string } `json:"package"`
	}
	_ = json.Unmarshal(*body, &req)
	if req.Package.Ecosystem != "Maven" || req.Package.Name != "io.prometheus:prometheus-metrics-tracer-common" {
		t.Errorf("maven query = %+v, want Maven/io.prometheus:prometheus-metrics-tracer-common", req.Package)
	}
}

func TestOSVClient_DistroComponentSkipped(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []any{}})
	}))
	t.Cleanup(srv.Close)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	got, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL: "pkg:rpm/rocky/gnutls@3.6.16-8.el8_10.5?distro=rocky-8.9", Name: "gnutls",
	})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d proposals, want 0 (distro is not OSV-query-by-package)", len(got))
	}
	if hit {
		t.Error("distro component should not have issued an OSV query")
	}
}

func TestOSVClient_SkipsGHSAOnlyRecord(t *testing.T) {
	ghsaOnly := `{"id": "GHSA-aaaa-bbbb-cccc", "modified": "2024-01-02T00:00:00Z"}`
	srv, _ := osvServer(t, ghsaOnly, osvVulnCVE)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	got, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL: "pkg:pypi/foo@1.0", Name: "foo",
	})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if len(got) != 1 { // the GHSA-only record is skipped; the CVE record survives
		t.Fatalf("got %d proposals, want 1 (GHSA-only skipped)", len(got))
	}
}

// OSV can carry a CVSS 4.0 severity vector. The greenfield takes the score as given
// (database_specific), so a v4.0 vector must translate cleanly (stored, not parsed) with
// the severity resolved from the numeric score / label — never dropped to unknown.
func TestOSVClient_CVSSv4VectorTolerated(t *testing.T) {
	v4 := `{
	  "id": "CVE-2026-4444",
	  "modified": "2026-01-02T00:00:00Z",
	  "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}],
	  "database_specific": {"severity": "HIGH", "cvss_score": 8.5}
	}`
	srv, _ := osvServer(t, v4)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	got, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{PURL: "pkg:pypi/foo@1", Name: "foo"})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	vf, ok := onlyProposalOSV(t, got).Proposal.VulnFacts()
	if !ok || vf.Severity != "high" || vf.CVSS.Score() != 8.5 {
		t.Errorf("osv v4.0: severity=%s score=%.1f, want high/8.5", vf.Severity, vf.CVSS.Score())
	}
	if vf.CVSS.Vector() == "" {
		t.Error("osv v4.0 vector should be preserved")
	}
}

func onlyProposalOSV(t *testing.T, got []app.ProposalFor) app.ProposalFor {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1", len(got))
	}
	return got[0]
}

func TestOSVClient_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	if _, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL: "pkg:pypi/foo@1.0", Name: "foo",
	}); err == nil {
		t.Fatal("expected an error on 500")
	}
}

// compile-time confirmation the client is a PackageVulnSource.
var _ app.PackageVulnSource = (*feed.OSVClient)(nil)
