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

// osvRedHatAdvisory mirrors OSV.dev's Red Hat ecosystem shape: the id is an RHSA, aliases is
// null, and the addressed CVEs live in `upstream` — one advisory fixing two CVEs.
const osvRedHatAdvisory = `{
  "id": "RHSA-2023:0835",
  "modified": "2023-02-16T00:00:00Z",
  "aliases": null,
  "upstream": ["CVE-2022-40897", "CVE-2021-3572", "CVE-2022-40897"],
  "database_specific": {"severity": "HIGH", "cvss_score": 5.9},
  "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "0:53.0.0-12.el9_4.1"}]}]}]
}`

// TestOSVClient_RedHatAdvisoryUpstreamCVEs proves a distro advisory record (id "RHSA-…",
// aliases null) is correlated via its `upstream` CVEs, carding BOTH CVEs one advisory fixes.
// Before the upstream fix these records were dropped as "no canonical CVE" and RHEL/Rocky/Alma
// rpm components silently produced zero matches.
func TestOSVClient_RedHatAdvisoryUpstreamCVEs(t *testing.T) {
	srv, _ := osvServer(t, osvRedHatAdvisory)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	got, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL: "pkg:rpm/redhat/python-setuptools@39.2.0-5.el9?distro=rhel-9", Name: "python-setuptools",
		Version: "39.2.0-5.el9", Source: "python-setuptools",
	})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d proposals, want 2 (one per upstream CVE)", len(got))
	}
	seen := map[string]bool{}
	for _, p := range got {
		seen[p.CVE.String()] = true
		if vf, ok := p.Proposal.VulnFacts(); !ok || vf.Severity != "high" {
			t.Errorf("cve %s: vuln facts = %+v ok=%v, want severity high", p.CVE, vf, ok)
		}
	}
	if !seen["CVE-2022-40897"] || !seen["CVE-2021-3572"] {
		t.Errorf("carded CVEs = %v, want both CVE-2022-40897 and CVE-2021-3572", seen)
	}
}

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

// TestOSVClient_DistroComponentQueried proves a distro (rpm) component now issues an OSV
// query against the resolved distro ecosystem, keyed by the SOURCE package name, with the
// rpm epoch on the version (so OSV can version-filter). openssl-libs -> source openssl.
func TestOSVClient_DistroComponentQueried(t *testing.T) {
	var gotReq osvQueryReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []any{}})
	}))
	t.Cleanup(srv.Close)
	c := feed.NewOSVClient(srv.URL, srv.Client())

	if _, err := c.VulnsForPackage(context.Background(), app.InventoryComponent{
		PURL:    "pkg:rpm/rocky/openssl-libs@1.1.1k-17.el8_10?arch=x86_64&distro=rocky-8.10&epoch=1&upstream=openssl-1.1.1k-17.el8_10.src.rpm",
		Name:    "openssl-libs",
		Version: "1:1.1.1k-17.el8_10",
		Source:  "openssl",
	}); err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	if gotReq.Package.Ecosystem != "Rocky Linux:8" {
		t.Errorf("ecosystem = %q, want Rocky Linux:8", gotReq.Package.Ecosystem)
	}
	if gotReq.Package.Name != "openssl" {
		t.Errorf("name = %q, want openssl (source, not the binary openssl-libs)", gotReq.Package.Name)
	}
	if gotReq.Version != "1:1.1.1k-17.el8_10" {
		t.Errorf("version = %q, want epoch-bearing 1:1.1.1k-17.el8_10", gotReq.Version)
	}
}

type osvQueryReq struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
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

// Wolfi and Chainguard are ROLLING distros: no numbered release, so their OSV ecosystems carry
// no version and their PURLs may omit a version suffix entirely. The versioned-distro parser
// rejected both as unresolvable, so a Wolfi-based image correlated nothing.
func TestOSVDistroEcosystem_RollingDistros(t *testing.T) {
	for _, tc := range []struct{ name, purl, want string }{
		{"wolfi without a version suffix", "pkg:apk/wolfi/openssl@3.1.4-r1?distro=wolfi", "Wolfi"},
		{"wolfi with a date suffix", "pkg:apk/wolfi/openssl@3.1.4-r1?distro=wolfi-20230201", "Wolfi"},
		{"chainguard", "pkg:apk/chainguard/openssl@3.1.4-r1?distro=chainguard", "Chainguard"},
		{"case-insensitive", "pkg:apk/wolfi/openssl@3.1.4-r1?distro=Wolfi", "Wolfi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := feed.OSVDistroEcosystemForTest(tc.purl); got != tc.want {
				t.Fatalf("ecosystem = %q, want %q", got, tc.want)
			}
		})
	}
}

// The versioned distros must be unaffected by the rolling-distro shortcut.
func TestOSVDistroEcosystem_VersionedDistrosStillResolve(t *testing.T) {
	for _, tc := range []struct{ purl, want string }{
		{"pkg:rpm/rocky/openssl@1.1.1?distro=rocky-8.10", "Rocky Linux:8"},
		{"pkg:rpm/alma/openssl@1.1.1?distro=alma-9.3", "AlmaLinux:9"},
		{"pkg:deb/debian/openssl@1.1.1?distro=debian-12", "Debian:12"},
		{"pkg:apk/alpine/openssl@1.1.1?distro=alpine-3.18.4", "Alpine:v3.18"},
		{"pkg:rpm/redhat/openssl@1.1.1?distro=rhel-9.3", "Red Hat"},
		{"pkg:rpm/unknown/openssl@1.1.1?distro=notadistro-1", ""},
		{"pkg:rpm/unknown/openssl@1.1.1", ""},
	} {
		if got := feed.OSVDistroEcosystemForTest(tc.purl); got != tc.want {
			t.Errorf("%s: ecosystem = %q, want %q", tc.purl, got, tc.want)
		}
	}
}
