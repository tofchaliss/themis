package feed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func rhServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRedHatClient_TranslatesSeverityAndNotAffected(t *testing.T) {
	body := `{
		"name":"CVE-2024-1","threat_severity":"Important","public_date":"2024-01-15T00:00:00Z",
		"cvss3":{"cvss3_base_score":"7.5","cvss3_scoring_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		"package_state":[
			{"product_name":"Red Hat Enterprise Linux 8","fix_state":"Not affected","package_name":"openssl"},
			{"product_name":"Red Hat Enterprise Linux 9","fix_state":"Not affected","package_name":"openssl"},
			{"product_name":"Red Hat Enterprise Linux 8","fix_state":"Affected","package_name":"curl"},
			{"product_name":"Red Hat Enterprise Linux 8","fix_state":"Not affected","package_name":""},
			{"product_name":"Red Hat OpenShift AI","fix_state":"Not affected","package_name":"odh-ml-pipelines-api-server-container"},
			{"product_name":"Logging Subsystem","fix_state":"Not affected","package_name":"openshift-logging/elasticsearch6-rhel8"}
		]
	}`
	srv := rhServer(t, http.StatusOK, body)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-1")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	// vuln-facts (High from Important) + ONE deduped not_affected applicability (openssl). The
	// "Affected" curl, the empty-package entry, and the container/namespaced product artifacts
	// (a "-container" image and an "openshift-logging/…" namespaced name — never package-level
	// SBOM components) are all skipped.
	if len(got) != 2 {
		t.Fatalf("proposals = %d, want 2", len(got))
	}
	var sawVF, sawApp bool
	for _, p := range got {
		if vf, ok := p.Proposal.VulnFacts(); ok {
			sawVF = true
			if vf.Severity != value.SeverityHigh {
				t.Errorf("severity = %v, want high (Important)", vf.Severity)
			}
		}
		if a, ok := p.Proposal.Applicability(); ok {
			sawApp = true
			if a.Status != "not_affected" || a.Package != "openssl" {
				t.Errorf("applicability = %+v, want not_affected openssl", a)
			}
		}
	}
	if !sawVF || !sawApp {
		t.Errorf("want both vuln-facts and applicability; got vf=%v app=%v", sawVF, sawApp)
	}
}

func TestRedHatClient_SeverityMapping(t *testing.T) {
	// CVSS base 5.0 = Medium band, so a mapped label (low/high/critical) differs from the fallback,
	// proving the Red Hat threat_severity → canonical mapping (not just the CVSS band).
	cases := []struct {
		threat string
		want   value.Severity
	}{
		{"Low", value.SeverityLow},
		{"Moderate", value.SeverityMedium},
		{"Important", value.SeverityHigh},
		{"Critical", value.SeverityCritical},
		{"", value.SeverityMedium}, // unknown label → derived from the CVSS band (5.0 = medium)
	}
	for _, tc := range cases {
		t.Run(tc.threat, func(t *testing.T) {
			body := `{"name":"CVE-2024-5","threat_severity":"` + tc.threat + `","public_date":"2024-01-15T00:00:00Z",
				"cvss3":{"cvss3_base_score":"5.0","cvss3_scoring_vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}}`
			srv := rhServer(t, http.StatusOK, body)
			got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-5")
			if err != nil {
				t.Fatalf("fetch: %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("proposals = %d, want 1 (vuln-facts only)", len(got))
			}
			vf, ok := got[0].Proposal.VulnFacts()
			if !ok || vf.Severity != tc.want {
				t.Errorf("severity = %v (ok=%v), want %v", vf.Severity, ok, tc.want)
			}
		})
	}
}

func TestRedHatClient_MainStreamFixesOnly(t *testing.T) {
	// affected_release carries fixes for several products; only MAIN-stream enterprise_linux
	// advisories reach FixedVersions — the EUS backport line, a non-EL product, and an empty
	// package are all excluded (EDR-VEX-01 Phase 3, to avoid a false stream-scoped "fixed").
	body := `{
		"name":"CVE-2024-7","threat_severity":"Important","public_date":"2024-01-15T00:00:00Z",
		"cvss3":{"cvss3_base_score":"7.5","cvss3_scoring_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		"affected_release":[
			{"product_name":"RHEL 8","package":"openssl-1:1.0.2k-16.el8_10","cpe":"cpe:/o:redhat:enterprise_linux:8"},
			{"product_name":"RHEL 8.6 EUS","package":"openssl-1:1.0.2k-16.el8_6","cpe":"cpe:/o:redhat:enterprise_linux_eus:8.6"},
			{"product_name":"RHEL 9","package":"openssl-1:3.0.1-47.el9_2","cpe":"cpe:/o:redhat:enterprise_linux:9"},
			{"product_name":"OpenShift","package":"openssl-1:3.0.1-47.el9_2","cpe":"cpe:/a:redhat:openshift:4"},
			{"product_name":"RHEL 8 empty","package":"","cpe":"cpe:/o:redhat:enterprise_linux:8"}
		]
	}`
	srv := rhServer(t, http.StatusOK, body)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-7")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("proposals = %d, want 1 (vuln-facts only)", len(got))
	}
	vf, ok := got[0].Proposal.VulnFacts()
	if !ok {
		t.Fatal("want a vuln-facts proposal")
	}
	want := []string{"openssl-1:1.0.2k-16.el8_10", "openssl-1:3.0.1-47.el9_2"} // el8 + el9 main-stream, in doc order
	if len(vf.FixVersions()) != len(want) {
		t.Fatalf("FixedVersions = %v, want %v (main-stream only)", vf.FixVersions(), want)
	}
	for i := range want {
		if vf.FixVersions()[i] != want[i] {
			t.Errorf("FixedVersions[%d] = %q, want %q", i, vf.FixVersions()[i], want[i])
		}
	}
}

func TestRedHatClient_NoCVSSStillEmitsApplicability(t *testing.T) {
	// No CVSS → no vuln-facts (mirror the NVD ACL drop-no-CVSS), but the not_affected statement
	// still folds. Also exercises the bare YYYY-MM-DD public_date form.
	body := `{"name":"CVE-2024-2","threat_severity":"Moderate","public_date":"2024-02-01",
		"cvss3":{"cvss3_base_score":"","cvss3_scoring_vector":""},
		"package_state":[{"product_name":"RHEL 8","fix_state":"Not affected","package_name":"zlib"}]}`
	srv := rhServer(t, http.StatusOK, body)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-2")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("proposals = %d, want 1 (applicability only)", len(got))
	}
	if _, ok := got[0].Proposal.Applicability(); !ok {
		t.Error("the single proposal must be an applicability")
	}
}

func TestRedHatClient_NoDateIsSkipped(t *testing.T) {
	body := `{"name":"CVE-2024-3","threat_severity":"Low",
		"cvss3":{"cvss3_base_score":"3.1","cvss3_scoring_vector":"v"},
		"package_state":[{"fix_state":"Not affected","package_name":"foo"}]}`
	srv := rhServer(t, http.StatusOK, body)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-3")
	if err != nil || got != nil {
		t.Fatalf("no date: got (%v,%v), want (nil,nil)", got, err)
	}
}

func TestRedHatClient_NotFoundIsNoData(t *testing.T) {
	srv := rhServer(t, http.StatusNotFound, "")
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-9")
	if err != nil || got != nil {
		t.Fatalf("404: got (%v,%v), want (nil,nil)", got, err)
	}
}

func TestRedHatClient_ServerErrorPropagates(t *testing.T) {
	srv := rhServer(t, http.StatusInternalServerError, "")
	if _, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-9"); err == nil {
		t.Error("a 500 must propagate as an error")
	}
}

func TestRedHatClient_InvalidJSONErrors(t *testing.T) {
	srv := rhServer(t, http.StatusOK, "{not json")
	if _, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2024-9"); err == nil {
		t.Error("invalid json must error")
	}
}

func TestRedHatClient_InvalidCVEArgSkipped(t *testing.T) {
	// An unparseable CVE returns before any request — also exercises the "" base-URL default and
	// the nil-http default in the constructor.
	got, err := feed.NewRedHatClient("", nil).FetchCVE(context.Background(), "not-a-cve")
	if err != nil || got != nil {
		t.Fatalf("invalid cve: got (%v,%v), want (nil,nil)", got, err)
	}
}

func TestRedHatClient_TransportErrorPropagates(t *testing.T) {
	// A refused connection surfaces as an error (a real fetch fault, distinct from a 404 gap).
	if _, err := feed.NewRedHatClient("http://127.0.0.1:1", nil).FetchCVE(context.Background(), "CVE-2024-9"); err == nil {
		t.Error("a transport error must propagate")
	}
}

// rhRoutedServer serves the CVE document at /cve/… and the advisory CSAF document at /csaf/…,
// counting CSAF fetches — the KN-MODULE-5 two-hop shape. csafStatus lets a test break hop two
// while hop one stays healthy.
func rhRoutedServer(t *testing.T, cveBody, csafBody string, csafStatus int, csafHits *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/csaf/"):
			*csafHits++
			if csafStatus != http.StatusOK {
				w.WriteHeader(csafStatus)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(csafBody))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(cveBody))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// rhModuleCVEBody is a CVE document whose only main-stream fix is a MODULE identifier — the
// exact shape measured live for CVE-2019-0211 (KN-MODULE-5): a name:stream-context that names
// no build, plus the advisory that does.
const rhModuleCVEBody = `{
	"name":"CVE-2019-0211","threat_severity":"Important","public_date":"2019-04-01T00:00:00Z",
	"cvss3":{"cvss3_base_score":"7.8","cvss3_scoring_vector":"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
	"affected_release":[
		{"package":"httpd:2.4-8000020190405071959.55190bc5","cpe":"cpe:/a:redhat:enterprise_linux:8","advisory":"RHSA-2019:0980"}
	]
}`

// rhCSAFBody is the advisory's CSAF product tree: the source-package NEVRA the CVE record lacks
// (with its ::module suffix), the per-arch binary rebuilds that are SCOPE not claims, and a
// malformed bare-EVR id that names no package — only the .src NEVRA may survive extraction.
const rhCSAFBody = `{
	"product_tree":{"branches":[
		{"category":"vendor","name":"Red Hat","branches":[
			{"category":"product_version","name":"httpd src",
			 "product":{"product_id":"httpd-0:2.4.37-11.module+el8.0.0+2969+90015743.src::httpd:2.4","name":"httpd"}},
			{"category":"product_version","name":"httpd x86_64",
			 "product":{"product_id":"httpd-0:2.4.37-11.module+el8.0.0+2969+90015743.x86_64::httpd:2.4","name":"httpd"}},
			{"category":"product_version","name":"mod_http2 src",
			 "product":{"product_id":"mod_http2-0:1.11.3-1.module+el8.0.0+2969+90015743.src::httpd:2.4","name":"mod_http2"}},
			{"category":"product_version","name":"malformed",
			 "product":{"product_id":"2.4.37-11.src","name":"bare evr"}}
		]}
	]}
}`

func rhFixes(t *testing.T, got []app.ProposalFor) []domain.FixedVersion {
	t.Helper()
	for _, p := range got {
		if vf, ok := p.Proposal.VulnFacts(); ok {
			return vf.Fixes
		}
	}
	t.Fatal("no vuln-facts proposal in result")
	return nil
}

func TestRedHatClient_ModuleFixResolvedThroughAdvisoryCSAF(t *testing.T) {
	hits := 0
	srv := rhRoutedServer(t, rhModuleCVEBody, rhCSAFBody, http.StatusOK, &hits)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2019-0211")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if hits != 1 {
		t.Fatalf("csaf fetches = %d, want 1", hits)
	}
	fixes := rhFixes(t, got)
	byVersion := map[string]string{}
	for _, f := range fixes {
		byVersion[f.Version] = f.Package
	}
	// Hop one's module entry is KEPT (nothing is dropped; it remains the module-level
	// remediation statement), and hop two adds the comparable source NEVRAs beside it.
	if pkg, ok := byVersion["httpd:2.4-8000020190405071959.55190bc5"]; !ok || pkg != "httpd" {
		t.Errorf("module entry missing or misattributed: %v", byVersion)
	}
	if pkg, ok := byVersion["httpd-0:2.4.37-11.module+el8.0.0+2969+90015743.src"]; !ok || pkg != "httpd" {
		t.Errorf("resolved httpd src NEVRA missing or misattributed: %v", byVersion)
	}
	if pkg, ok := byVersion["mod_http2-0:1.11.3-1.module+el8.0.0+2969+90015743.src"]; !ok || pkg != "mod_http2" {
		t.Errorf("resolved mod_http2 src NEVRA missing or misattributed: %v", byVersion)
	}
	// Binary-arch rebuilds are scope, and a bare EVR names no package: neither may become a bound.
	for v := range byVersion {
		if strings.HasSuffix(v, ".x86_64") || v == "2.4.37-11.src" {
			t.Errorf("excluded id leaked into fixes: %q", v)
		}
	}
	if len(fixes) != 3 {
		t.Errorf("fixes = %d (%v), want 3", len(fixes), byVersion)
	}

	// The safety pair from the live case (mirrors KN-MODULE-4's mutation-verified guard): the
	// resolved bound clears the patched -65 build and refuses the pre-fix -9 build; the module
	// identifier alone can clear NOTHING.
	resolved := []string{"httpd-0:2.4.37-11.module+el8.0.0+2969+90015743.src"}
	if !value.RPMFixedByStream("rpm", "2.4.37-65.module+el8.10.0+40257+286895ef.9", resolved) {
		t.Error("patched -65 build must clear against the resolved -11 bound")
	}
	if value.RPMFixedByStream("rpm", "2.4.37-9.module+el8.0.0+2969+90015743", resolved) {
		t.Error("pre-fix -9 build must NOT clear")
	}
	if value.RPMFixedByStream("rpm", "2.4.37-65.module+el8.10.0+40257+286895ef.9",
		[]string{"httpd:2.4-8000020190405071959.55190bc5"}) {
		t.Error("the bare module identifier must never clear anything")
	}
}

func TestRedHatClient_NonModuleFixFetchesNoAdvisory(t *testing.T) {
	hits := 0
	cveBody := `{
		"name":"CVE-2025-1","threat_severity":"Important","public_date":"2025-01-01T00:00:00Z",
		"cvss3":{"cvss3_base_score":"7.5","cvss3_scoring_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
		"affected_release":[
			{"package":"curl-0:7.61.1-34.el8_10.13","cpe":"cpe:/a:redhat:enterprise_linux:8","advisory":"RHSA-2025:1"}
		]
	}`
	srv := rhRoutedServer(t, cveBody, "", http.StatusOK, &hits)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2025-1")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if hits != 0 {
		t.Errorf("csaf fetches = %d, want 0 — a plain NEVRA needs no second hop", hits)
	}
	if fixes := rhFixes(t, got); len(fixes) != 1 || fixes[0].Version != "curl-0:7.61.1-34.el8_10.13" {
		t.Errorf("fixes = %v, want the plain NEVRA alone", fixes)
	}
}

func TestRedHatClient_AdvisoryFetchFailureFallsOpen(t *testing.T) {
	hits := 0
	srv := rhRoutedServer(t, rhModuleCVEBody, "", http.StatusInternalServerError, &hits)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2019-0211")
	if err != nil {
		t.Fatalf("a broken second hop must not fail the fetch: %v", err)
	}
	if hits != 1 {
		t.Errorf("csaf fetches = %d, want 1", hits)
	}
	fixes := rhFixes(t, got)
	if len(fixes) != 1 || fixes[0].Version != "httpd:2.4-8000020190405071959.55190bc5" {
		t.Errorf("fixes = %v, want hop one's module entry alone (fail open)", fixes)
	}
}

func TestRedHatClient_AdvisoryInvalidJSONFallsOpen(t *testing.T) {
	hits := 0
	srv := rhRoutedServer(t, rhModuleCVEBody, "{not json", http.StatusOK, &hits)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2019-0211")
	if err != nil {
		t.Fatalf("a malformed csaf doc must not fail the fetch: %v", err)
	}
	if fixes := rhFixes(t, got); len(fixes) != 1 {
		t.Errorf("fixes = %v, want hop one's module entry alone", fixes)
	}
}

func TestRedHatClient_NonRHSAAdvisoryNotFetched(t *testing.T) {
	hits := 0
	cveBody := `{
		"name":"CVE-2020-1","threat_severity":"Moderate","public_date":"2020-01-01T00:00:00Z",
		"cvss3":{"cvss3_base_score":"5.3","cvss3_scoring_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		"affected_release":[
			{"package":"nodejs:10-8000020190911085529.f8e95b4e","cpe":"cpe:/a:redhat:enterprise_linux:8","advisory":"RHBA-2020:0402"}
		]
	}`
	srv := rhRoutedServer(t, cveBody, rhCSAFBody, http.StatusOK, &hits)
	if _, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2020-1"); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if hits != 0 {
		t.Errorf("csaf fetches = %d, want 0 — only security advisories (RHSA) are resolved", hits)
	}
}

func TestRedHatClient_SameAdvisoryFetchedOnce(t *testing.T) {
	hits := 0
	cveBody := `{
		"name":"CVE-2019-0211","threat_severity":"Important","public_date":"2019-04-01T00:00:00Z",
		"cvss3":{"cvss3_base_score":"7.8","cvss3_scoring_vector":"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
		"affected_release":[
			{"package":"httpd:2.4-8000020190405071959.55190bc5","cpe":"cpe:/a:redhat:enterprise_linux:8","advisory":"RHSA-2019:0980"},
			{"package":"httpd:2.4-8000020190405071959.55190bc5","cpe":"cpe:/o:redhat:enterprise_linux:8","advisory":"RHSA-2019:0980"}
		]
	}`
	srv := rhRoutedServer(t, cveBody, rhCSAFBody, http.StatusOK, &hits)
	got, err := feed.NewRedHatClient(srv.URL, srv.Client()).FetchCVE(context.Background(), "CVE-2019-0211")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if hits != 1 {
		t.Errorf("csaf fetches = %d, want 1 — one advisory, one request", hits)
	}
	// Hop one keeps its per-row duplicates (existing behavior; fixFold's RPMEVR keying dedups
	// them at reconciliation) — the assertion is on what THIS change adds: each resolved .src
	// NEVRA appears exactly once however many rows named its advisory.
	count := map[string]int{}
	for _, f := range rhFixes(t, got) {
		if strings.HasSuffix(f.Version, ".src") {
			count[f.Version]++
		}
	}
	if len(count) != 2 {
		t.Errorf("resolved src NEVRAs = %v, want the advisory's 2", count)
	}
	for v, n := range count {
		if n != 1 {
			t.Errorf("resolved fix %q appears %d times, want exactly 1", v, n)
		}
	}
}
