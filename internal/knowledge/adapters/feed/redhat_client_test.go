package feed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
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
