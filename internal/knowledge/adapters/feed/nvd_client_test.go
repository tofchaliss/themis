package feed_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// nvdServer replies to /rest/json/cves/2.0 with the given CVE objects as one page.
func nvdServer(t *testing.T, cves ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vulns := make([]json.RawMessage, 0, len(cves))
		for _, c := range cves {
			vulns = append(vulns, json.RawMessage(`{"cve":`+c+`}`))
		}
		body, _ := json.Marshal(map[string]any{"totalResults": len(cves), "vulnerabilities": vulns})
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// cve builds a live NVD CVE object with the given id and metrics JSON.
func cve(id, metrics string) string {
	return `{"id":"` + id + `","lastModified":"2026-07-20T10:00:00.000","metrics":` + metrics + `}`
}

func onlyProposal(t *testing.T, got []app.ProposalFor) app.ProposalFor {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("got %d proposals, want 1", len(got))
	}
	return got[0]
}

func TestNVDClient_V31Scored(t *testing.T) {
	srv := nvdServer(t, cve("CVE-2024-2000",
		`{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.8,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:L"}}]}`))
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, err := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	pf := onlyProposal(t, got)
	vf, _ := pf.Proposal.VulnFacts()
	if vf.Severity != "high" || vf.CVSS.Score() != 7.8 {
		t.Errorf("v3.1: severity=%s score=%.1f, want high/7.8", vf.Severity, vf.CVSS.Score())
	}
}

// The D-NVD-2 fix: a CVE scored ONLY under CVSS 4.0 (the CVE-2025-8869 shape) now yields a
// real severity/score instead of unknown/0.
func TestNVDClient_V40Only_ResolvesSeverity(t *testing.T) {
	srv := nvdServer(t, cve("CVE-2025-8869",
		`{"cvssMetricV40":[{"type":"Secondary","cvssData":{"baseScore":5.9,"baseSeverity":"MEDIUM","vectorString":"CVSS:4.0/AV:N"}}]}`))
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, err := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	pf := onlyProposal(t, got)
	if pf.CVE.String() != "CVE-2025-8869" {
		t.Errorf("cve = %s", pf.CVE.String())
	}
	vf, _ := pf.Proposal.VulnFacts()
	if vf.Severity != "medium" || vf.CVSS.Score() != 5.9 {
		t.Errorf("v4.0-only: severity=%s score=%.1f, want medium/5.9 (D-NVD-2)", vf.Severity, vf.CVSS.Score())
	}
}

// When both v3.1 and v4.0 exist, v3.1 wins the headline (comparability across the fleet).
func TestNVDClient_V31BeatsV40(t *testing.T) {
	srv := nvdServer(t, cve("CVE-2024-3000", `{
		"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1"}}],
		"cvssMetricV40":[{"type":"Primary","cvssData":{"baseScore":5.9,"baseSeverity":"MEDIUM","vectorString":"CVSS:4.0"}}]
	}`))
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, _ := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	vf, _ := onlyProposal(t, got).Proposal.VulnFacts()
	if vf.Severity != "critical" || vf.CVSS.Score() != 9.8 {
		t.Errorf("both v3.1+v4.0: severity=%s score=%.1f, want critical/9.8 (v3.1 wins)", vf.Severity, vf.CVSS.Score())
	}
}

// Within a version, a Primary (NVD) entry beats a Secondary (CNA) entry.
func TestNVDClient_PrimaryBeatsSecondary(t *testing.T) {
	srv := nvdServer(t, cve("CVE-2024-4000", `{"cvssMetricV40":[
		{"type":"Secondary","cvssData":{"baseScore":5.9,"baseSeverity":"MEDIUM","vectorString":"CVSS:4.0/s"}},
		{"type":"Primary","cvssData":{"baseScore":8.1,"baseSeverity":"HIGH","vectorString":"CVSS:4.0/p"}}
	]}`))
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, _ := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	vf, _ := onlyProposal(t, got).Proposal.VulnFacts()
	if vf.Severity != "high" || vf.CVSS.Score() != 8.1 {
		t.Errorf("primary-over-secondary: severity=%s score=%.1f, want high/8.1", vf.Severity, vf.CVSS.Score())
	}
}

// A CVE NVD has not scored under any version is skipped (no signal to carry).
func TestNVDClient_NoMetricsSkipped(t *testing.T) {
	srv := nvdServer(t, cve("CVE-2026-9999", `{}`))
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, err := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d proposals, want 0 (no CVSS → skipped)", len(got))
	}
}

func TestNVDClient_Paginates(t *testing.T) {
	page0 := cve("CVE-2024-0001", `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]}`)
	page1 := cve("CVE-2024-0002", `{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":6.0,"baseSeverity":"MEDIUM"}}]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		var one string
		if idx == 0 {
			one = page0
		} else {
			one = page1
		}
		// totalResults = 2, one record per page → the client must fetch twice.
		body, _ := json.Marshal(map[string]any{
			"totalResults":    2,
			"vulnerabilities": []json.RawMessage{json.RawMessage(`{"cve":` + one + `}`)},
		})
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	got, err := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("ChangedSince: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d proposals across pages, want 2", len(got))
	}
}

func TestNVDClient_NonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	if _, err := c.ChangedSince(context.Background(), time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("expected an error on 403")
	}
}

// compile-time confirmation the client is a ChangedVulnSource.
var _ app.ChangedVulnSource = (*feed.NVDClient)(nil)
