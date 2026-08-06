package feed_test

import (
	"context"
	"encoding/json"
	"errors"
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

const nvdTestLayout = "2006-01-02T15:04:05.000"

// nvdSlice is one observed [lastModStartDate, lastModEndDate] request pair.
type nvdSlice struct{ start, end time.Time }

// recordingNVDServer serves empty pages and records the window of every request, so a test
// can assert on the whole walk rather than on a single call.
func recordingNVDServer(t *testing.T, slices *[]nvdSlice) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err1 := time.Parse(nvdTestLayout, r.URL.Query().Get("lastModStartDate"))
		e, err2 := time.Parse(nvdTestLayout, r.URL.Query().Get("lastModEndDate"))
		if err1 != nil || err2 != nil {
			t.Errorf("unparseable window: %q..%q", r.URL.Query().Get("lastModStartDate"), r.URL.Query().Get("lastModEndDate"))
		}
		*slices = append(*slices, nvdSlice{s, e})
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
}

// TestNVDClient_ChangedSince_WalksTheWindowInContiguousSlices is the NVD-WATCH-1 regression.
// The window since the watermark is covered by a walk of slices, not by one whole-window
// request that stops at the page budget. What must hold is coverage, so this asserts the
// three properties that make the walk sound: it STARTS at the watermark (clamped to NVD's
// 120-day maximum), it REACHES now, and consecutive slices are CONTIGUOUS — no gap between
// one slice's end and the next slice's start, because a gap is exactly the silent skip the
// old code shipped.
func TestNVDClient_ChangedSince_WalksTheWindowInContiguousSlices(t *testing.T) {
	for _, tc := range []struct {
		name     string
		since    time.Time
		wantSpan time.Duration // expected age of the first slice's start
	}{
		{"zero watermark clamps to the 120-day maximum", time.Time{}, 120 * 24 * time.Hour},
		{"recent watermark is used as-is", time.Now().Add(-72 * time.Hour).UTC(), 72 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var slices []nvdSlice
			srv := recordingNVDServer(t, &slices)
			defer srv.Close()
			c := feed.NewNVDClient(srv.URL, "", srv.Client())

			if _, err := c.ChangedSince(context.Background(), tc.since); err != nil {
				t.Fatalf("ChangedSince: %v", err)
			}
			if len(slices) == 0 {
				t.Fatal("no requests issued")
			}
			if age := time.Since(slices[0].start); age < tc.wantSpan-time.Minute || age > tc.wantSpan+time.Minute {
				t.Errorf("first slice starts %v ago, want ~%v", age, tc.wantSpan)
			}
			if tail := time.Since(slices[len(slices)-1].end); tail > time.Minute {
				t.Errorf("walk stops %v short of now — the tail of the window is never read", tail)
			}
			for i := 1; i < len(slices); i++ {
				if !slices[i].start.Equal(slices[i-1].end) {
					t.Fatalf("gap between slice %d (ends %v) and slice %d (starts %v) — records in the gap are skipped",
						i-1, slices[i-1].end, i, slices[i].start)
				}
			}
		})
	}
}

// A slice holding more records than the page budget must NOT be silently truncated. It is
// narrowed and retried; only when narrowing bottoms out does it surface as an error, so the
// caller's watermark stays put and the slice is retried on the next poll rather than skipped
// forever. This is the defect NVD-WATCH-1 recorded: 356,223 records in a 120-day window
// against a 20,000-record budget, read as a successful poll.
func TestNVDClient_ChangedSince_OverfullSliceNarrowsThenErrorsNeverTruncates(t *testing.T) {
	var widths []time.Duration
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := time.Parse(nvdTestLayout, r.URL.Query().Get("lastModStartDate"))
		e, _ := time.Parse(nvdTestLayout, r.URL.Query().Get("lastModEndDate"))
		if r.URL.Query().Get("startIndex") == "0" {
			widths = append(widths, e.Sub(s))
		}
		// Always claim far more results than the budget can read, so every slice overflows.
		_, _ = w.Write([]byte(`{"totalResults":1000000,"vulnerabilities":[` + cve("CVE-2024-9999",
			`{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":7.8,"baseSeverity":"HIGH","vectorString":"CVSS:3.1/AV:L"}}]}`) + `]}`))
	}))
	defer srv.Close()
	c := feed.NewNVDClient(srv.URL, "", srv.Client())

	_, err := c.ChangedSince(context.Background(), time.Now().Add(-48*time.Hour))
	if !errors.Is(err, feed.ErrWindowTruncated) {
		t.Fatalf("err = %v, want ErrWindowTruncated — a slice it cannot read must never look like success", err)
	}
	if len(widths) < 2 {
		t.Fatalf("issued %d slice attempts, want the slice narrowed and retried at least once", len(widths))
	}
	for i := 1; i < len(widths); i++ {
		if widths[i] >= widths[i-1] {
			t.Fatalf("slice %d width %v did not narrow from %v", i, widths[i], widths[i-1])
		}
	}
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
