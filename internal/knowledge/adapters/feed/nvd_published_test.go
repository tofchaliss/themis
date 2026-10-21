package feed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// GUI-16 layer 2: PublishedSince walks NVD's published window page by page, keeps unscored
// CVEs (a fresh CVE often has no score yet), drops withdrawn ones, and translates nothing —
// the result is displayed, never folded.
func TestNVDClient_PublishedSince(t *testing.T) {
	var queries []string
	resets := 1 // the first request is reset once, as NVD does under load; the retry succeeds
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		start := r.URL.Query().Get("startIndex")
		if start == "0" && resets > 0 {
			resets--
			if hj, ok := w.(http.Hijacker); ok {
				if conn, _, err := hj.Hijack(); err == nil {
					_ = conn.Close()
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if start == "0" {
			_, _ = fmt.Fprint(w, `{"totalResults":3,"vulnerabilities":[
			  {"cve":{"id":"CVE-2026-1000","published":"2026-10-20T10:00:00.000","vulnStatus":"Analyzed",
			    "descriptions":[{"lang":"es","value":"no"},{"lang":"en","value":"A flaw in foo."}],
			    "metrics":{"cvssMetricV31":[{"type":"Primary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/x"}}]}}},
			  {"cve":{"id":"CVE-2026-1001","published":"2026-10-19T08:00:00.000","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"withdrawn"}]}}
			]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"totalResults":3,"vulnerabilities":[
		  {"cve":{"id":"CVE-2026-1002","published":"2026-10-18T00:00:00.000","vulnStatus":"Awaiting Analysis","descriptions":[{"lang":"en","value":"Not scored yet."}]}}
		]}`)
	}))
	defer srv.Close()

	c := NewNVDClient(srv.URL, "", srv.Client())
	rows, err := c.PublishedSince(context.Background(), time.Now().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatalf("PublishedSince: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %+v, want the two live CVEs (the rejected one dropped)", rows)
	}
	if r := rows[0]; r.CVE != "CVE-2026-1000" || r.Severity != "critical" || r.Score != 9.8 || r.Summary != "A flaw in foo." || r.Published.Year() != 2026 {
		t.Errorf("first = %+v", r)
	}
	if r := rows[1]; r.CVE != "CVE-2026-1002" || r.Severity != "" || r.Score != 0 || r.Summary != "Not scored yet." {
		t.Errorf("unscored = %+v", r)
	}
	if len(queries) != 3 || !containsAll(queries[0], "pubStartDate=", "pubEndDate=", "startIndex=0", "resultsPerPage=200") ||
		!containsAll(queries[1], "startIndex=0") || !containsAll(queries[2], "startIndex=2") {
		t.Errorf("queries = %v, want the reset page retried once, then the second page", queries)
	}

	// A zero `since` and one older than NVD's maximum span are both bounded to the maximum.
	queries = nil
	if _, err := c.PublishedSince(context.Background(), time.Time{}); err != nil || len(queries) == 0 {
		t.Fatalf("zero since: %v / %d queries", err, len(queries))
	}
	// A failing server surfaces.
	srv.Close()
	if _, err := c.PublishedSince(context.Background(), time.Now()); err == nil {
		t.Error("an unreachable NVD must surface, not read as nothing published")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
