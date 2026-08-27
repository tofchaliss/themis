package feed_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
)

// rockyPage is one Apollo v2 advisories page in the wire shape the client consumes.
func rockyPage(total int, advisories ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"advisories": advisories, "total": total})
	return string(b)
}

func rxsaAdvisory(name string, cves []string, nvras ...string) map[string]any {
	cvs := make([]map[string]any, 0, len(cves))
	for _, c := range cves {
		cvs = append(cvs, map[string]any{"name": c})
	}
	return map[string]any{
		"name": name,
		"cves": cvs,
		"rpms": map[string]any{"Rocky Linux SIG Cloud 9": map[string]any{"nvras": nvras}},
	}
}

func TestRockyClient_FoldsSourcePackageBoundsForCardedCVEsOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kw := r.URL.Query().Get("filters.keyword"); kw != "RXSA" {
			t.Errorf("keyword filter = %q, want RXSA", kw)
		}
		_, _ = w.Write([]byte(rockyPage(2,
			// The RXSA under test: one src.rpm (folds) + binary rpms (rebuild SCOPE, never fold).
			rxsaAdvisory("RXSA-2026:51035", []string{"CVE-2026-23415", "CVE-2026-99999"},
				"kernel-0:5.14.0-687.36.1.el9_8.cloud.1.0.src.rpm",
				"kernel-debug-debuginfo-0:5.14.0-687.36.1.el9_8.cloud.1.0.x86_64.rpm"),
			// An RLSA clone sharing a carded CVE: excluded wholesale ("do not duplicate the
			// clone coverage" — its content already arrives via the Red Hat feed).
			rxsaAdvisory("RLSA-2026:60306", []string{"CVE-2026-23415"},
				"golang-0:1.26.7-1.el9.src.rpm"))))
	}))
	t.Cleanup(srv.Close)

	known := map[string]struct{}{"CVE-2026-23415": {}} // CVE-2026-99999 is deliberately uncarded
	props, err := feed.NewRockyClient(srv.URL, nil).ProposalsForKnown(context.Background(), known)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(props) != 1 || props[0].CVE.String() != "CVE-2026-23415" {
		t.Fatalf("proposals = %+v, want exactly the carded CVE (the D5 discard is in the client)", props)
	}
	facts, ok := props[0].Proposal.VulnFacts()
	if !ok {
		t.Fatal("proposal must carry VulnFacts")
	}
	if len(facts.Fixes) != 1 {
		t.Fatalf("fixes = %v, want ONLY the source package (binary rpms are scope, the clone is excluded)", facts.Fixes)
	}
	f := facts.Fixes[0]
	if f.Package != "kernel" || f.Version != "0:5.14.0-687.36.1.el9_8.cloud.1.0" || f.Ecosystem != "rpm" {
		t.Errorf("fix = %+v, want kernel / 0:5.14.0-687.36.1.el9_8.cloud.1.0 / rpm", f)
	}
	if facts.Severity.String() != "unknown" {
		t.Errorf("severity = %v, want unknown — rocky never contends for the headline (D11)", facts.Severity)
	}
}

func TestRockyClient_WalksPagesAndAbortsOnServerError(t *testing.T) {
	// Two pages: total 150 at limit 100 → the client must request page 0 and page 1.
	var pagesSeen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pagesSeen = append(pagesSeen, page)
		if page == "0" {
			_, _ = w.Write([]byte(rockyPage(150, rxsaAdvisory("RXSA-2026:1", []string{"CVE-2026-1"}, "a-0:1-1.el9.src.rpm"))))
			return
		}
		_, _ = w.Write([]byte(rockyPage(150, rxsaAdvisory("RXSA-2026:2", []string{"CVE-2026-2"}, "b-0:2-1.el9.src.rpm"))))
	}))
	t.Cleanup(srv.Close)

	known := map[string]struct{}{"CVE-2026-1": {}, "CVE-2026-2": {}}
	props, err := feed.NewRockyClient(srv.URL, nil).ProposalsForKnown(context.Background(), known)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(pagesSeen) != 2 || len(props) != 2 {
		t.Fatalf("pages=%v props=%d, want both pages walked and both CVEs folded", pagesSeen, len(props))
	}

	// A page failure aborts the sweep — feed health records it, the next interval retries.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(bad.Close)
	if _, err := feed.NewRockyClient(bad.URL, nil).ProposalsForKnown(context.Background(), known); err == nil {
		t.Fatal("a page error must abort the sweep")
	}
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "{")
	}))
	t.Cleanup(garbled.Close)
	if _, err := feed.NewRockyClient(garbled.URL, nil).ProposalsForKnown(context.Background(), known); err == nil {
		t.Fatal("invalid json must abort the sweep")
	}
}

func TestRockyClient_DedupsAcrossAdvisoriesAndSkipsFixlessOnes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(rockyPage(3,
			rxsaAdvisory("RXSA-2026:1", []string{"CVE-2026-1"}, "pkg-0:1.0-1.el9.src.rpm"),
			// The same CVE+package+version from a second advisory must fold once.
			rxsaAdvisory("RXSA-2026:2", []string{"CVE-2026-1"}, "pkg-0:1.0-1.el9.src.rpm"),
			// Binary-only advisory (no .src.rpm): nothing verdict-grade to fold.
			rxsaAdvisory("RXSA-2026:3", []string{"CVE-2026-1"}, "pkg-debuginfo-0:1.0-1.el9.x86_64.rpm"))))
	}))
	t.Cleanup(srv.Close)

	props, err := feed.NewRockyClient(srv.URL, nil).ProposalsForKnown(context.Background(),
		map[string]struct{}{"CVE-2026-1": {}})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(props) != 1 {
		t.Fatalf("proposals = %d, want 1", len(props))
	}
	facts, _ := props[0].Proposal.VulnFacts()
	if len(facts.Fixes) != 1 {
		t.Fatalf("fixes = %v, want the duplicate collapsed to one", facts.Fixes)
	}
}
