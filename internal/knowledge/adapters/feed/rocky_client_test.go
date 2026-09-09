package feed_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
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

// --- KN-MODULE-4: per-CVE RLSA fix bounds -----------------------------------------------

// The live payload, verbatim from errata.rockylinux.org for CVE-2021-40438 (2026-09-09): three
// advisories, one of them a BUGFIX (RLBA) that rebuilds the same packages without stating a
// security fix.
func cve40438Page() string {
	adv := func(name string, cves []string, nvras ...string) map[string]any {
		cvs := make([]map[string]any, 0, len(cves))
		for _, c := range cves {
			cvs = append(cvs, map[string]any{"name": c})
		}
		return map[string]any{
			"name": name, "cves": cvs,
			"rpms": map[string]any{"Rocky Linux 8": map[string]any{"nvras": nvras}},
		}
	}
	return rockyPage(3,
		adv("RLBA-2021:4604", []string{"CVE-2021-40438"},
			"httpd-0:2.4.37-41.module+el8.5.0+700+aaaaaaa.src.rpm"),
		adv("RLSA-2021:4537", []string{"CVE-2021-40438"},
			"httpd-0:2.4.37-43.module+el8.5.0+714+5ec56ee8.src.rpm",
			"httpd-0:2.4.37-43.module+el8.5.0+714+5ec56ee8.x86_64.rpm"),
		adv("RLSA-2021:3816", []string{"CVE-2021-40438", "CVE-2021-26691"},
			"httpd-0:2.4.37-39.module+el8.4.0+571+fd70afb1.src.rpm"),
	)
}

// The defect this closes: Red Hat states an el8 modular fix as a module NEVRA whose version is
// the stream NAME, which bounds nothing, so a patched build stays open forever. RLSA states the
// real build. Measured live 2026-09-09 on CVE-2021-40438 (critical, KEV, EPSS 0.99999) against a
// PATCHED httpd 2.4.37-65.module+el8.10.0.
func TestRockyClient_VulnsForCVEYieldsRealModularBounds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("filters.keyword"); got != "CVE-2021-40438" {
			t.Errorf("keyword = %q, want the CVE id — the query must be per-CVE, not a walk", got)
		}
		_, _ = fmt.Fprint(w, cve40438Page())
	}))
	defer srv.Close()

	facts, err := feed.NewRockyClient(srv.URL, srv.Client()).VulnsForCVE(context.Background(), cveID(t, "CVE-2021-40438"))
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Found {
		t.Fatal("Found = false; the advisories carry real fix bounds")
	}
	if facts.Withdrawn {
		t.Error("Withdrawn = true; Rocky errata never withdraw a CVE")
	}
	vf, ok := facts.Proposal.Proposal.VulnFacts()
	if !ok {
		t.Fatal("not a vuln-facts Proposal")
	}
	// `rocky` supplies bounds, never a headline (D11).
	if vf.Severity != value.SeverityUnknown {
		t.Errorf("severity = %v, want unknown — rocky must not contend for the headline", vf.Severity)
	}
	got := map[string]bool{}
	for _, f := range vf.Fixes {
		if f.Package != "httpd" {
			t.Errorf("fix attributed to %q, want httpd", f.Package)
		}
		got[f.Version] = true
	}
	// Both RLSA bounds, and ONLY from .src.rpm — the binary rpm must not become a second claim.
	for _, want := range []string{
		"0:2.4.37-43.module+el8.5.0+714+5ec56ee8",
		"0:2.4.37-39.module+el8.4.0+571+fd70afb1",
	} {
		if !got[want] {
			t.Errorf("missing fix bound %q; got %v", want, got)
		}
	}
	// The BUGFIX advisory states no security fix and must not contribute a bound.
	if got["0:2.4.37-41.module+el8.5.0+700+aaaaaaa"] {
		t.Error("an RLBA bugfix advisory must not supply a security fix bound")
	}
	if len(got) != 2 {
		t.Errorf("got %d bounds, want exactly 2: %v", len(got), got)
	}
}

// The keyword search is fuzzy: it returns advisories that merely MENTION the id. Only one that
// actually lists the CVE states a fix for it.
func TestRockyClient_VulnsForCVEIgnoresAdvisoriesNotNamingTheCVE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, rockyPage(1, rxsaAdvisory("RLSA-2021:9999", []string{"CVE-2021-99999"},
			"httpd-0:2.4.37-99.module+el8.10.0+1+aaaa.src.rpm")))
	}))
	defer srv.Close()

	facts, err := feed.NewRockyClient(srv.URL, srv.Client()).VulnsForCVE(context.Background(), cveID(t, "CVE-2021-40438"))
	if err != nil {
		t.Fatal(err)
	}
	if facts.Found {
		t.Error("Found = true for an advisory that does not name this CVE")
	}
}

// A CVE Rocky does not track is an ABSENCE, not an error and not a withdrawal.
func TestRockyClient_VulnsForCVEUntrackedIsEmptyNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, rockyPage(0))
	}))
	defer srv.Close()

	facts, err := feed.NewRockyClient(srv.URL, srv.Client()).VulnsForCVE(context.Background(), cveID(t, "CVE-2021-40438"))
	if err != nil {
		t.Fatalf("an untracked CVE must not error: %v", err)
	}
	if facts.Found || facts.Withdrawn {
		t.Errorf("Found=%v Withdrawn=%v, want both false", facts.Found, facts.Withdrawn)
	}
}

// cveID parses a canonical CVE id for the tests.
func cveID(t *testing.T, s string) value.CVEID {
	t.Helper()
	id, err := value.NewCVEID(s)
	if err != nil {
		t.Fatalf("bad CVE id %q: %v", s, err)
	}
	return id
}
