package feed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// alpineServer serves fake secdb branch files keyed by path ("/v3.18/main.json" → body).
// Unlisted paths 404, which for the client is a normal gap (a branch not published upstream).
func alpineServer(t *testing.T, files map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func carded(cves ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, c := range cves {
		m[c] = struct{}{}
	}
	return m
}

// The D5 bound lives in the client: the branch DB names thousands of CVEs, and only the carded
// ones may materialize as Proposals. The "0" version is the secdb's known-unfixed marker (a
// vulnerability list, not a bound) and non-CVE ids (XSA-…) can never match a card.
func TestAlpineClient_FoldsOnlyCardedCVEs(t *testing.T) {
	srv := alpineServer(t, map[string]string{
		"/v3.18/main.json": `{"packages":[
			{"pkg":{"name":"openssl","secfixes":{
				"3.1.4-r5":["CVE-2024-1","CVE-2024-9999"],
				"0":["CVE-2024-1111"],
				"3.1.4-r2":["XSA-123","CVE-2024-2 (annotated)"]}}},
			{"pkg":{"name":"busybox","secfixes":{"1.36.1-r7":["CVE-2024-1"]}}}
		]}`,
	})
	c := feed.NewAlpineClient(srv.URL, []string{"v3.18"}, nil)

	props, err := c.ProposalsForKnown(context.Background(), carded("CVE-2024-1", "CVE-2024-2"))
	if err != nil {
		t.Fatalf("ProposalsForKnown: %v", err)
	}
	if len(props) != 2 {
		t.Fatalf("proposals = %d, want 2 (CVE-2024-1 + CVE-2024-2; uncarded/unfixed/non-CVE dropped)", len(props))
	}
	byCVE := map[string][]domain.FixedVersion{}
	for _, p := range props {
		facts, ok := p.Proposal.VulnFacts()
		if !ok {
			t.Fatalf("%s: proposal is not vuln-facts", p.CVE)
		}
		byCVE[p.CVE.String()] = facts.Fixes
	}
	// CVE-2024-1 is fixed by two different packages — both bounds fold onto the one card.
	fixes := byCVE["CVE-2024-1"]
	sort.Slice(fixes, func(i, j int) bool { return fixes[i].Package < fixes[j].Package })
	if len(fixes) != 2 || fixes[0].Package != "busybox" || fixes[1].Package != "openssl" || fixes[1].Version != "3.1.4-r5" {
		t.Errorf("CVE-2024-1 fixes = %+v, want busybox + openssl bounds", fixes)
	}
	// CVE-2024-2 arrived with a trailing annotation the id-fold strips.
	if fixes := byCVE["CVE-2024-2"]; len(fixes) != 1 || fixes[0].Version != "3.1.4-r2" {
		t.Errorf("CVE-2024-2 fixes = %+v, want the openssl 3.1.4-r2 bound", fixes)
	}
}

// The same fix stated by several branches must not duplicate the bound; a branch the server
// lacks (404) is a normal gap the sweep walks past.
func TestAlpineClient_DedupsAcrossBranchesAndSkipsAbsentOnes(t *testing.T) {
	db := `{"packages":[{"pkg":{"name":"openssl","secfixes":{"3.1.4-r5":["CVE-2024-1"]}}}]}`
	srv := alpineServer(t, map[string]string{
		"/v3.18/main.json": db,
		"/v3.19/main.json": db, // same statement, second branch
	})
	c := feed.NewAlpineClient(srv.URL, []string{"v3.18", "v3.19", "v3.99"}, nil)

	props, err := c.ProposalsForKnown(context.Background(), carded("CVE-2024-1"))
	if err != nil {
		t.Fatalf("ProposalsForKnown: %v", err)
	}
	if len(props) != 1 {
		t.Fatalf("proposals = %d, want 1", len(props))
	}
	if facts, _ := props[0].Proposal.VulnFacts(); len(facts.Fixes) != 1 {
		t.Errorf("fixes = %+v, want the one deduplicated bound", facts.Fixes)
	}
}

// A non-404 failure aborts the sweep: there is one fetch, so its failure IS the sweep failing —
// feed health records it and the next interval retries. Same for a body that is not the secdb.
func TestAlpineClient_Errors(t *testing.T) {
	boom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(boom.Close)
	if _, err := feed.NewAlpineClient(boom.URL, []string{"v3.18"}, nil).
		ProposalsForKnown(context.Background(), carded("CVE-2024-1")); err == nil {
		t.Error("500: expected error")
	}

	garbage := alpineServer(t, map[string]string{"/v3.18/main.json": "not json"})
	if _, err := feed.NewAlpineClient(garbage.URL, []string{"v3.18"}, nil).
		ProposalsForKnown(context.Background(), carded("CVE-2024-1")); err == nil {
		t.Error("bad json: expected error")
	}
}

// Blank branch entries (a trailing comma in the env list) are skipped, not fetched as "//main.json".
func TestAlpineClient_SkipsBlankBranches(t *testing.T) {
	srv := alpineServer(t, map[string]string{})
	c := feed.NewAlpineClient(srv.URL, []string{"", "  "}, nil)
	props, err := c.ProposalsForKnown(context.Background(), carded("CVE-2024-1"))
	if err != nil || len(props) != 0 {
		t.Fatalf("blank branches: got (%d,%v), want (0,nil)", len(props), err)
	}
}
