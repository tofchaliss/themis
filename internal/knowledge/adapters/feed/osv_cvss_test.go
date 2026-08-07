package feed_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/app"
)

func osvServing(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func urllib3(t *testing.T, srv *httptest.Server) []app.ProposalFor {
	t.Helper()
	got, err := feed.NewOSVClient(srv.URL, srv.Client()).VulnsForPackage(context.Background(),
		app.InventoryComponent{PURL: "pkg:pypi/urllib3@1.26.5", Name: "urllib3", Version: "1.26.5", Ecosystem: "pypi"})
	if err != nil {
		t.Fatalf("VulnsForPackage: %v", err)
	}
	return got
}

// The CVSS v4.0 / vector-selection gap (N6). Two defects in one line of the ACL:
//
//  1. `Severity[0]` let whichever vector the feed ordered FIRST decide the enterprise's severity.
//     OSV lists CVSS_V2, CVSS_V3 and CVSS_V4 side by side, so a v2 vector could silently outrank a
//     v3.1 one — a downgrade of the evidence with no trace.
//  2. The numeric score came only from OSV's database-specific extension, so a record carrying a
//     vector and no extension landed `severity=unknown` / `score=0` — and an unknown severity
//     scores zero, which sorts a real vulnerability to the BOTTOM of a triage queue.
func TestOSV_PrefersTheBestVectorAndDerivesTheScore(t *testing.T) {
	srv := osvServing(t, `{"vulns":[{
		"id":"CVE-2024-0001","modified":"2026-01-02T00:00:00Z","aliases":["CVE-2024-0001"],
		"severity":[
			{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:P/I:P/A:P"},
			{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
		],
		"affected":[{"package":{"name":"urllib3","ecosystem":"PyPI"},
		             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]
	}]}`)

	got := urllib3(t, srv)
	if len(got) != 1 {
		t.Fatalf("proposals = %d, want 1", len(got))
	}
	facts, ok := got[0].Proposal.VulnFacts()
	if !ok {
		t.Fatal("expected vuln facts")
	}
	if v := facts.CVSS.Vector(); v != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" {
		t.Errorf("vector = %q, want the v3.1 one — the v2 entry is listed first and must not win", v)
	}
	if s := facts.CVSS.Score(); s != 9.8 {
		t.Errorf("score = %v, want 9.8 derived from the vector (OSV published no number)", s)
	}
	if facts.Severity != value.SeverityCritical {
		t.Errorf("severity = %q, want critical — an unscored record used to land `unknown`", facts.Severity)
	}
}

// A v4.0-only record cannot be SCORED yet (the v4 formula is not implemented), but its vector is
// recorded rather than discarded, and no number is invented for it.
func TestOSV_V4OnlyRecordKeepsItsVectorWithoutInventingAScore(t *testing.T) {
	srv := osvServing(t, `{"vulns":[{
		"id":"CVE-2024-0002","modified":"2026-01-02T00:00:00Z","aliases":["CVE-2024-0002"],
		"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"}],
		"affected":[{"package":{"name":"urllib3","ecosystem":"PyPI"},
		             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]
	}]}`)

	got := urllib3(t, srv)
	if len(got) != 1 {
		t.Fatalf("proposals = %d, want 1", len(got))
	}
	facts, _ := got[0].Proposal.VulnFacts()
	if facts.CVSS.Vector() == "" {
		t.Error("the v4.0 vector must be recorded even though it cannot be scored yet")
	}
	if facts.CVSS.Score() != 0 {
		t.Errorf("score = %v, want 0 — inventing a number from an unimplemented formula is worse than admitting ignorance", facts.CVSS.Score())
	}
}

// An explicit database_specific score still WINS over derivation: it is what the source published,
// and deriving over it would replace a source's stated verdict with our arithmetic.
func TestOSV_PublishedScoreBeatsDerivation(t *testing.T) {
	srv := osvServing(t, `{"vulns":[{
		"id":"CVE-2024-0003","modified":"2026-01-02T00:00:00Z","aliases":["CVE-2024-0003"],
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
		"database_specific":{"cvss_score":6.1},
		"affected":[{"package":{"name":"urllib3","ecosystem":"PyPI"},
		             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]
	}]}`)

	got := urllib3(t, srv)
	facts, _ := got[0].Proposal.VulnFacts()
	if facts.CVSS.Score() != 6.1 {
		t.Errorf("score = %v, want the published 6.1 — derivation fills a gap, it does not overrule a source", facts.CVSS.Score())
	}
}
