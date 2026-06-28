package vexfeed

import "testing"

func TestParseOSVFeedSeverity(t *testing.T) {
	raw := []byte(`[{
		"id":"CVE-2024-X","aliases":["CVE-2024-X"],
		"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
		"affected":[
			{"package":{"ecosystem":"Alpine","name":"openssl"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0"}]}],
			 "database_specific":{"severity":"High"}},
			{"package":{"ecosystem":"Alpine","name":"curl"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0"}]}]}
		]
	}]`)
	out, err := ParseOSVFeed(raw, "alpine")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("assertions = %d, want 2", len(out))
	}
	// openssl: severity from database_specific, vector from entry severity block.
	var openssl, curl *struct{ sev, vec string }
	for i := range out {
		switch out[i].PackageName {
		case "openssl":
			openssl = &struct{ sev, vec string }{out[i].Severity, out[i].CVSSVector}
		case "curl":
			curl = &struct{ sev, vec string }{out[i].Severity, out[i].CVSSVector}
		}
	}
	if openssl == nil || openssl.sev != "high" || openssl.vec == "" {
		t.Fatalf("openssl severity/vector = %+v", openssl)
	}
	// curl: no database_specific → severity empty, but the entry CVSS vector still carried.
	if curl == nil || curl.sev != "" || curl.vec == "" {
		t.Fatalf("curl severity/vector = %+v", curl)
	}
}

func TestParseOSVFeedRockyUpstreamCVE(t *testing.T) {
	// Rocky RLSA records carry the CVE(s) in "upstream", not "aliases", and a
	// single advisory bundles several CVEs. Each finding must be keyed by the
	// canonical CVE (not RLSA-…), and the advisory must expand to one per CVE.
	raw := []byte(`[{
		"id":"RLSA-2023:1670",
		"upstream":["CVE-2023-25690","CVE-2023-27522"],
		"affected":[
			{"package":{"ecosystem":"Rocky Linux:8","name":"httpd"},
			 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.4.37-51.module+el8.8.0"}]}]}
		]
	}]`)
	out, err := ParseOSVFeed(raw, "rocky")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 assertions (one per upstream CVE), got %d: %+v", len(out), out)
	}
	got := map[string]bool{}
	for _, a := range out {
		got[a.CVEID] = true
		if a.AdvisoryID != "RLSA-2023:1670" {
			t.Fatalf("advisory id should be preserved, got %q", a.AdvisoryID)
		}
		if a.PackageName != "httpd" {
			t.Fatalf("package = %q", a.PackageName)
		}
	}
	if !got["CVE-2023-25690"] || !got["CVE-2023-27522"] {
		t.Fatalf("expected both upstream CVEs as canonical ids, got %v", got)
	}
}

func TestOSVEntryCVEIDsFallbackToAdvisoryID(t *testing.T) {
	// An advisory with no CVE anywhere keeps its own id (so the finding is not
	// dropped), only when that id is not itself a CVE.
	e := osvEntry{ID: "RLSA-2099:0001"}
	if ids := e.cveIDs(); len(ids) != 0 {
		t.Fatalf("non-CVE id should yield no canonical CVE, got %v", ids)
	}
}
