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
