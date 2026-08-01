package feed

import "testing"

// A CSAF-VEX doc where the not_affected product-ids resolve to a package name via the PURL kept
// in the product_tree (branch product + relationship full_product_name). The two ids resolve to
// the same package and dedup to one statement; an unresolvable id is skipped.
const csafSample = `{
  "document": {"tracking": {"id": "RHSA-2024:0001", "current_release_date": "2024-01-15T00:00:00Z"}},
  "product_tree": {
    "branches": [
      {"category": "vendor", "name": "Red Hat", "branches": [
        {"category": "product_name", "name": "openssl",
         "product": {"product_id": "openssl", "name": "openssl",
                     "product_identification_helper": {"purl": "pkg:rpm/redhat/openssl"}}}
      ]}
    ],
    "relationships": [
      {"category": "default_component_of", "product_reference": "openssl", "relates_to_product_reference": "rhel-8",
       "full_product_name": {"product_id": "rhel-8:openssl", "name": "openssl on RHEL 8",
                             "product_identification_helper": {"purl": "pkg:rpm/redhat/openssl@1.0.2k-16.el8?arch=x86_64"}}}
    ]
  },
  "vulnerabilities": [
    {"cve": "CVE-2024-1", "product_status": {"known_not_affected": ["rhel-8:openssl", "openssl", "mystery:widget"]}}
  ]
}`

func TestParseCSAFVEX_ResolvesAndDedups(t *testing.T) {
	stmts, err := parseCSAFVEX([]byte(csafSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// "rhel-8:openssl" and "openssl" both resolve to "openssl" (deduped); "mystery:widget" has no
	// PURL in the tree and is skipped.
	if len(stmts) != 1 {
		t.Fatalf("statements = %+v, want 1 (deduped openssl)", stmts)
	}
	s := stmts[0]
	if s.CVE.String() != "CVE-2024-1" || s.Package != "openssl" {
		t.Errorf("statement = %+v, want CVE-2024-1 / openssl", s)
	}
	if s.Justification == "" {
		t.Error("justification should carry the advisory id")
	}
}

func TestParseCSAFVEX_SkipConditions(t *testing.T) {
	// No release date → skipped (nil, nil).
	noDate := `{"document":{"tracking":{"id":"X"}},"vulnerabilities":[{"cve":"CVE-2024-1","product_status":{"known_not_affected":["p"]}}]}`
	if stmts, err := parseCSAFVEX([]byte(noDate)); err != nil || stmts != nil {
		t.Errorf("no date: got (%v,%v), want (nil,nil)", stmts, err)
	}

	// A vulnerability without a canonical CVE is skipped; a valid one alongside still parses.
	mixed := `{
      "document":{"tracking":{"id":"X","current_release_date":"2024-01-15T00:00:00Z"}},
      "product_tree":{"branches":[{"category":"product_name","name":"p","product":{"product_id":"p","product_identification_helper":{"purl":"pkg:rpm/redhat/p"}}}]},
      "vulnerabilities":[
        {"cve":"not-a-cve","product_status":{"known_not_affected":["p"]}},
        {"cve":"CVE-2024-2","product_status":{"known_not_affected":["p"]}}
      ]}`
	stmts, err := parseCSAFVEX([]byte(mixed))
	if err != nil {
		t.Fatalf("mixed: %v", err)
	}
	if len(stmts) != 1 || stmts[0].CVE.String() != "CVE-2024-2" {
		t.Errorf("mixed statements = %+v, want only CVE-2024-2", stmts)
	}
}

func TestParseCSAFVEX_InvalidJSON(t *testing.T) {
	if _, err := parseCSAFVEX([]byte("{not json")); err == nil {
		t.Error("invalid json must error")
	}
}

func TestPurlPackageName(t *testing.T) {
	cases := map[string]string{
		"pkg:rpm/redhat/openssl@1.0.2k-16.el8?arch=x86_64": "openssl",
		"pkg:rpm/redhat/openssl":                           "openssl",
		"pkg:deb/debian/zlib1g@1.2.11":                     "zlib1g",
		"pkg:golang/github.com/foo/bar@v1.2.3":             "bar",
		"":                                                 "",
	}
	for in, want := range cases {
		if got := purlPackageName(in); got != want {
			t.Errorf("purlPackageName(%q) = %q, want %q", in, got, want)
		}
	}
}
