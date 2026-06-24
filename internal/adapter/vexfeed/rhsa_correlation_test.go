package vexfeed_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
)

// TestRHSAAdvisoryAsCorrelationSource covers the CR-4 RHSA NEVRA extraction: a
// Red Hat CSAF "fixed" product becomes an rpm correlation assertion (affected
// below the fixed NEVRA) that produces a finding with rhsa provenance, while a
// known_not_affected product yields no correlation finding (rangeless → dropped).
func TestRHSAAdvisoryAsCorrelationSource(t *testing.T) {
	raw := []byte(`{
		"document":{"tracking":{"id":"RHSA-2024:1"}},
		"vulnerabilities":[{"cve":"CVE-2024-C","product_status":[
			{"category":"fixed","branches":[{"product":{"product_id":"pkg:rpm/redhat/httpd@2.4.37-43.el8?arch=x86_64"}}]},
			{"category":"known_not_affected","branches":[{"product":{"product_id":"pkg:rpm/redhat/nginx@1.0"}}]}
		]}]
	}`)
	assertions, err := vexfeed.ParseCSAF(raw, "RHSA-2024:1")
	if err != nil {
		t.Fatal(err)
	}

	var httpd *domain.VendorVEXAssertion
	for i := range assertions {
		if assertions[i].PackageName == "httpd" {
			httpd = &assertions[i]
		}
	}
	if httpd == nil || httpd.Ecosystem != "rpm" || httpd.Fixed != "2.4.37-43.el8" {
		t.Fatalf("httpd assertion = %+v", httpd)
	}

	src := vexfeed.NewAssertionCorrelationSource(domain.FindingSourceRHSA)
	src.Load(assertions)

	// httpd below the fixed NEVRA → finding with rhsa provenance.
	got, err := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm", Name: "httpd", Version: "2.4.37-30.el8",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CVEID != "CVE-2024-C" || got[0].Source != domain.FindingSourceRHSA {
		t.Fatalf("httpd finding = %+v", got)
	}

	// httpd at/above the fix → no finding.
	if atFix, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm", Name: "httpd", Version: "2.4.37-43.el8",
	}); len(atFix) != 0 {
		t.Fatalf("at-fix httpd should not match: %+v", atFix)
	}

	// nginx known_not_affected (no fixed range) → dropped, no finding.
	if nginx, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm", Name: "nginx", Version: "1.0",
	}); len(nginx) != 0 {
		t.Fatalf("known_not_affected nginx should not correlate: %+v", nginx)
	}
}
