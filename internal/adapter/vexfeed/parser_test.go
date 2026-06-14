package vexfeed_test

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
)

func TestParseCSAF(t *testing.T) {
	raw := []byte(`{
		"document":{"tracking":{"id":"RHSA-2024:0001"}},
		"vulnerabilities":[{"cve":"CVE-2024-0001","product_status":{"known_not_affected":["pkg:rpm/redhat/httpd@2.4.37-51.el8"]}}]
	}`)
	out, err := vexfeed.ParseCSAF(raw, "")
	if err != nil || len(out) != 1 || out[0].Status != domain.VEXStatusNotAffected {
		t.Fatalf("ParseCSAF() = %+v, %v", out, err)
	}
}

func TestParseCSAFMissingID(t *testing.T) {
	_, err := vexfeed.ParseCSAF([]byte(`{"document":{"tracking":{}}}`), "")
	if err == nil {
		t.Fatal("expected error for missing tracking id")
	}
}

func TestParseOSVFeed(t *testing.T) {
	raw := []byte(`[{
		"id":"ALPINE-1",
		"aliases":["CVE-2024-0002"],
		"affected":[{"package":{"ecosystem":"Alpine","name":"busybox"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0","fixed":"1.0-r1"}]}]}]
	}]`)
	out, err := vexfeed.ParseOSVFeed(raw, "alpine")
	if err != nil || len(out) != 1 || out[0].PackageName != "busybox" {
		t.Fatalf("ParseOSVFeed() = %+v, %v", out, err)
	}
}

func TestParseOSVSingleObject(t *testing.T) {
	raw := []byte(`{"id":"CVE-2024-0003","aliases":["CVE-2024-0003"],"affected":[{"package":{"ecosystem":"Alpine","name":"zlib"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"}]}]}]}`)
	out, err := vexfeed.ParseOSVFeed(raw, "alpine")
	if err != nil || len(out) != 1 {
		t.Fatalf("ParseOSVFeed() = %+v, %v", out, err)
	}
}

func TestEnrichmentMatcherPort(t *testing.T) {
	port := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}}
	got := port.Match("pkg:rpm/rhel/httpd@2.4.37-51.el8", "CVE-2023-25690", []domain.VendorVEXAssertion{{
		CVEID: "CVE-2023-25690", ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8", Status: domain.VEXStatusNotAffected,
	}})
	if !got.Matched {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestStaticFeedSource(t *testing.T) {
	src := vexfeed.StaticFeedSource{FeedName: "test", Assertions: []domain.VendorVEXAssertion{{CVEID: "CVE-1"}}}
	if src.Name() != "test" {
		t.Fatal(src.Name())
	}
	out, err := src.Fetch(t.Context())
	if err != nil || len(out) != 1 {
		t.Fatalf("Fetch() = %v, %v", out, err)
	}
}

func TestURLFeedSourceEmptyURL(t *testing.T) {
	src := vexfeed.URLFeedSource{Name_: "x", Fetcher: &vexfeed.HTTPFetcher{}}
	if _, err := src.Fetch(t.Context()); err == nil {
		t.Fatal("expected error")
	}
}

func TestCompareRPMEVR(t *testing.T) {
	// exercise via matcher phase 3 indirectly in TestPhase3_ErrataInherited
	m := vexfeed.DefaultMatcher{}
	got := m.Match("pkg:rpm/rhel/openssl@1.1.1k-6.el8_5.1", "CVE-1", []domain.VendorVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:rpm/redhat/openssl@1.1.1k-6.el8_5", Status: domain.VEXStatusNotAffected,
	}})
	if !got.Matched {
		t.Fatal("expected inherited match")
	}
}

func TestMatcherNoAssertions(t *testing.T) {
	got := (&vexfeed.DefaultMatcher{}).Match("pkg:rpm/rhel/a@1", "CVE-1", nil)
	if got.Matched || got.PURLMismatch {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestCaptureMismatchLogger(t *testing.T) {
	log := &vexfeed.CaptureMismatchLogger{}
	log.LogPURLMismatch("CVE-1", "a", "b")
	if len(log.Entries) != 1 {
		t.Fatal("expected entry")
	}
}

func TestNoOpMismatchLogger(t *testing.T) {
	vexfeed.NoOpMismatchLogger{}.LogPURLMismatch("CVE-1", "a", "b")
}

func TestNoOpSyncMetrics(t *testing.T) {
	m := vexfeed.NoOpSyncMetrics{}
	m.RecordSync("rhel", "ok")
	m.RecordAssertions("rhel", "exact", 1)
	m.RecordPURLMismatch("rhel")
}

func TestNoOpSyncLogger(t *testing.T) {
	l := vexfeed.NoOpSyncLogger{}
	l.Warn("x")
	l.Error("y")
}
