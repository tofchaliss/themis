//go:build integration

package vexfeed

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/domain"
)

func TestParsePURLVariants(t *testing.T) {
	cases := []struct {
		in   string
		typ  string
		name string
	}{
		{"not-a-purl", "", ""},
		{"pkg:deb", "deb", ""},
		{"pkg:rpm/redhat/httpd", "rpm", "httpd"},
		{"pkg:rpm/redhat/httpd@2.4.37", "rpm", "httpd"},
	}
	for _, tc := range cases {
		got := parsePURL(tc.in)
		if got.Type != tc.typ || got.Name != tc.name {
			t.Fatalf("parsePURL(%q) = %+v", tc.in, got)
		}
	}
}

func TestBuildPURL(t *testing.T) {
	if buildPURL(parsedPURL{}) != "" {
		t.Fatal("expected empty")
	}
	got := buildPURL(parsedPURL{Type: "rpm", Namespace: "redhat", Name: "httpd", Version: "1.0"})
	if !strings.Contains(got, "httpd@1.0") {
		t.Fatalf("buildPURL() = %q", got)
	}
	got = buildPURL(parsedPURL{Type: "apk", Name: "busybox"})
	if got != "pkg:apk/busybox" {
		t.Fatalf("buildPURL() = %q", got)
	}
}

func TestStripErrataRevision(t *testing.T) {
	got := stripErrataRevision("1.1.1k-6-el8_5.1")
	if got != "1.1.1k-6-el8_5" {
		t.Fatalf("stripErrataRevision() = %q", got)
	}
	if stripErrataRevision("1.0") != "1.0" {
		t.Fatal("expected unchanged short version")
	}
}

func TestCompareRPMEVREpoch(t *testing.T) {
	if compareRPMEVR("1:2.0-1", "0:3.0-1") <= 0 {
		t.Fatal("expected higher epoch to win")
	}
	if compareVersionSegment("10", "2") <= 0 {
		t.Fatal("expected numeric compare")
	}
	if compareVersionSegment("alpha", "beta") >= 0 {
		t.Fatal("expected string compare")
	}
}

func TestStripAlpineBuildRevision(t *testing.T) {
	if stripAlpineBuildRevision("1.35.0-r5") != "1.35.0" {
		t.Fatal("expected strip")
	}
	if stripAlpineBuildRevision("1.35.0-rX") != "1.35.0-rX" {
		t.Fatal("expected no strip for non-numeric suffix")
	}
}

func TestMapCSAFCategory(t *testing.T) {
	if mapCSAFCategory("known_affected") != domain.VEXStatusAffected {
		t.Fatal("expected affected")
	}
	if mapCSAFCategory("weird_not_affected_label") != domain.VEXStatusNotAffected {
		t.Fatal("expected not_affected via contains")
	}
	if mapCSAFCategory("unknown") != domain.VEXStatusAffected {
		t.Fatal("expected default affected")
	}
}

func TestParseCSAFAdvisoryLegacyBranches(t *testing.T) {
	raw := []byte(`{
		"document":{"tracking":{"id":"RHSA-LEG"}},
		"vulnerabilities":[{"cve":"CVE-LEG","product_status":[{"category":"known_not_affected","branches":[{"product":{"product_id":"pkg:rpm/redhat/bash@1.0"}}]}]}]
	}`)
	out, err := ParseCSAFAdvisory(raw, "")
	if err != nil || len(out) != 1 {
		t.Fatalf("ParseCSAFAdvisory() = %v, %v", out, err)
	}
}

func TestParseOSVFeedFirstCVE(t *testing.T) {
	raw := []byte(`[{"id":"ADV","aliases":["CVE-2024-9999"],"affected":[{"package":{"ecosystem":"Alpine","name":"x"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]}]}]`)
	out, err := ParseOSVFeed(raw, "alpine")
	if err != nil || len(out) == 0 || out[0].CVEID != "CVE-2024-9999" {
		t.Fatalf("ParseOSVFeed() = %v, %v", out, err)
	}
}

func TestNamespacesEquivalent(t *testing.T) {
	if !namespacesEquivalent("rhel", "redhat") {
		t.Fatal("expected rhel/redhat equivalent")
	}
	if !namespacesEquivalent("rocky/linux", "rocky") {
		t.Fatal("expected rocky/linux equivalent")
	}
	if namespacesEquivalent("fedora", "redhat") {
		t.Fatal("expected not equivalent")
	}
}

func TestMatcherAlpineOSVBranches(t *testing.T) {
	m := DefaultMatcher{Logger: &CaptureMismatchLogger{}}
	got := m.Match("pkg:apk/alpine/busybox@1.0-r0", "CVE-1", []domain.VendorVEXAssertion{{
		CVEID: "CVE-1", Ecosystem: "Alpine", PackageName: "busybox", Introduced: "0", Fixed: "2.0-r0",
		Status: domain.VEXStatusAffected,
	}})
	if !got.Matched || got.MatchType != domain.VEXMatchTypeRangeMatched {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestMatcherLogPURLMismatch(t *testing.T) {
	capture := &CaptureMismatchLogger{}
	m := DefaultMatcher{Logger: capture}
	_ = m.Match("pkg:rpm/rhel/a@1", "CVE-1", []domain.VendorVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:rpm/debian/a@9", Status: domain.VEXStatusNotAffected,
	}})
	if len(capture.Entries) == 0 {
		t.Fatal("expected mismatch log")
	}
}

func TestMatcherMatchAssertionRPMMismatch(t *testing.T) {
	m := DefaultMatcher{}
	got := m.Match("pkg:rpm/rhel/httpd@1.0", "CVE-1", []domain.VendorVEXAssertion{{
		CVEID: "CVE-1", ComponentPURL: "pkg:rpm/debian/httpd@9", Status: domain.VEXStatusNotAffected,
	}})
	if got.Matched || !got.PURLMismatch {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestHTTPFetcherFetchOnceErrors(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})}
	f := &HTTPFetcher{HTTPClient: client}
	if _, _, err := f.fetchOnce(context.Background(), client, "http://example.com"); err == nil {
		t.Fatal("expected transport error")
	}
	client2 := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader("bad"))}, nil
	})}
	f2 := &HTTPFetcher{HTTPClient: client2}
	if _, _, err := f2.fetchOnce(context.Background(), client2, "http://example.com"); err == nil {
		t.Fatal("expected status error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNoOpSyncLoggerMetricsDirect(t *testing.T) {
	var logger NoOpSyncLogger
	logger.Warn("w")
	logger.Error("e")
	var metrics NoOpSyncMetrics
	metrics.RecordSync("f", "ok")
	metrics.RecordAssertions("f", "exact", 1)
	metrics.RecordPURLMismatch("f")
}

func TestListAssertionsForSBOMCVEsError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryErr: errors.New("fail")})
	_, err := store.ListAssertionsForSBOMCVEs(context.Background(), "sbom", []string{"CVE-1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFindSBOMDocumentIDsScanError(t *testing.T) {
	store := NewPostgresAssertionStore(&mockPool{queryRows: &errorScanRows{}})
	_, err := store.FindSBOMDocumentIDsForCVE(context.Background(), "CVE-1")
	if err == nil {
		t.Fatal("expected scan error")
	}
}

type errorScanRows struct{}

func (errorScanRows) Close()                                       {}
func (errorScanRows) Conn() *pgx.Conn                              { return nil }
func (errorScanRows) Err() error                                   { return nil }
func (errorScanRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (errorScanRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (errorScanRows) Next() bool                                   { return true }
func (errorScanRows) Scan(...any) error                            { return errors.New("scan failed") }
func (errorScanRows) Values() ([]any, error)                       { return nil, nil }
func (errorScanRows) RawValues() [][]byte                          { return nil }

func TestScanVendorAssertionsScanError(t *testing.T) {
	rows := &errorScanRows{}
	_, err := scanVendorAssertions(rows)
	if err == nil {
		t.Fatal("expected scan error")
	}
}
