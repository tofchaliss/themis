package vexfeed_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/testutil/findingset"
)

// TestDistroCorrelationGoldenCorpus is the CR-10 regression gate: a representative
// corpus of distro assertions (with the exact over-match / boundary counterexamples
// behind D-NVD-1) is correlated against a component matrix, and the resulting
// finding set is diffed against a committed golden snapshot. Any correlation change
// surfaces as an explicit added/removed delta. Regenerate with UPDATE_GOLDEN=1.
func TestDistroCorrelationGoldenCorpus(t *testing.T) {
	src := vexfeed.NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	src.Load([]domain.VendorVEXAssertion{
		{Feed: "alpine", CVEID: "CVE-2024-A", Ecosystem: "Alpine", PackageName: "busybox", Introduced: "0", Fixed: "1.36.1-r2", Severity: "high"},
		{Feed: "alpine", CVEID: "CVE-2024-B", Ecosystem: "Alpine", PackageName: "openssl", Introduced: "3.0", Fixed: "3.1.4-r0", Severity: "critical"},
		{Feed: "rocky", CVEID: "CVE-2024-C", Ecosystem: "Rocky Linux", PackageName: "httpd", Introduced: "0", Fixed: "2.4.37-43.el8"},
		{Feed: "wolfi", CVEID: "CVE-2024-D", Ecosystem: "Wolfi", PackageName: "curl", Introduced: "0"},
	})

	matrix := []domain.CanonicalComponent{
		{PURL: "pkg:apk/busybox", Name: "busybox", Ecosystem: "apk", Version: "1.36.1-r0"},  // below fix → match A
		{PURL: "pkg:apk/busybox", Name: "busybox", Ecosystem: "apk", Version: "1.36.1-r2"},  // at fix → no match
		{PURL: "pkg:apk/openssl", Name: "openssl", Ecosystem: "apk", Version: "3.0.5"},      // in range → match B
		{PURL: "pkg:apk/openssl", Name: "openssl", Ecosystem: "apk", Version: "2.9.0"},      // below introduced → no match
		{PURL: "pkg:rpm/httpd", Name: "httpd", Ecosystem: "rpm", Version: "2.4.37-30.el8"},  // below fix → match C
		{PURL: "pkg:rpm/httpd", Name: "httpd", Ecosystem: "rpm", Version: "2.4.37-43.el8"},  // at fix → no match
		{PURL: "pkg:apk/curl", Name: "curl", Ecosystem: "apk", Version: "8.0.0"},            // match-all → match D
		{PURL: "pkg:apk/nosuch", Name: "nosuch", Ecosystem: "apk", Version: "1.0"},          // unknown → no match
	}

	var keys []string
	for _, comp := range matrix {
		records, err := src.FetchForComponent(context.Background(), comp)
		if err != nil {
			t.Fatal(err)
		}
		for _, rec := range records {
			keys = append(keys, findingset.KeyString(
				domain.VersionedPURL(comp.PURL, comp.Version), rec.CVEID, rec.Source))
		}
	}

	findingset.AssertGolden(t, filepath.Join("testdata", "golden", "distro_corpus.golden"), keys)
}
