package vexfeed

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestFeedClassToSource(t *testing.T) {
	cases := map[string]string{
		"alpine": domain.FindingSourceDistroOSV,
		"rocky":  domain.FindingSourceDistroOSV,
		"wolfi":  domain.FindingSourceDistroOSV,
		"rhel":   domain.FindingSourceRHSA,
		"rhsa":   domain.FindingSourceRHSA,
	}
	for feed, want := range cases {
		if got := feedClassToSource(feed); got != want {
			t.Errorf("feedClassToSource(%q) = %q, want %q", feed, got, want)
		}
	}
}

func TestNormalizeAssertionName(t *testing.T) {
	if got := normalizeAssertionName("Alpine/BusyBox"); got != "busybox" {
		t.Fatalf("got %q", got)
	}
	if got := normalizeAssertionName("openssl"); got != "openssl" {
		t.Fatalf("got %q", got)
	}
}

func TestAssertionCorrelationSourceFetch(t *testing.T) {
	src := NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	if src.Name() != domain.FindingSourceDistroOSV {
		t.Fatalf("name = %q", src.Name())
	}
	src.Load([]domain.VendorVEXAssertion{
		// Alpine busybox affected [0, 1.36.1-r2), high severity.
		{Feed: "alpine", CVEID: "CVE-2024-1", Ecosystem: "Alpine", PackageName: "busybox", Introduced: "0", Fixed: "1.36.1-r2", Severity: "high"},
		// Rocky openssl affected [1.0, 3.0).
		{Feed: "rocky", CVEID: "CVE-2024-2", Ecosystem: "Rocky Linux", PackageName: "openssl", Introduced: "1.0", Fixed: "3.0"},
		// Rangeless assertion is dropped (no over-match).
		{Feed: "alpine", CVEID: "CVE-2024-3", Ecosystem: "Alpine", PackageName: "curl"},
	})

	// apk busybox below the fix → matched, severity + provenance carried.
	got, err := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "apk", Name: "alpine/busybox", Version: "1.36.1-r0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].CVEID != "CVE-2024-1" {
		t.Fatalf("busybox match = %+v", got)
	}
	if got[0].Severity != "high" || got[0].Source != domain.FindingSourceDistroOSV || len(got[0].FixVersions) != 1 {
		t.Fatalf("busybox provenance = %+v", got[0])
	}

	// apk busybox at the fixed version → not matched (upper exclusive).
	if got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "apk", Name: "busybox", Version: "1.36.1-r2",
	}); len(got) != 0 {
		t.Fatalf("fixed version should not match: %+v", got)
	}

	// rpm openssl in range → matched.
	if got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm", Name: "openssl", Version: "2.0",
	}); len(got) != 1 {
		t.Fatalf("openssl match = %+v", got)
	}

	// Rangeless curl → never indexed, no match.
	if got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "apk", Name: "curl", Version: "8.0",
	}); len(got) != 0 {
		t.Fatalf("rangeless assertion must not match: %+v", got)
	}

	// Unknown package → no match.
	if got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "apk", Name: "nonexistent", Version: "1.0",
	}); len(got) != 0 {
		t.Fatalf("unknown package = %+v", got)
	}
}

// TestAssertionCorrelationSourceRejectsCrossStream is the regression for the
// el8-vs-el9 cross-stream false positive: an el8 component must never match an
// el9-only fix (the real CVE-2022-29458 / ncurses case), but must still match a
// genuine el8 assertion whose fix is above the installed version.
func TestAssertionCorrelationSourceRejectsCrossStream(t *testing.T) {
	src := NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	src.Load([]domain.VendorVEXAssertion{
		// Only an el9 fix exists for this CVE (el8 is "not affected" upstream).
		{Feed: "rocky", CVEID: "CVE-2022-29458", Ecosystem: "Rocky Linux:9",
			PackageName: "ncurses", Introduced: "0", Fixed: "0:6.2-10.20210508.el9_6.2"},
		// A genuine el8 fix for a different CVE, above the installed build.
		{Feed: "rocky", CVEID: "CVE-2024-EL8", Ecosystem: "Rocky Linux:8",
			PackageName: "ncurses", Introduced: "0", Fixed: "0:6.1-12.20180224.el8"},
	})

	got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm", Name: "rocky/ncurses", Version: "6.1-10.20180224.el8",
	})

	var sawEl9, sawEl8 bool
	for _, r := range got {
		switch r.CVEID {
		case "CVE-2022-29458":
			sawEl9 = true
		case "CVE-2024-EL8":
			sawEl8 = true
		}
	}
	if sawEl9 {
		t.Fatalf("el8 component matched an el9-only fix (cross-stream false positive): %+v", got)
	}
	if !sawEl8 {
		t.Fatalf("el8 component should match the genuine el8 assertion: %+v", got)
	}
}

// TestAssertionCorrelationSourceCrossStreamFromPURL reproduces the runtime hole:
// the installed version field carries no ".elN" dist tag (only the purl does) and
// the el9 fix lives in an entry whose ecosystem label is coarse ("Rocky Linux").
// The stream must still be read — from the purl for the component, from the fixed
// NEVRA for the assertion — so the el9 fix is rejected for an el8 package.
func TestAssertionCorrelationSourceCrossStreamFromPURL(t *testing.T) {
	src := NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	src.Load([]domain.VendorVEXAssertion{
		{Feed: "rocky", CVEID: "CVE-2022-29458", Ecosystem: "Rocky Linux",
			PackageName: "ncurses", Introduced: "0", Fixed: "0:6.2-10.20210508.el9_6.2"},
	})
	got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "rpm", Name: "rocky/ncurses",
		Version: "6.1-10.20180224", // NB: no .el8 here — only the purl carries it
		PURL:    "pkg:rpm/rocky/ncurses@6.1-10.20180224.el8?arch=x86_64&distro=rocky-8.9",
	})
	for _, r := range got {
		if r.CVEID == "CVE-2022-29458" {
			t.Fatalf("el8 component (stream from purl) matched an el9 fix: %+v", got)
		}
	}
}

func TestAssertionCorrelationSourceMatchAll(t *testing.T) {
	src := NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	// introduced "0" with no fix → affects all versions.
	src.Load([]domain.VendorVEXAssertion{
		{Feed: "wolfi", CVEID: "CVE-2024-9", Ecosystem: "Wolfi", PackageName: "zlib", Introduced: "0"},
	})
	got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "apk", Name: "zlib", Version: "1.2.3",
	})
	if len(got) != 1 || got[0].CVEID != "CVE-2024-9" {
		t.Fatalf("match-all = %+v", got)
	}
}

func TestCorrelationLoaderRefresh(t *testing.T) {
	src := NewAssertionCorrelationSource(domain.FindingSourceDistroOSV)
	loader := &CorrelationLoader{
		Source: src,
		Feeds: []FeedSource{
			StaticFeedSource{FeedName: "alpine", Assertions: []domain.VendorVEXAssertion{
				{Feed: "alpine", CVEID: "CVE-1", Ecosystem: "Alpine", PackageName: "busybox", Introduced: "0", Fixed: "2.0"},
			}},
			nil, // skipped
		},
	}
	if err := loader.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh = %v", err)
	}
	if got, _ := src.FetchForComponent(context.Background(), domain.CanonicalComponent{Ecosystem: "apk", Name: "busybox", Version: "1.0"}); len(got) != 1 {
		t.Fatalf("loaded index empty: %+v", got)
	}

	// All feeds failing → aggregate error.
	failing := &CorrelationLoader{
		Source: NewAssertionCorrelationSource("x"),
		Feeds:  []FeedSource{StaticFeedSource{FeedName: "rocky", Err: errors.New("boom")}},
	}
	if err := failing.Refresh(context.Background()); err == nil {
		t.Fatal("expected aggregate failure error")
	}
}
