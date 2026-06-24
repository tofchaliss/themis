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
