package vexfeed_test

import (
	"testing"

	"github.com/themis-project/themis/internal/adapter/vexfeed"
	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func matcher() *vexfeed.DefaultMatcher {
	return &vexfeed.DefaultMatcher{}
}

func assertions(a ...domain.VendorVEXAssertion) []domain.VendorVEXAssertion {
	return a
}

func TestPhase1_ExactMatch(t *testing.T) {
	purl := "pkg:rpm/redhat/openssl@1.1.1k-6.el8_5"
	got := matcher().Match(purl, "CVE-2021-1234", assertions(domain.VendorVEXAssertion{
		CVEID: "CVE-2021-1234", ComponentPURL: purl, Status: domain.VEXStatusNotAffected,
	}))
	if !got.Matched || got.MatchType != domain.VEXMatchTypeExact {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestPhase2_RhelToRedhat(t *testing.T) {
	got := matcher().Match(
		"pkg:rpm/rhel/httpd@2.4.37-51.el8",
		"CVE-2023-25690",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2023-25690",
			ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if !got.Matched || got.MatchType != domain.VEXMatchTypeNamespaceNormalised {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestPhase2_RockyLinux(t *testing.T) {
	got := matcher().Match(
		"pkg:rpm/rocky/linux/busybox@1.35.0-3.el9",
		"CVE-2022-0001",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2022-0001",
			ComponentPURL: "pkg:rpm/rocky/busybox@1.35.0-3.el9",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if !got.Matched || got.MatchType != domain.VEXMatchTypeNamespaceNormalised {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestPhase2_AlmaLinux(t *testing.T) {
	got := matcher().Match(
		"pkg:rpm/alma/httpd@2.4.37-51.el8",
		"CVE-2023-25690",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2023-25690",
			ComponentPURL: "pkg:rpm/almalinux/httpd@2.4.37-51.el8",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if !got.Matched || got.MatchType != domain.VEXMatchTypeNamespaceNormalised {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestPhase3_ErrataInherited(t *testing.T) {
	got := matcher().Match(
		"pkg:rpm/rhel/openssl@1.1.1k-6.el8_5.1",
		"CVE-2021-1234",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2021-1234",
			ComponentPURL: "pkg:rpm/redhat/openssl@1.1.1k-6.el8_5",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if !got.Matched || got.MatchType != domain.VEXMatchTypeVersionInherited {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestPhase3_ErrataTooOld(t *testing.T) {
	got := matcher().Match(
		"pkg:rpm/rhel/openssl@1.1.1k-5.el8_5",
		"CVE-2021-1234",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2021-1234",
			ComponentPURL: "pkg:rpm/redhat/openssl@1.1.1k-6.el8_5",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if got.Matched || !got.PURLMismatch {
		t.Fatalf("Match() = %+v, want purl_mismatch", got)
	}
}

func TestPhase4_AlpineInRange(t *testing.T) {
	got := matcher().Match(
		"pkg:apk/alpine/busybox@1.35.0-r5",
		"CVE-2023-0001",
		assertions(domain.VendorVEXAssertion{
			CVEID: "CVE-2023-0001", Ecosystem: "Alpine", PackageName: "busybox",
			Introduced: "0", Fixed: "1.35.0-r6", Status: domain.VEXStatusAffected,
		}),
	)
	if !got.Matched || got.MatchType != domain.VEXMatchTypeRangeMatched || got.ResolvedStatus != domain.VEXStatusAffected {
		t.Fatalf("Match() = %+v", got)
	}
}

// TestPhase4_AlpineWithQualifiers locks in the real-world Syft/Trivy purl shape:
// the apk purl carries ?arch=...&distro=... qualifiers after the version. The
// matcher must strip those so the name parses as "busybox" (not
// "busybox@...?arch=...") and the version compares cleanly.
func TestPhase4_AlpineWithQualifiers(t *testing.T) {
	got := matcher().Match(
		"pkg:apk/alpine/busybox@1.35.0-r5?arch=x86_64&distro=3.20.2",
		"CVE-2023-0001",
		assertions(domain.VendorVEXAssertion{
			CVEID: "CVE-2023-0001", Ecosystem: "Alpine", PackageName: "busybox",
			Introduced: "0", Fixed: "1.35.0-r6", Status: domain.VEXStatusAffected,
		}),
	)
	if !got.Matched || got.MatchType != domain.VEXMatchTypeRangeMatched || got.ResolvedStatus != domain.VEXStatusAffected {
		t.Fatalf("Match() with qualifiers = %+v, want matched/range/affected", got)
	}
}

func TestPhase4_AlpineNotInRange_Fixed(t *testing.T) {
	got := matcher().Match(
		"pkg:apk/alpine/busybox@1.35.0-r6",
		"CVE-2023-0001",
		assertions(domain.VendorVEXAssertion{
			CVEID: "CVE-2023-0001", Ecosystem: "Alpine", PackageName: "busybox",
			Introduced: "0", Fixed: "1.35.0-r6",
		}),
	)
	if !got.Matched || got.ResolvedStatus != domain.VEXStatusNotAffected {
		t.Fatalf("Match() = %+v, want not_affected at fixed boundary", got)
	}
}

func TestPhase4_AlpineNotInRange_Below(t *testing.T) {
	got := matcher().Match(
		"pkg:apk/alpine/busybox@1.34.0-r0",
		"CVE-2023-0001",
		assertions(domain.VendorVEXAssertion{
			CVEID: "CVE-2023-0001", Ecosystem: "Alpine", PackageName: "busybox",
			Introduced: "1.35.0-r0", Fixed: "1.35.0-r6",
		}),
	)
	if !got.Matched || got.ResolvedStatus != domain.VEXStatusNotAffected {
		t.Fatalf("Match() = %+v", got)
	}
}

func TestAllPhasesFail(t *testing.T) {
	log := &vexfeed.CaptureMismatchLogger{}
	m := &vexfeed.DefaultMatcher{Logger: log}
	got := m.Match("pkg:rpm/rhel/unknown@1.0.0", "CVE-2021-9999", assertions(domain.VendorVEXAssertion{
		CVEID: "CVE-2021-9999", ComponentPURL: "pkg:rpm/redhat/other@9.9.9", Status: domain.VEXStatusNotAffected,
	}))
	if got.Matched || !got.PURLMismatch {
		t.Fatalf("Match() = %+v", got)
	}
	if len(log.Entries) != 1 || log.Entries[0].CVEID != "CVE-2021-9999" {
		t.Fatalf("log entries = %+v", log.Entries)
	}
}

func TestBackportAuthority_httpd(t *testing.T) {
	match := matcher().Match(
		"pkg:rpm/rhel/httpd@2.4.37-51.el8",
		"CVE-2023-25690",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2023-25690",
			ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if !match.Matched {
		t.Fatal("expected vendor match")
	}
	port := vexfeed.EnrichmentMatcher{Inner: vexfeed.DefaultMatcher{}}
	vendor := port.Match("pkg:rpm/rhel/httpd@2.4.37-51.el8", "CVE-2023-25690", assertions(match.Assertion))
	winner := domain.VEXAssertionMatch{
		ComponentPURL: "pkg:rpm/rhel/httpd@2.4.37-51.el8",
		CVEID:         "CVE-2023-25690",
		Status:        vendor.Status,
		Source:        domain.VEXSourceUpstreamVendor,
		MatchType:     string(vendor.MatchType),
	}
	state, _, _, _ := enrichment.ResolveEffectiveState(&winner)
	if state != domain.EffectiveStateNotAffected {
		t.Fatalf("effective_state = %q, want not_affected", state)
	}
}

func TestCaseNormalisation(t *testing.T) {
	got := matcher().Match(
		"pkg:RPM/RHEL/HTTPD@2.4.37-51.el8",
		"CVE-2023-25690",
		assertions(domain.VendorVEXAssertion{
			CVEID:         "CVE-2023-25690",
			ComponentPURL: "pkg:rpm/redhat/httpd@2.4.37-51.el8",
			Status:        domain.VEXStatusNotAffected,
		}),
	)
	if !got.Matched {
		t.Fatalf("Match() = %+v", got)
	}
}
