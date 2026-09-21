package value_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

// EDR-VEX-02 D5/D6. Classification happens BEFORE any version is interpreted, so a non-OS
// product's version can never be read as an operating-system major.
func TestScopeFromCPE(t *testing.T) {
	for _, c := range []struct {
		in     string
		family string
		major  string
		why    string
	}{
		{"cpe:/o:redhat:enterprise_linux:8", value.FamilyEnterpriseLinux, "8",
			"the statement that SHOULD apply to a Rocky 8.10 estate"},
		{"cpe:/o:redhat:enterprise_linux:7", value.FamilyEnterpriseLinux, "7",
			"the measured defect's statement"},
		{"cpe:/a:redhat:openshift_pipelines:1", "openshift_pipelines", "1",
			"MEASURED, and the reason D5 exists: a valid version of 1 that is NOT an OS major"},
		{"cpe:2.3:o:redhat:enterprise_linux:9:*:*:*:*:*:*:*", value.FamilyEnterpriseLinux, "9",
			"the 2.3 formatted string is accepted too"},
		{"cpe:/o:redhat:enterprise_linux:8.10", value.FamilyEnterpriseLinux, "8",
			"a minor is dropped: a release's elN marker carries major granularity"},
		{"CPE:/O:RedHat:Enterprise_Linux:8", value.FamilyEnterpriseLinux, "8",
			"case folding, since vendors are inconsistent about it"},

		// Everything below is UNKNOWN — epistemic uncertainty, never product mismatch (D4).
		{"", "", "", "absent"},
		{"not-a-cpe", "", "", "malformed"},
		{"cpe:/o:redhat", "", "", "too few fields to name a product"},
		{"cpe:/a:redhat:rhel_software_collections", "", "", "a product with NO version answers half the question"},
		{"cpe:/o:redhat:enterprise_linux:*", "", "", "a wildcard version establishes nothing"},
		{"cpe:/o:redhat:enterprise_linux:-", "", "", "nor does the NA marker"},
	} {
		got := value.ScopeFromCPE(c.in)
		if got.Family != c.family || got.Major != c.major {
			t.Errorf("ScopeFromCPE(%q) = %+v, want family=%q major=%q — %s", c.in, got, c.family, c.major, c.why)
		}
	}
}

// The release side: an `elN` marker IS the family+major statement, which is what lets a Red Hat
// statement cover a Rocky release with no product-string comparison (D6).
func TestScopeFromRPMRelease(t *testing.T) {
	for _, c := range []struct {
		in    string
		major string
		why   string
	}{
		{"2.4.37-65.module+el8.10.0+40257+286895ef.9", "8", "the measured Rocky 8.10 httpd build"},
		{"1.0.2k-16.el8_10", "8", "a non-modular el8 build"},
		{"2.4.62-13.el9_8.5", "9", "el9"},
		{"2.4.63-13.el10_2.4", "10", "el10 — two digits, not truncated to 1"},
		{"2.4.37-65", "", "no marker → scope not established, so applicability is unknown"},
		{"", "", "empty"},
	} {
		got := value.ScopeFromRPMRelease(c.in)
		if got.Major != c.major {
			t.Errorf("ScopeFromRPMRelease(%q) = %+v, want major %q — %s", c.in, got, c.major, c.why)
		}
		if c.major != "" && got.Family != value.FamilyEnterpriseLinux {
			t.Errorf("ScopeFromRPMRelease(%q) family = %q, want %q", c.in, got.Family, value.FamilyEnterpriseLinux)
		}
	}
}

// THE CONCRETE MATRIX from EDR-VEX-02's validation order, against a Rocky Linux 8.10 release.
func TestMatchScope_TheDecidedMatrix(t *testing.T) {
	release := value.ScopeFromRPMRelease("2.4.37-65.module+el8.10.0+40257+286895ef.9")
	if !release.Known() {
		t.Fatalf("release scope not established: %+v", release)
	}
	for _, c := range []struct {
		name   string
		cpe    string
		want   value.ScopeMatch
		reason string
	}{
		{"RHEL 8 — same family and major", "cpe:/o:redhat:enterprise_linux:8",
			value.ScopeApplicable, "the ~90 statements that genuinely apply"},
		{"RHEL 7 — different major", "cpe:/o:redhat:enterprise_linux:7",
			value.ScopeNotApplicable, "the measured defect: visible, and blocked"},
		{"OpenShift Pipelines — different product", "cpe:/a:redhat:openshift_pipelines:1",
			value.ScopeNotApplicable, "KNOWN different product, so a definite answer, not unknown"},
		{"missing CPE — insufficient evidence", "",
			value.ScopeUnknown, "epistemic uncertainty"},
		{"malformed CPE — insufficient evidence", "cpe:garbage",
			value.ScopeUnknown, "epistemic uncertainty"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := value.MatchScope(value.ScopeFromCPE(c.cpe), release); got != c.want {
				t.Errorf("MatchScope = %q, want %q — %s", got, c.want, c.reason)
			}
		})
	}
}

// D5's counterexample as an explicit test: openshift_pipelines:1 must NEVER be read as major 1
// and compared against an OS release. Family is compared first, so the majors never meet.
func TestMatchScope_NonOSVersionIsNeverAnOSMajor(t *testing.T) {
	release := value.ProductScope{Family: value.FamilyEnterpriseLinux, Major: "1"}
	vendor := value.ScopeFromCPE("cpe:/a:redhat:openshift_pipelines:1")
	if vendor.Major != "1" {
		t.Fatalf("test premise: vendor major = %q, want 1", vendor.Major)
	}
	// Both carry major "1" — only the family distinguishes them. A resolver that compared
	// versions first would call this applicable.
	if got := value.MatchScope(vendor, release); got != value.ScopeNotApplicable {
		t.Errorf("MatchScope = %q, want not_applicable — the product must be classified BEFORE"+
			" its version is interpreted (D5)", got)
	}
}

// The two unplaceable sides are DIFFERENT answers (D11), and neither is ever not_applicable,
// which would assert a comparison that was not made.
//
// This test asserted one word for both until 2026-09-21, and that was the defect
// (DEF_VEX_UNKNOWN_CONFLATES_TWO_UNCERTAINTIES): `unknown` carried "the vendor said nothing
// readable" and "the vendor was perfectly clear but we cannot place our own release", which a
// reviewer reacts to completely differently.
func TestMatchScope_SeparatesTheTwoUnplaceableSides(t *testing.T) {
	rhel8 := value.ProductScope{Family: value.FamilyEnterpriseLinux, Major: "8"}
	quarkus := value.ScopeFromCPE("cpe:/a:redhat:quarkus:3")
	if !quarkus.Known() {
		t.Fatalf("test premise: %q must place, or this proves nothing", quarkus)
	}

	// The vendor's statement cannot be placed — a feed gap, and nothing whatever follows from it.
	if got := value.MatchScope(value.ProductScope{}, rhel8); got != value.ScopeUnknown {
		t.Errorf("unplaceable vendor scope = %q, want unknown", got)
	}
	// Half a scope is not a scope: a family with no major places nothing.
	if got := value.MatchScope(value.ProductScope{Family: "x"}, rhel8); got != value.ScopeUnknown {
		t.Errorf("family without major = %q, want unknown — half an answer is not an answer", got)
	}

	// The vendor was CLEAR; the release is what could not be placed. The measured case: Red Hat
	// names a Quarkus product and the Finding carries a Maven artifact with no `elN` build.
	if got := value.MatchScope(quarkus, value.ProductScope{}); got != value.ScopeNotComparable {
		t.Errorf("placed vendor scope vs unplaceable release = %q, want not_comparable", got)
	}

	// Both unplaceable: `unknown` wins, so that word always means exactly "the statement could
	// not be placed" and never leaks the release-side case.
	if got := value.MatchScope(value.ProductScope{}, value.ProductScope{}); got != value.ScopeUnknown {
		t.Errorf("both unplaceable = %q, want unknown — the unreadable statement is the deeper gap", got)
	}
}

// not_comparable is NON-CLEARING, like every state but applicable. Asserted as its own property
// because the whole safety argument for adding a state rests on it: the governance checks compare
// against ScopeApplicable, so a new word can never accidentally become a suppression.
func TestScopeNotComparableIsNotApplicable(t *testing.T) {
	if value.ScopeNotComparable == value.ScopeApplicable {
		t.Fatal("not_comparable must never equal applicable")
	}
	for _, s := range []value.ScopeMatch{value.ScopeUnknown, value.ScopeNotApplicable, value.ScopeNotComparable} {
		if s == value.ScopeApplicable {
			t.Errorf("%q equals applicable — absent evidence must never suppress", s)
		}
	}
}

// The remaining shapes of cpeProductVersion, reached through the exported surface: the 2.3 form's
// short variants, and escaped colons inside a component (a Perl-module product encodes as
// `ssh\:\:parallel`, the shape that once yielded a lone backslash in KN-CLAIM-1).
func TestScopeFromCPE_EdgeShapes(t *testing.T) {
	for _, c := range []struct {
		in     string
		family string
		major  string
		why    string
	}{
		{"cpe:2.3:o:redhat", "", "", "2.3 with too few fields to name a product"},
		{"cpe:2.3:o:redhat:enterprise_linux", "", "", "2.3 product with no version field"},
		{"cpe:/o:redhat:enterprise_linux", "", "", "2.2 product with no version field"},
		{`cpe:/a:redhat:ssh\:\:parallel:2`, "ssh::parallel", "2",
			"an escaped colon must not split the product — the KN-CLAIM-1 shape"},
		{"cpe:2.3:a:vendor:prod:3:*:*:*:*:*:*:*", "prod", "3", "2.3 with the full trailing field set"},
	} {
		got := value.ScopeFromCPE(c.in)
		if got.Family != c.family || got.Major != c.major {
			t.Errorf("ScopeFromCPE(%q) = %+v, want family=%q major=%q — %s", c.in, got, c.family, c.major, c.why)
		}
	}
}
