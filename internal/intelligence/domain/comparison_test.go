package domain_test

import (
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

func cmpFixture() domain.ReleaseComparison {
	return domain.ReleaseComparison{
		BaselineID:  "rel-a",
		CandidateID: "rel-b",
		Fixed: []domain.PostureEntry{{FindingID: "f1", CVE: "CVE-1", Components: []domain.PostureComponent{
			{PURL: "pkg:rpm/x@1", Name: "x", Source: "src-x"},
		}}},
		New:        []domain.PostureEntry{{FindingID: "f2", CVE: "CVE-2"}},
		Persisting: []domain.PostureEntry{{FindingID: "f3", CVE: "CVE-3"}},
	}
}

func TestReleaseComparison_Grounds(t *testing.T) {
	c := cmpFixture()
	for _, ref := range []string{"rel-a", "rel-b", "f1", "CVE-1", "pkg:rpm/x@1", "x", "src-x", "f2", "CVE-2", "f3", "CVE-3"} {
		if !c.Grounds(ref) {
			t.Errorf("Grounds(%q) = false, want true", ref)
		}
	}
	for _, ref := range []string{"", "rel-z", "CVE-9999", "libwhatever"} {
		if c.Grounds(ref) {
			t.Errorf("Grounds(%q) = true, want false", ref)
		}
	}
}

func TestReleaseComparison_Empty(t *testing.T) {
	if !(domain.ReleaseComparison{BaselineID: "a", CandidateID: "b"}).Empty() {
		t.Error("no buckets must read as empty")
	}
	if cmpFixture().Empty() {
		t.Error("populated buckets must not read as empty")
	}
}

// The prompt caps each bucket worst-first and reports what it hid — a truncated prompt that
// did not say so would let the model claim completeness it was never given.
func TestReleaseComparison_ShownCapsAndOmittedCounts(t *testing.T) {
	var many []domain.PostureEntry
	for i := 0; i < 20; i++ {
		many = append(many, domain.PostureEntry{FindingID: fmt.Sprintf("f%d", i), CVE: fmt.Sprintf("CVE-%d", i)})
	}
	c := domain.ReleaseComparison{CandidateID: "rel-b", Fixed: many, New: many[:3], Persisting: nil}
	if got := len(c.FixedShown()); got != 15 {
		t.Errorf("FixedShown = %d, want 15", got)
	}
	if got := c.FixedOmitted(); got != 5 {
		t.Errorf("FixedOmitted = %d, want 5", got)
	}
	if got := len(c.NewShown()); got != 3 || c.NewOmitted() != 0 {
		t.Errorf("NewShown = %d omitted %d, want 3/0", got, c.NewOmitted())
	}
	if got := len(c.PersistingShown()); got != 0 || c.PersistingOmitted() != 0 {
		t.Errorf("PersistingShown = %d omitted %d, want 0/0", got, c.PersistingOmitted())
	}
	// Shown must preserve the server's worst-first order.
	if c.FixedShown()[0].FindingID != "f0" {
		t.Errorf("shown[0] = %s, want f0", c.FixedShown()[0].FindingID)
	}
}

func TestCompareReleasesV1_Declaration(t *testing.T) {
	c := domain.CompareReleasesV1()
	if c.ID != "compare_releases" || c.Output != domain.OutputInformation {
		t.Fatalf("capability = %+v", c)
	}
	if c.MinSelection != 2 || c.MaxSelection != 2 || c.SelectionType != domain.SelectionRelease {
		t.Errorf("selection contract = %d..%d %s, want exactly two releases", c.MinSelection, c.MaxSelection, c.SelectionType)
	}
	if !c.HasNeed(domain.NeedReleaseComparison) || c.HasNeed(domain.NeedReleasePosture) {
		t.Error("must declare the comparison projection and not the posture")
	}
	// The validator must compile its schema — the registry addition is only real if it does.
	if _, err := domain.NewValidator(c); err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if _, ok := domain.DefaultRegistry().Lookup("compare_releases"); !ok {
		t.Error("DefaultRegistry must carry compare_releases")
	}
}

// The G-AI-5 tripwire: every shipped capability today is local-only, internal-privacy —
// nothing can reach a cloud provider, which is WHY the full data-classification /
// provider-clearance machinery (D10/INT-0069) is correctly deferred. The moment a capability
// declares otherwise, this fails the build and forces the G-AI-5 decision before the route
// exists — the R4 "guarded deferral" pattern.
func TestEveryShippedCapabilityIsLocalOnly(t *testing.T) {
	for _, id := range []string{"recommend_position", "plan_remediation", "explain_vulnerability", "compare_releases"} {
		c, ok := domain.DefaultRegistry().Lookup(id)
		if !ok {
			t.Fatalf("capability %q missing from the registry", id)
		}
		if !c.Routing.LocalOnly || c.Routing.Privacy != domain.PrivacyInternal {
			t.Errorf("%s routing = %+v — a non-local capability requires the G-AI-5 classification/clearance decision FIRST", id, c.Routing)
		}
	}
}
