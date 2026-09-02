package domain

import (
	"strings"
	"testing"
)

func TestFaultlineFixAvailable(t *testing.T) {
	if (FaultlineView{}).FixAvailable() {
		t.Error("no fixed versions → FixAvailable should be false")
	}
	if !(FaultlineView{FixedVersions: []string{"1.2.3"}}).FixAvailable() {
		t.Error("fixed version present → FixAvailable should be true")
	}
}

func TestAssembledContextGrounds(t *testing.T) {
	ac := AssembledContext{Projection: FindingAssessment{Finding: FindingView{
		ID:          "F1",
		FaultlineID: "FL1",
		CVE:         "CVE-2024-0001",
		Components:  []string{"pkg:golang/example.com/x@1.0.0"},
	}, Knowledge: FaultlineView{ID: "FL1", CVE: "CVE-2024-0001"}}}
	grounded := []string{"F1", "FL1", "CVE-2024-0001", "pkg:golang/example.com/x@1.0.0"}
	for _, ref := range grounded {
		if !ac.Grounds(ref) {
			t.Errorf("ref %q should be grounded", ref)
		}
	}
	for _, ref := range []string{"", "CVE-9999-9999", "pkg:golang/other@2.0.0"} {
		if ac.Grounds(ref) {
			t.Errorf("ref %q must not be grounded", ref)
		}
	}
}

// Rule 4 made structural (EDR-TRUST-01 T10): Grounds anchors to the authoritative projection,
// so a shaped Capability Context cannot widen what counts as grounded.
//
// The runtime is allowed to reduce and reshape what it received. If Grounds consulted the
// shaped view instead, a transformation that invented or renamed an identifier would have its
// invention CONFIRMED — the check would be measuring the model against the runtime's own
// output. Delegating makes that impossible rather than merely discouraged.
func TestGroundsAnchorsToTheProjectionNotTheShapedView(t *testing.T) {
	ac := AssembledContext{
		Projection: FindingAssessment{
			Finding:   FindingView{ID: "F1", FaultlineID: "FL1", CVE: "CVE-1", Components: []string{"pkg:golang/x@1.0.0"}},
			Knowledge: FaultlineView{ID: "FL1", CVE: "CVE-1"},
		},
		// Precedents are retrieved by the runtime from its own semantic index — supplementary
		// reasoning context, never citable evidence. A model citing one is hallucinating a
		// source for the subject at hand.
		Precedents: []PrecedentPosition{{ReleaseID: "R-OTHER", SourceCVE: "CVE-9999", Component: "pkg:golang/invented@9.9"}},
	}

	for _, ref := range []string{"F1", "FL1", "CVE-1", "pkg:golang/x@1.0.0"} {
		if !ac.Grounds(ref) {
			t.Errorf("%q is in the projection and must be grounded", ref)
		}
	}
	for _, ref := range []string{"R-OTHER", "CVE-9999", "pkg:golang/invented@9.9", "F2", ""} {
		if ac.Grounds(ref) {
			t.Errorf("%q is NOT in the authoritative projection and must not be grounded", ref)
		}
	}
}

// The accessors read straight through to the authoritative projection — a shaped context has
// no private copy that could drift from what the owning context vouched for.
// A context carrying a Comparison grounds through IT — the comparison's identifiers, not the
// (zero-valued) finding projection beside it.
func TestAssembledContextGroundsThroughComparison(t *testing.T) {
	ac := AssembledContext{Comparison: ReleaseComparison{
		BaselineID: "rel-a", CandidateID: "rel-b",
		Persisting: []PostureEntry{{FindingID: "f3", CVE: "CVE-3"}},
	}}
	for _, ref := range []string{"rel-a", "rel-b", "f3", "CVE-3"} {
		if !ac.Grounds(ref) {
			t.Errorf("Grounds(%q) = false, want true", ref)
		}
	}
	if ac.Grounds("CVE-404") {
		t.Error("an identifier in no bucket must not ground")
	}
}

func TestAssembledContextAccessorsReadTheProjection(t *testing.T) {
	ac := AssembledContext{Projection: FindingAssessment{
		Finding:   FindingView{ID: "F1", ReleaseID: "R1"},
		Knowledge: FaultlineView{ID: "FL1", Severity: "high"},
	}}
	if ac.Finding().ID != "F1" || ac.Finding().ReleaseID != "R1" {
		t.Errorf("Finding() = %+v", ac.Finding())
	}
	if ac.Faultline().ID != "FL1" || ac.Faultline().Severity != "high" {
		t.Errorf("Faultline() = %+v", ac.Faultline())
	}
}

// An empty projection grounds nothing — a missing projection must never read as "everything
// is grounded", which would turn a failed read into a licence to hallucinate freely.
func TestEmptyProjectionGroundsNothing(t *testing.T) {
	var p FindingAssessment
	for _, ref := range []string{"F1", "FL1", "CVE-1", ""} {
		if p.Grounds(ref) {
			t.Errorf("empty projection must not ground %q", ref)
		}
	}
}

// PLAN-6, second attempt — the LIVE ref, verbatim from the VM.
//
// The first attempt tightened the prompt. It failed identically, because a model citing the
// heading of the item it is discussing is stable behaviour, not noise — groundsRef's own comment
// had already recorded that across two earlier rounds. Fixing it in the prompt a third time was
// repeating a step that had twice been shown not to work.
//
// The gate now strips "+N more" first, because the renderer wrote that suffix, not the model.
// The second and third cases are the ones that matter: normalising our own artifact must not
// weaken what the citation actually asserts.
func TestGroundsRef_TruncatedPackageHeading(t *testing.T) {
	posture := ReleasePosture{ReleaseID: "rel-1", Entries: []PostureEntry{
		{FindingID: "f1", CVE: "CVE-2026-1", ResidualPriority: 70, Components: []PostureComponent{
			{Name: "perl-Carp", Source: "perl-Carp", Ecosystem: "rpm"},
			{Name: "perl-constant", Source: "perl-constant", Ecosystem: "rpm"},
			{Name: "perl-Data-Dumper", Source: "perl-Data-Dumper", Ecosystem: "rpm"},
		}},
	}}
	ac := AssembledContext{Release: posture}

	for _, tc := range []struct {
		name, ref string
		want      bool
	}{
		{"the live ref, verbatim", "perl-Carp, perl-constant, perl-Data-Dumper +29 more", true},
		{"an invented name still fails", "perl-Carp, not-a-package +29 more", false},
		{"a bare invented name still fails", "not-a-package", false},
		{"the suffix alone grounds nothing", "+29 more", false},
		{"no suffix, all real", "perl-Carp, perl-constant", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := groundsRef(ac, tc.ref); got != tc.want {
				t.Errorf("groundsRef(%q) = %v, want %v", tc.ref, got, tc.want)
			}
		})
	}
}

// The named `python38:3.8-...` form is preferred when present, because it NAMES the stream where
// the build marker only identifies it.
func TestStreamKeyPrefersTheNamedStream(t *testing.T) {
	fixes := []PostureFix{{Package: "PyYAML", Version: "python38:3.8-8030020200818121840.4190259b"}}
	if got := streamKeyFor(fixes, "PyYAML"); got != "python38:3.8" {
		t.Errorf("streamKeyFor = %q, want %q", got, "python38:3.8")
	}
	// An ordinary version is not a stream, and must not become a grouping key.
	if got := streamKeyFor([]PostureFix{{Package: "PyYAML", Version: "5.1"}}, "PyYAML"); got != "" {
		t.Errorf("streamKeyFor(ordinary version) = %q, want empty", got)
	}
	// An RPM NEVRA must NOT read as a named stream. `0:1-1.module+el8.4.0+570+c2eaf144` is
	// epoch:version-release, and a looser pattern parsed it as the stream "0:1" — merging every
	// module build sharing an epoch:version, across different EL minors. Caught by
	// TestPlanActions_DifferentModuleBuildsDoNotMerge; asserted here at the recogniser.
	nevra := []PostureFix{{Package: "PyYAML", Version: "0:1-1.module+el8.4.0+570+c2eaf144"}}
	if got := streamKeyFor(nevra, "PyYAML"); got != ".module+el8.4.0+570+c2eaf144" {
		t.Errorf("streamKeyFor(NEVRA) = %q, want the BUILD marker, not an epoch parsed as a stream", got)
	}
	// A fix for a DIFFERENT package must not be borrowed (AI-GROUND-1's rule, applied here).
	if got := streamKeyFor([]PostureFix{{Package: "other", Version: "0:1-1.module+el8.4.0+570+c2eaf144"}}, "PyYAML"); got != "" {
		t.Errorf("streamKeyFor(other package's fix) = %q, want empty", got)
	}
}

// G-AI-3: the delta weight halves a fully-disjoint release's rank, keeps an identical one
// whole, and leaves the unknown case unweighted; exact-CVE precedents rank by weight alone.
func TestPrecedentDeltaWeightAndRankScore(t *testing.T) {
	full := PrecedentPosition{Score: 0.8, ReleaseOverlap: 1.0, OverlapKnown: true}
	none := PrecedentPosition{Score: 0.8, ReleaseOverlap: 0.0, OverlapKnown: true}
	unknown := PrecedentPosition{Score: 0.8}
	if full.DeltaWeight() != 1.0 || none.DeltaWeight() != 0.5 || unknown.DeltaWeight() != 1.0 {
		t.Fatalf("weights = %v %v %v", full.DeltaWeight(), none.DeltaWeight(), unknown.DeltaWeight())
	}
	if full.RankScore() != 0.8 || none.RankScore() != 0.4 {
		t.Errorf("semantic ranks = %v %v", full.RankScore(), none.RankScore())
	}
	exact := PrecedentPosition{Score: 0, ReleaseOverlap: 0.6, OverlapKnown: true}
	if exact.RankScore() != 0.8 { // weight alone: 0.5 + 0.5*0.6
		t.Errorf("exact-CVE rank = %v, want the delta weight", exact.RankScore())
	}
}

// AI-204-2: thinness is named only when the backend KNOWS the grounding cannot support a
// stance — all-scope components, or zero version evidence. Unknown claim classes count as
// carriers (EDR-CORRELATION-01), so they are never thin.
func TestGroundingThinness(t *testing.T) {
	base := func() FindingAssessment {
		return FindingAssessment{
			Finding:   FindingView{ID: "F1", Components: []string{"a", "b"}, ClaimClasses: []string{"scope", "scope"}},
			Knowledge: FaultlineView{AffectedRanges: []string{"<1.2"}},
		}
	}

	if got := GroundingThinness(base()); !strings.Contains(got, "all scope-class") || !strings.Contains(got, "2 component(s)") {
		t.Errorf("all-scope = %q", got)
	}

	mixed := base()
	mixed.Finding.ClaimClasses = []string{"scope", "carrier"}
	if got := GroundingThinness(mixed); got != "" {
		t.Errorf("a single carrier must not be thin: %q", got)
	}

	unknown := base()
	unknown.Finding.ClaimClasses = []string{"scope", ""}
	if got := GroundingThinness(unknown); got != "" {
		t.Errorf("unknown counts as carrier, must not be thin: %q", got)
	}

	misaligned := base()
	misaligned.Finding.ClaimClasses = []string{"scope"} // an older node sent no classes
	if got := GroundingThinness(misaligned); got != "" {
		t.Errorf("misaligned classes must not claim thinness: %q", got)
	}

	noEvidence := FindingAssessment{Finding: FindingView{ID: "F1", Components: []string{"a"}, ClaimClasses: []string{"carrier"}}}
	if got := GroundingThinness(noEvidence); !strings.Contains(got, "no affected ranges and no fix versions") {
		t.Errorf("no version evidence = %q", got)
	}

	healthy := base()
	healthy.Finding.ClaimClasses = []string{"carrier", "carrier"}
	if got := GroundingThinness(healthy); got != "" {
		t.Errorf("healthy grounding = %q, want empty", got)
	}

	// EDR-VERDICT-01 D7 / AI-REC-1: every carrier cleared by a vendor-fix verdict ⇒ nothing
	// live to decide about — diagnosably thin, not a model failure.
	allCleared := base()
	allCleared.Finding.ClaimClasses = []string{"carrier", "scope"}
	allCleared.Finding.VerdictStates = []string{"cleared_vendor_fix", ""}
	if got := GroundingThinness(allCleared); !strings.Contains(got, "every carrier cleared") {
		t.Errorf("all-carriers-cleared = %q, want the cleared-thinness class", got)
	}
	// One OPEN carrier beside a cleared one is a live grounding — never thin.
	oneLive := base()
	oneLive.Finding.ClaimClasses = []string{"carrier", "carrier"}
	oneLive.Finding.VerdictStates = []string{"cleared_vendor_fix", ""}
	if got := GroundingThinness(oneLive); got != "" {
		t.Errorf("one live carrier must not be thin: %q", got)
	}
}

// AI-REC-1, measured 2026-09-02: a recommendation grounded `affected` at 0.90 on a CLEARED
// copy, because the prompt showed bare purls. ComponentLines states each occurrence's verdict
// so the model can cite the clearance instead of tripping over it; missing/short verdict
// arrays (an older projection) read as open — the fail-safe direction.
func TestFindingViewComponentLines(t *testing.T) {
	f := FindingView{
		Components:     []string{"pkg:pypi/setuptools@39.2.0", "pkg:pypi/setuptools@70.3.0", "pkg:rpm/rocky/python3-ply@3.9-9.el8"},
		ClaimClasses:   []string{"carrier", "carrier", "scope"},
		VerdictStates:  []string{"cleared_vendor_fix", "", ""},
		VerdictGrades:  []string{"inferred", "", ""},
		VerdictReasons: []string{"matched to platform-python-setuptools 39.2.0-9.el8_10 at the distro version", "", ""},
	}
	lines := f.ComponentLines()
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if !strings.Contains(lines[0], "CLEARED by vendor fix (inferred)") ||
		!strings.Contains(lines[0], "platform-python-setuptools") ||
		!strings.Contains(lines[0], "NOT live evidence") {
		t.Errorf("cleared line = %q, want the labeled clearance with grade and premise", lines[0])
	}
	if !strings.Contains(lines[1], "OPEN") || strings.Contains(lines[1], "CLEARED") {
		t.Errorf("open line = %q", lines[1])
	}
	if !strings.Contains(lines[2], "scope-class") {
		t.Errorf("scope line = %q", lines[2])
	}

	// An older projection with no verdict arrays: every non-scope row reads OPEN.
	old := FindingView{Components: []string{"a", "b"}, ClaimClasses: []string{"carrier", "scope"}}
	oldLines := old.ComponentLines()
	if !strings.Contains(oldLines[0], "OPEN") || !strings.Contains(oldLines[1], "scope-class") {
		t.Errorf("older projection lines = %v", oldLines)
	}
	if old.OpenCarrierCount() != 1 {
		t.Errorf("OpenCarrierCount (older projection) = %d, want 1", old.OpenCarrierCount())
	}
	if f.OpenCarrierCount() != 1 {
		t.Errorf("OpenCarrierCount = %d, want 1 — cleared and scope rows are not live", f.OpenCarrierCount())
	}
	// A clearance without grade/reason still labels itself.
	bare := FindingView{Components: []string{"x"}, ClaimClasses: []string{"carrier"}, VerdictStates: []string{"cleared_vendor_fix"}}
	if l := bare.ComponentLines()[0]; !strings.Contains(l, "CLEARED by vendor fix —") && !strings.Contains(l, "CLEARED by vendor fix — NOT") {
		t.Errorf("bare clearance line = %q", l)
	}
}
