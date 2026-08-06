package domain

import "testing"

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
