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
	ac := AssembledContext{
		Finding: FindingView{
			ID:          "F1",
			FaultlineID: "FL1",
			CVE:         "CVE-2024-0001",
			Components:  []string{"pkg:golang/example.com/x@1.0.0"},
		},
		Faultline: FaultlineView{ID: "FL1", CVE: "CVE-2024-0001"},
	}
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
