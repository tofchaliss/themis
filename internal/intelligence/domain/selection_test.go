package domain

import "testing"

func TestSelectionType_Valid(t *testing.T) {
	for _, ty := range []SelectionType{SelectionFinding, SelectionRelease} {
		if !ty.Valid() {
			t.Errorf("expected %q valid", ty)
		}
	}
	// Rejected entry points, and why: a Position has no independent identity (it is
	// addressed only as a version of a Finding) and no use case asks a user to pick one;
	// "product" and "faultline" are addressable but nothing selects them today. All three
	// are Decision Context — assembled, never selected (EDR-TRUST-01 T9).
	for _, ty := range []SelectionType{"position", "product", "faultline", "", "FINDING"} {
		if ty.Valid() {
			t.Errorf("expected %q invalid", ty)
		}
	}
	if got := SelectionRelease.String(); got != "release" {
		t.Errorf("String() = %q, want %q", got, "release")
	}
}

func TestNewSelection_TrimsBlankIDs(t *testing.T) {
	sel := NewSelection(SelectionFinding, " F1 ", "", "   ", "F2")
	if len(sel.IDs) != 2 || sel.IDs[0] != "F1" || sel.IDs[1] != "F2" {
		t.Fatalf("IDs = %v, want [F1 F2] (blank ids dropped, whitespace trimmed)", sel.IDs)
	}
	if got := sel.First(); got != "F1" {
		t.Errorf("First() = %q, want F1", got)
	}
	if got := NewSelection(SelectionFinding).First(); got != "" {
		t.Errorf("First() on an empty Selection = %q, want empty", got)
	}
}

// Accepts is the contract enforced at the door, before any grounding is assembled or any
// provider is called. Cardinality being a capability declaration rather than a global
// setting is what lets it double as the fan-out guard (T9).
func TestCapability_Accepts(t *testing.T) {
	oneFinding := Capability{SelectionType: SelectionFinding, MinSelection: 1, MaxSelection: 1}
	manyFindings := Capability{SelectionType: SelectionFinding, MinSelection: 1, MaxSelection: 5}
	oneRelease := Capability{SelectionType: SelectionRelease, MinSelection: 1, MaxSelection: 1}

	cases := []struct {
		name string
		capb Capability
		sel  Selection
		want bool
	}{
		{"exactly one, as declared", oneFinding, NewSelection(SelectionFinding, "F1"), true},
		{"empty selection is below the minimum", oneFinding, NewSelection(SelectionFinding), false},
		{"two where one is allowed", oneFinding, NewSelection(SelectionFinding, "F1", "F2"), false},
		{"wrong type — a release sent to a Finding capability", oneFinding, NewSelection(SelectionRelease, "R1"), false},
		{"unknown type is never accepted", oneFinding, NewSelection(SelectionType("position"), "P1"), false},
		{"at the upper bound", manyFindings, NewSelection(SelectionFinding, "F1", "F2", "F3", "F4", "F5"), true},
		{"one past the upper bound", manyFindings, NewSelection(SelectionFinding, "F1", "F2", "F3", "F4", "F5", "F6"), false},
		{"release capability takes a release", oneRelease, NewSelection(SelectionRelease, "R1"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.capb.Accepts(c.sel); got != c.want {
				t.Fatalf("Accepts = %v, want %v", got, c.want)
			}
		})
	}
}

// The shipped capability reasons about one (Release, Faultline) concern, so it takes exactly
// one Finding. Pinned so a later edit cannot silently widen it.
func TestRecommendPositionV1_TakesExactlyOneFinding(t *testing.T) {
	c := RecommendPositionV1()
	if c.SelectionType != SelectionFinding || c.MinSelection != 1 || c.MaxSelection != 1 {
		t.Fatalf("selection contract = %s [%d,%d], want finding [1,1]", c.SelectionType, c.MinSelection, c.MaxSelection)
	}
	if !c.Accepts(NewSelection(SelectionFinding, "F1")) {
		t.Error("must accept a single Finding")
	}
	if c.Accepts(NewSelection(SelectionFinding, "F1", "F2")) {
		t.Error("must not accept two Findings")
	}
}
