package domain

import "testing"

func TestScoreCause(t *testing.T) {
	base := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v65))
	mut := func(f func(*ComponentScore)) ComponentScore {
		n := run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v65))
		f(&n)
		return n
	}
	cases := []struct {
		name string
		next ComponentScore
		want string
	}{
		{"calculator", mut(func(c *ComponentScore) { c.CalculatorVersion = "k2" }), CauseCalculatorChanged},
		{"selection", mut(func(c *ComponentScore) { c.ClassPolicy = "class-2" }), CauseSelectionPolicyChanged},
		{"temporal policy", mut(func(c *ComponentScore) { c.TemporalPolicy = "temporal-2" }), CauseTemporalPolicyChanged},
		{"eligibility", mut(func(c *ComponentScore) { c.ClaimClass = ClaimScope }), CauseEligibilityChanged},
		{"applicability", mut(func(c *ComponentScore) { c.VerdictState = "cleared_vendor_fix" }), CauseApplicabilityChanged},
		{"requirement", mut(func(c *ComponentScore) { c.Requirements.CR.Value = "H" }), CauseRequirementChanged},
		{"added", run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v65), cnaOf("c", "z", v65)), CauseSourceAdded},
		{"withdrawn", run(rpm, cnaOf("a", "x", v65), cnaOf("b", "y", v65).inactive()), CauseSourceWithdrawn},
		{"relinked", run(rpm, cnaOf("a", "x", v65).ident("L"), cnaOf("b", "y", v65)), CauseIdentityRelinked},
		{"classified", run(rpm, cand("a", "x", v65), cnaOf("b", "y", v65)), CauseClassificationChanged},
		{"temporal", mut(func(c *ComponentScore) { c.Temporal[1].State = MetricAcceptedByPolicy }), CauseTemporalAccepted},
		{"corrected", mut(func(c *ComponentScore) { c.Candidates[0].ValidationReason = "x" }), CauseSourceCorrected},
	}
	for _, tc := range cases {
		if got := ScoreCause(&base, tc.next); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
	if ScoreCause(nil, base) != CauseComponentAdded {
		t.Error("first revision")
	}
	if RollupCause(true, nil) != CauseComponentRemoved || RollupCause(false, nil) != "recalculated" ||
		RollupCause(false, []string{"b", "a", "b"}) != "a,b" {
		t.Error("rollup cause")
	}
}
