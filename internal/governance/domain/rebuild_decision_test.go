package domain

import "testing"

// D3: only a new SBOM's evaluation is a rebuild trigger; a re-discovery never is.
func TestRebuildTriggerOfEvaluation(t *testing.T) {
	if got, ok := RebuildTriggerOfEvaluation(CauseNewSBOM); !ok || got != RebuildTriggerNewSBOM {
		t.Errorf("new_sbom = %q %v", got, ok)
	}
	for _, cause := range []string{CauseRediscovery, "", "other"} {
		if got, ok := RebuildTriggerOfEvaluation(cause); ok || got != "" {
			t.Errorf("%q = %q %v, want no trigger", cause, got, ok)
		}
	}
}

func TestRebuildNoneReason(t *testing.T) {
	cases := map[RebuildMode]string{
		RebuildModeAuto: RebuildNoneNothingCounts, RebuildModeAsk: RebuildNoneNothingCounts,
		RebuildModeOff: RebuildNoneModeOff, "": RebuildNoneModeOff,
	}
	for mode, want := range cases {
		if got := RebuildNoneReason(mode); got != want {
			t.Errorf("%q = %q, want %q", mode, got, want)
		}
	}
}

func TestRebuildEntryNames(t *testing.T) {
	for in, want := range map[string]string{"carrier": "carrier", ClaimScope: "scope", "": "unknown", "odd": "unknown"} {
		if got := RebuildClaimClassName(in); got != want {
			t.Errorf("class %q = %q, want %q", in, got, want)
		}
	}
	if RebuildPositionName("") != "none" || RebuildPositionName(StanceAcceptedRisk) != string(StanceAcceptedRisk) {
		t.Error("position names")
	}
}

// D10 item 6, no profile, no request.
func TestRebuildOutcomeWithProfile(t *testing.T) {
	cases := []struct {
		outcome string
		found   bool
		out     string
		why     string
	}{
		{RebuildOutcomeRequest, true, RebuildOutcomeRequest, ""},
		{RebuildOutcomeRequest, false, RebuildOutcomeRecommend, RebuildRecommendNoBuildProfile},
		{RebuildOutcomeRecommend, true, RebuildOutcomeRecommend, RebuildRecommendModeAsk},
		{RebuildOutcomeRecommend, false, RebuildOutcomeRecommend, RebuildRecommendNoBuildProfile},
		{RebuildOutcomeNone, true, RebuildOutcomeNone, ""},
		{RebuildOutcomeNone, false, RebuildOutcomeNone, ""},
	}
	for _, c := range cases {
		if out, why := RebuildOutcomeWithProfile(c.outcome, c.found); out != c.out || why != c.why {
			t.Errorf("%s found=%v: %q %q, want %q %q", c.outcome, c.found, out, why, c.out, c.why)
		}
	}
}
