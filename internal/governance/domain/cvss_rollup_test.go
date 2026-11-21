package domain

import "testing"

func comp(purl, claim, verdict string, env float64, status string) ComponentScore {
	c := ComponentScore{PURL: purl, Eligible: claim != ClaimScope, Open: verdict != "cleared_vendor_fix", Status: status}
	if status != ScoreUnavailable {
		c.Scores = &Scores{Environmental: env}
	} else {
		c.UnscoredReason = UnscoredNoApplicable
	}
	return c
}

func TestRollUpStates(t *testing.T) {
	const (
		open, cleared = "", "cleared_vendor_fix"
		fin, prov, un = ScoreFinal, ScoreProvisional, ScoreUnavailable
	)
	cases := []struct {
		name     string
		comps    []ComponentScore
		state    string
		score    float64
		coverage string
	}{
		{"none", nil, RollupNoComponents, 0, CoverageNotApplicable},
		{"scope only", []ComponentScore{comp("a", ClaimScope, open, 5, fin), comp("b", ClaimScope, open, 5, fin)}, RollupNoCarrier, 0, CoverageNotApplicable},
		{"scope cleared + scope open", []ComponentScore{comp("a", ClaimScope, cleared, 5, fin), comp("b", ClaimScope, open, 5, fin)}, RollupNoCarrier, 0, CoverageNotApplicable},
		{"carrier cleared x2", []ComponentScore{comp("a", "carrier", cleared, 5, fin), comp("b", "carrier", cleared, 5, fin)}, RollupNoOpenOccurrences, 0, CoverageNotApplicable},
		{"scope open + carrier cleared", []ComponentScore{comp("a", ClaimScope, open, 5, fin), comp("b", "carrier", cleared, 5, fin)}, RollupNoOpenOccurrences, 0, CoverageNotApplicable},
		{"scope open + unknown cleared", []ComponentScore{comp("a", ClaimScope, open, 5, fin), comp("b", "", cleared, 5, fin)}, RollupNoOpenOccurrences, 0, CoverageNotApplicable},
		{"carrier unusable + scope usable", []ComponentScore{comp("z", "carrier", open, 0, un), comp("a", "carrier", open, 0, un), comp("b", ClaimScope, open, 9.8, fin)}, RollupUnavailable, 0, CoverageNone},
		{"one usable one not", []ComponentScore{comp("a", "carrier", open, 6.5, fin), comp("b", "carrier", open, 0, un)}, RollupScored, 6.5, CoveragePartial},
		{"scope never counts", []ComponentScore{comp("a", "carrier", open, 6.5, fin), comp("b", "", open, 7.2, fin), comp("c", ClaimScope, open, 9.8, fin)}, RollupScored, 7.2, CoverageComplete},
		{"tie", []ComponentScore{comp("a", "carrier", open, 7.2, fin), comp("b", "carrier", open, 7.2, fin)}, RollupScored, 7.2, CoverageComplete},
		{"cleared never counts", []ComponentScore{comp("a", "carrier", cleared, 9.8, fin), comp("b", "carrier", open, 5.9, fin)}, RollupScored, 5.9, CoverageComplete},
		{"provisional counts", []ComponentScore{comp("a", "carrier", open, 5, prov)}, RollupScored, 5, CoverageComplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RollUp(tc.comps)
			if got.State != tc.state || got.Coverage.Value != tc.coverage {
				t.Fatalf("state %s coverage %s", got.State, got.Coverage.Value)
			}
			if tc.state == RollupScored {
				if got.Score == nil || *got.Score != tc.score || got.Band != ScoreBand(tc.score) {
					t.Fatalf("score %v", got.Score)
				}
			} else if got.Score != nil {
				t.Fatalf("state %s produced score %v", got.State, *got.Score)
			}
		})
	}
	tie := RollUp([]ComponentScore{comp("b", "carrier", "", 7.2, ScoreFinal), comp("a", "carrier", "", 7.2, ScoreFinal)})
	if len(tie.AtMaximum) != 2 || tie.AtMaximum[0] != "a" {
		t.Errorf("tie keeps all: %v", tie.AtMaximum)
	}
}

func TestRollUpFinality(t *testing.T) {
	// D5: provisional at the maximum makes the Finding provisional; below it does not.
	got := RollUp([]ComponentScore{comp("a", "carrier", "", 8.2, ScoreProvisional), comp("b", "carrier", "", 8.2, ScoreFinal)})
	if got.Status != ScoreProvisional || len(got.Contributors) != 2 {
		t.Errorf("tied provisional: %+v", got)
	}
	got = RollUp([]ComponentScore{comp("a", "carrier", "", 7.5, ScoreProvisional), comp("b", "carrier", "", 8.2, ScoreFinal)})
	if got.Status != ScoreFinal {
		t.Errorf("below-max provisional: %+v", got)
	}
	// 3 final + 1 provisional + 1 unavailable: coverage 4/5 partial, finality 3 of 4.
	got = RollUp([]ComponentScore{
		comp("a", "carrier", "", 5, ScoreFinal), comp("b", "carrier", "", 5, ScoreFinal), comp("c", "carrier", "", 5, ScoreFinal),
		comp("d", "carrier", "", 4, ScoreProvisional), comp("e", "carrier", "", 0, ScoreUnavailable),
	})
	if got.Coverage != (Ratio{4, 5, CoveragePartial}) || got.Finality != (Ratio{3, 4, CoveragePartial}) {
		t.Errorf("coverage %+v finality %+v", got.Coverage, got.Finality)
	}
	if len(got.Unassessed) != 1 || got.Unassessed[0].Reason != UnscoredNoApplicable {
		t.Errorf("unassessed %+v", got.Unassessed)
	}
	if ContentFingerprint(got) == ContentFingerprint(RollUp(nil)) {
		t.Error("fingerprints collide")
	}
}
