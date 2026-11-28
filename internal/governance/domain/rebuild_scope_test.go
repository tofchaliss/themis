package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

// EDR-REBUILD-01 D4, D17 value 3: `rebuild:off` on any level wins, otherwise the nearest level
// decides, a level with both reads ask, and no tag at all keeps the Release out.
func TestResolveRebuildTag(t *testing.T) {
	cases := []struct {
		name                      string
		release, project, product []string
		want                      domain.RebuildTagMode
	}{
		{"no tag anywhere", []string{"team:a"}, nil, []string{"tier:1"}, domain.RebuildTagMode{Mode: domain.RebuildModeOff}},
		{"own auto", []string{"rebuild:auto"}, nil, nil, domain.RebuildTagMode{Mode: domain.RebuildModeAuto, Tag: domain.RebuildTagAuto, Level: domain.RebuildTagLevelRelease}},
		{"inherited from the project", nil, []string{" Rebuild:Ask "}, []string{"rebuild:auto"}, domain.RebuildTagMode{Mode: domain.RebuildModeAsk, Tag: domain.RebuildTagAsk, Level: domain.RebuildTagLevelProject}},
		{"inherited from the product", nil, nil, []string{"rebuild:auto"}, domain.RebuildTagMode{Mode: domain.RebuildModeAuto, Tag: domain.RebuildTagAuto, Level: domain.RebuildTagLevelProduct}},
		{"nearest wins over the product", []string{"rebuild:auto"}, nil, []string{"rebuild:ask"}, domain.RebuildTagMode{Mode: domain.RebuildModeAuto, Tag: domain.RebuildTagAuto, Level: domain.RebuildTagLevelRelease}},
		{"both on one level reads ask", []string{"rebuild:auto", "rebuild:ask"}, nil, nil, domain.RebuildTagMode{Mode: domain.RebuildModeAsk, Tag: domain.RebuildTagAsk, Level: domain.RebuildTagLevelRelease}},
		{"off on the product beats auto on the release", []string{"rebuild:auto"}, nil, []string{"rebuild:off"}, domain.RebuildTagMode{Mode: domain.RebuildModeOff, Tag: domain.RebuildTagOff, Level: domain.RebuildTagLevelProduct}},
		{"off on the release", []string{"rebuild:off"}, []string{"rebuild:auto"}, nil, domain.RebuildTagMode{Mode: domain.RebuildModeOff, Tag: domain.RebuildTagOff, Level: domain.RebuildTagLevelRelease}},
	}
	for _, c := range cases {
		if got := domain.ResolveRebuildTag(c.release, c.project, c.product); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

// D17: the effective mode is the lowest of the ceiling and the tag, and names who set it. The
// rows are the two tables of the decision.
func TestEffectiveRebuildMode(t *testing.T) {
	tag := func(m domain.RebuildMode) domain.RebuildTagMode { return domain.RebuildTagMode{Mode: m} }
	cases := []struct {
		ceiling   domain.RebuildMode
		ceilingBy string
		tag       domain.RebuildMode
		want      domain.RebuildMode
		wantBy    string
	}{
		{domain.RebuildModeAuto, domain.RebuildModeSetByInstallation, domain.RebuildModeAuto, domain.RebuildModeAuto, domain.RebuildModeSetByInstallation},
		{domain.RebuildModeAuto, domain.RebuildModeSetByInstallation, domain.RebuildModeAsk, domain.RebuildModeAsk, domain.RebuildModeSetByTag},
		{domain.RebuildModeAsk, domain.RebuildModeSetByInstallation, domain.RebuildModeAuto, domain.RebuildModeAsk, domain.RebuildModeSetByInstallation},
		{domain.RebuildModeAsk, domain.RebuildModeSetByPolicy, domain.RebuildModeAsk, domain.RebuildModeAsk, domain.RebuildModeSetByPolicy},
		{domain.RebuildModeAuto, domain.RebuildModeSetByInstallation, domain.RebuildModeOff, domain.RebuildModeOff, domain.RebuildModeSetByTag},
		{domain.RebuildModeOff, domain.RebuildModeSetByPolicy, domain.RebuildModeAuto, domain.RebuildModeOff, domain.RebuildModeSetByPolicy},
	}
	for _, c := range cases {
		got, by := domain.EffectiveRebuildMode(c.ceiling, c.ceilingBy, tag(c.tag))
		if got != c.want || by != c.wantBy {
			t.Errorf("ceiling %s (%s), tag %s: got %s by %s, want %s by %s", c.ceiling, c.ceilingBy, c.tag, got, by, c.want, c.wantBy)
		}
	}
}

func TestRebuildOutcome(t *testing.T) {
	cases := []struct {
		mode     domain.RebuildMode
		targeted int
		want     string
	}{
		{domain.RebuildModeAuto, 2, domain.RebuildOutcomeRequest},
		{domain.RebuildModeAsk, 1, domain.RebuildOutcomeRecommend},
		{domain.RebuildModeOff, 5, domain.RebuildOutcomeNone},
		{domain.RebuildModeAuto, 0, domain.RebuildOutcomeNone},
		{domain.RebuildMode("loud"), 3, domain.RebuildOutcomeNone},
	}
	for _, c := range cases {
		if got := domain.RebuildOutcome(c.mode, c.targeted); got != c.want {
			t.Errorf("%s/%d: got %s want %s", c.mode, c.targeted, got, c.want)
		}
	}
}

// The policy says why a candidate did not count: one reason each, the first rule that left it out.
func TestEvaluateRebuildCountsWhatItSkipped(t *testing.T) {
	p := domain.DefaultRebuildPolicy()
	got := domain.EvaluateRebuild(p, []domain.RebuildCandidate{
		{FindingID: "f1", PURL: "a", Severity: domain.SLABucketHigh, Fix: domain.RebuildFixKnown},
		{FindingID: "f2", PURL: "b", Severity: domain.SLABucketHigh, Fix: domain.RebuildFixKnown, Position: domain.StanceAcceptedRisk},
		{FindingID: "f3", PURL: "c", Severity: domain.SLABucketHigh, Fix: domain.RebuildFixKnown, ClaimClass: domain.ClaimScope},
		{FindingID: "f4", PURL: "d", Severity: domain.SLABucketHigh, Fix: domain.RebuildFixNone},
		{FindingID: "f5", PURL: "e", Severity: domain.SLABucketHigh, Fix: domain.RebuildFixUnknown},
		{FindingID: "f6", PURL: "f", Severity: domain.SLABucketHigh},
		{FindingID: "f7", PURL: "g", Severity: domain.SLABucketLow, Fix: domain.RebuildFixKnown},
	})
	want := map[string]int{
		domain.RebuildSkippedDecided: 1, domain.RebuildSkippedScope: 1, domain.RebuildSkippedNoFix: 1,
		domain.RebuildSkippedFixUnknown: 2, domain.RebuildSkippedBelowFloor: 1,
	}
	if len(got.Targeted) != 1 || got.Targeted[0].FindingID != "f1" || len(got.Skipped) != len(want) {
		t.Fatalf("targeted %+v skipped %+v", got.Targeted, got.Skipped)
	}
	for k, n := range want {
		if got.Skipped[k] != n {
			t.Errorf("skipped[%s] = %d, want %d", k, got.Skipped[k], n)
		}
	}
}
