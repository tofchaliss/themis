package domain

import (
	"testing"
	"time"
)

func TestRebuildRecommendationClock(t *testing.T) {
	at := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	if RebuildRecommendationExpired(at, at.Add(RebuildRecommendationTTL-time.Second)) {
		t.Error("inside its 7 days a recommendation is not expired")
	}
	if !RebuildRecommendationExpired(at, at.Add(RebuildRecommendationTTL)) {
		t.Error("at 7 days a recommendation is expired")
	}
	if !RebuildApprovedHolds(at, at.Add(RebuildApprovedHold-time.Second)) || RebuildApprovedHolds(at, at.Add(RebuildApprovedHold)) {
		t.Error("the hold of an approval lasts RebuildApprovedHold and no longer")
	}
}

// D41 item 2: the same targeted components (in any order), policy record and version, build
// profile revision and reason are the same ask. Any one of them differing is a new ask.
func TestSameRebuildRecommendation(t *testing.T) {
	base := func() RebuildDecision {
		return RebuildDecision{
			RecommendReason: RebuildRecommendModeAsk,
			Policy:          RebuildDecisionPolicy{ScopeKind: "installation", Version: 2},
			BuildProfile:    &RebuildDecisionBuildProfile{Scope: "project", Revision: 3, SHA256: "abc"},
			Targeted:        []RebuildDecisionEntry{{FindingID: "f1", PURL: "p1"}, {FindingID: "f2", PURL: "p2"}},
		}
	}
	reordered := base()
	reordered.Targeted = []RebuildDecisionEntry{{FindingID: "f2", PURL: "p2", Severity: "high"}, {FindingID: "f1", PURL: "p1"}}
	if !SameRebuildRecommendation(base(), reordered) {
		t.Error("the order of the targets and their other facts must not matter")
	}
	noProfile, alsoNoProfile := base(), base()
	noProfile.BuildProfile, alsoNoProfile.BuildProfile = nil, nil
	if !SameRebuildRecommendation(noProfile, alsoNoProfile) {
		t.Error("two asks with no build profile are the same ask")
	}
	for name, change := range map[string]func(*RebuildDecision){
		"policy version": func(d *RebuildDecision) { d.Policy.Version = 3 },
		"policy scope":   func(d *RebuildDecision) { d.Policy.ScopeKind = "product" },
		"policy id":      func(d *RebuildDecision) { d.Policy.ScopeID = "prod-1" },
		"reason":         func(d *RebuildDecision) { d.RecommendReason = RebuildRecommendNoBuildProfile },
		"no profile":     func(d *RebuildDecision) { d.BuildProfile = nil },
		"profile": func(d *RebuildDecision) {
			d.BuildProfile = &RebuildDecisionBuildProfile{Scope: "project", Revision: 4, SHA256: "def"}
		},
		"fewer targets": func(d *RebuildDecision) { d.Targeted = d.Targeted[:1] },
		"other target":  func(d *RebuildDecision) { d.Targeted[1].PURL = "p9" },
	} {
		other := base()
		change(&other)
		if SameRebuildRecommendation(base(), other) {
			t.Errorf("%s: must be a different ask", name)
		}
	}
}

func TestApprovedRebuildRequestAndExpiryEvent(t *testing.T) {
	at := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	d := RebuildDecision{DecisionID: "dec-1", ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "proj-1",
		Outcome: RebuildOutcomeRecommend, RecommendReason: RebuildRecommendModeAsk, DecidedAt: at,
		Targeted: []RebuildDecisionEntry{{FindingID: "f1"}, {FindingID: "f2"}}}
	req := ApprovedRebuildRequest(d, RebuildApproval{Actor: "pat"})
	if req.DecisionID != "dec-1" || req.Outcome != RebuildOutcomeRequest || req.RecommendReason != "" || req.Approval == nil || req.Approval.Actor != "pat" {
		t.Errorf("request = %+v", req)
	}
	if d.Approval != nil || d.Outcome != RebuildOutcomeRecommend {
		t.Error("the recommendation itself must not change")
	}
	ev := NewRebuildRecommendationExpired(d, at.Add(RebuildRecommendationTTL))
	if ev.DecisionID != "dec-1" || ev.ReleaseID != "rel-1" || ev.ProductID != "prod-1" || ev.ProjectID != "proj-1" ||
		ev.TargetedCount != 2 || !ev.DecidedAt.Equal(at) || !ev.ExpiredAt.Equal(at.Add(RebuildRecommendationTTL)) {
		t.Errorf("event = %+v", ev)
	}
}
