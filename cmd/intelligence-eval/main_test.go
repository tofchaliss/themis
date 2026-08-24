//go:build llm

package main

import (
	"testing"

	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// The scoring logic is unit-tested without a live model (D-Δ4a-6): a produced/valid/honest
// outcome passes; a contract failure fails.
func TestScorePass(t *testing.T) {
	pass := []string{app.ReasonOK, app.ReasonInsufficient, app.ReasonNoGrounding, app.ReasonBudgetExhausted}
	fail := []string{app.ReasonSchemaInvalid, app.ReasonBusinessInvalid, app.ReasonProviderError, app.ReasonUnknownCap}
	for _, r := range pass {
		if !scorePass(app.Outcome{Reason: r}) {
			t.Errorf("reason %q must PASS", r)
		}
	}
	for _, r := range fail {
		if scorePass(app.Outcome{Reason: r}) {
			t.Errorf("reason %q must FAIL", r)
		}
	}
}

// selectionFor rebuilds the right Selection kind from the frozen context.
func TestSelectionFor(t *testing.T) {
	cmp := domain.AssembledContext{Comparison: domain.ReleaseComparison{BaselineID: "a", CandidateID: "b"}}
	if s := selectionFor("compare_releases", cmp); s.Type != domain.SelectionRelease || len(s.IDs) != 2 {
		t.Errorf("comparison selection = %+v", s)
	}
	rel := domain.AssembledContext{Release: domain.ReleasePosture{ReleaseID: "rel-1"}}
	if s := selectionFor("plan_remediation", rel); s.Type != domain.SelectionRelease || s.First() != "rel-1" {
		t.Errorf("release selection = %+v", s)
	}
	fnd := domain.AssembledContext{Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1"}}}
	if s := selectionFor("recommend_position", fnd); s.Type != domain.SelectionFinding || s.First() != "F1" {
		t.Errorf("finding selection = %+v", s)
	}
}

// replayProjection serves the frozen context's three sub-parts — the eval's whole reason it can
// re-run a capability without a live Governance read.
func TestReplayProjectionServesFrozenContext(t *testing.T) {
	ac := domain.AssembledContext{
		Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1"}},
		Release:    domain.ReleasePosture{ReleaseID: "rel-1"},
		Comparison: domain.ReleaseComparison{CandidateID: "cand"},
	}
	p := replayProjection{ac: ac}
	if a, _ := p.GetAssessment(nil, "x"); a.Finding.ID != "F1" {
		t.Error("assessment not served from frozen context")
	}
	if r, _ := p.GetReleasePosture(nil, "x"); r.ReleaseID != "rel-1" {
		t.Error("posture not served")
	}
	if c, _ := p.GetReleaseComparison(nil, "x", "y"); c.CandidateID != "cand" {
		t.Error("comparison not served")
	}
}
