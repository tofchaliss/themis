package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type fakeAdvisor struct {
	rec      app.Recommendation
	produced bool
	err      error
	calls    int
}

func (a *fakeAdvisor) RecommendPosition(_ context.Context, _ string) (app.Recommendation, bool, error) {
	a.calls++
	return a.rec, a.produced, a.err
}

func seedFinding(t *testing.T, repo *fakeRepo) domain.FindingID {
	t.Helper()
	f, err := domain.NewFinding("F1", "rel-1", "fl-1", "CVE-2024-0001")
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	repo.seed(f)
	return f.ID()
}

func TestRecommendPositionDisabled(t *testing.T) {
	repo := newRepo()
	id := seedFinding(t, repo)
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{}) // no advisor = AI off
	pid, produced, err := svc.RecommendPosition(context.Background(), id)
	if err != nil || produced || pid != "" {
		t.Errorf("AI disabled → no proposal; got %q, %v, %v", pid, produced, err)
	}
}

func TestRecommendPositionFindingMissing(t *testing.T) {
	adv := &fakeAdvisor{produced: true, rec: app.Recommendation{Stance: "affected", Capability: "c"}}
	svc := app.NewFindingService(newRepo(), &seqIDs{}, fixedClock{}).WithAdvisor(adv)
	if _, _, err := svc.RecommendPosition(context.Background(), "nope"); err == nil {
		t.Error("missing finding should error before invoking AI")
	}
	if adv.calls != 0 {
		t.Error("AI must not be invoked for a missing finding")
	}
}

func TestRecommendPositionDeclines(t *testing.T) {
	repo := newRepo()
	id := seedFinding(t, repo)
	cases := []*fakeAdvisor{
		{produced: false},                      // declined
		{err: errors.New("intelligence down")}, // unreachable ≡ disabled
	}
	for _, adv := range cases {
		svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(adv)
		pid, produced, err := svc.RecommendPosition(context.Background(), id)
		if err != nil || produced || pid != "" {
			t.Errorf("decline/unreachable → no proposal; got %q, %v, %v", pid, produced, err)
		}
	}
}

func TestRecommendPositionProduced(t *testing.T) {
	repo := newRepo()
	id := seedFinding(t, repo)
	adv := &fakeAdvisor{produced: true, rec: app.Recommendation{
		Stance: "affected", Confidence: 0.8, Reasoning: "KEV-listed, no fix", Capability: "recommend_position@v1",
	}}
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(adv)

	pid, produced, err := svc.RecommendPosition(context.Background(), id)
	if err != nil || !produced || pid == "" {
		t.Fatalf("expected a produced advisory proposal; got %q, %v, %v", pid, produced, err)
	}

	f, err := repo.GetByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	var found bool
	for _, p := range f.Proposals() {
		if p.ID() != pid {
			continue
		}
		found = true
		if p.Proposer().Kind != domain.ActorAI {
			t.Errorf("proposer kind = %s, want ai", p.Proposer().Kind)
		}
		if p.Proposer().ID != "recommend_position@v1" {
			t.Errorf("provenance = %s, want capability ref", p.Proposer().ID)
		}
		if p.Status() != domain.StatusProposed {
			t.Errorf("AI proposal must NOT be auto-accepted; status = %s", p.Status())
		}
		if p.Stance() != domain.StanceAffected {
			t.Errorf("stance = %s, want affected", p.Stance())
		}
	}
	if !found {
		t.Error("advisory proposal was not recorded on the finding")
	}
}

func TestRecommendPositionInvalidStance(t *testing.T) {
	repo := newRepo()
	id := seedFinding(t, repo)
	adv := &fakeAdvisor{produced: true, rec: app.Recommendation{Stance: "bogus", Capability: "c"}}
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(adv)
	if _, _, err := svc.RecommendPosition(context.Background(), id); err == nil {
		t.Error("an invalid AI stance should surface the RaiseProposal error")
	}
}
