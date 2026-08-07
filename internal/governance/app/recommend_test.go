package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
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
		Stance: "affected", Confidence: 0.8, Reasoning: "KEV-listed, no fix",
		Capability: "recommend_position@v1", DecidedBy: "llm:affected",
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

// The TRUST-8 caveat must reach the RECORDED RATIONALE, not merely be carried in a struct.
// That is the whole point: the rationale is the field a human reads when exercising the
// decision T4 reserves for them, and it is the least-verified part of an AI proposal — the
// structured evidence was grounded and Business-Verified, the narrative was not. A warning
// stored anywhere else is a warning a reviewer can miss.
func TestRecommendPosition_UngroundedRationaleMentionsAreRecordedInTheRationale(t *testing.T) {
	repo := newRepo()
	id := seedFinding(t, repo)
	adv := &fakeAdvisor{produced: true, rec: app.Recommendation{
		Stance:     "affected",
		Confidence: 0.95,
		Capability: "recommend_position@v1",
		DecidedBy:  "llm:affected",
		Reasoning:  "Included in release ee006ff7-f278-496e-8b31-ff0aba181db3.",
		// Business Verification passes: the cited evidence really is this Finding's faultline.
		Evidence:          []string{"fl-1"},
		RationaleWarnings: []string{"ee006ff7-f278-496e-8b31-ff0aba181db3"},
	}}
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(adv)

	pid, produced, err := svc.RecommendPosition(context.Background(), id)
	if err != nil || !produced {
		t.Fatalf("RecommendPosition: produced=%v err=%v — a warned proposal is still valid", produced, err)
	}

	var got domain.GovernanceProposal
	for _, p := range repo.byID[id].Proposals() {
		if p.ID() == pid {
			got = p
		}
	}
	rationale := got.Rationale()
	if !strings.Contains(rationale, "UNVERIFIED MENTIONS") {
		t.Fatalf("rationale = %q, want the caveat embedded in it", rationale)
	}
	if !strings.Contains(rationale, "ee006ff7-f278-496e-8b31-ff0aba181db3") {
		t.Fatalf("rationale = %q, want the specific invented id named", rationale)
	}
	// The narrative itself is preserved verbatim — the caveat annotates, never edits, what the
	// model said. Rewriting model output would destroy the audit trail it is evidence of.
	if !strings.Contains(rationale, "Included in release ee006ff7-f278-496e-8b31-ff0aba181db3.") {
		t.Fatalf("rationale = %q, want the original reasoning preserved unedited", rationale)
	}
	// Still Inferred, so the constitutional bar (T4) applies exactly as before — a warning is
	// not an extra gate, and its absence is not a licence.
	if got.EvidenceTrust() != value.TrustInferred {
		t.Fatalf("evidence class = %q, want %q", got.EvidenceTrust(), value.TrustInferred)
	}
}

// A clean rationale must stay clean: no caveat, no marker, nothing for a reviewer to learn to
// ignore. A warning that appears on every proposal is not a warning.
func TestRecommendPosition_CleanRationaleCarriesNoCaveat(t *testing.T) {
	repo := newRepo()
	id := seedFinding(t, repo)
	adv := &fakeAdvisor{produced: true, rec: app.Recommendation{
		Stance: "affected", Confidence: 0.9, Capability: "recommend_position@v1",
		Reasoning: "The installed version falls inside the affected range.",
		Evidence:  []string{"fl-1"},
	}}
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{}).WithAdvisor(adv)

	pid, _, err := svc.RecommendPosition(context.Background(), id)
	if err != nil {
		t.Fatalf("RecommendPosition: %v", err)
	}
	for _, p := range repo.byID[id].Proposals() {
		if p.ID() == pid && strings.Contains(p.Rationale(), "UNVERIFIED") {
			t.Fatalf("rationale = %q, want no caveat on a clean narrative", p.Rationale())
		}
	}
}
