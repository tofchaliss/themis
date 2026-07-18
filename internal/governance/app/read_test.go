package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type fakeProjection struct {
	posture []app.PostureEntry
	blast   []string
	err     error
}

func (f fakeProjection) ReleasePosture(context.Context, string) ([]app.PostureEntry, error) {
	return f.posture, f.err
}

func (f fakeProjection) FaultlineBlastRadius(context.Context, string) ([]string, error) {
	return f.blast, f.err
}

func findingWithPositions(t *testing.T) domain.Finding {
	t.Helper()
	p1, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "v1", fixedClock{}.Now())
	pos1 := domain.ReconstitutePosition(1, domain.StanceAffected, "confirmed", human,
		domain.PositionInputs{AcceptedProposalID: "p1", FaultlineRef: "fl-1"}, fixedClock{}.Now())
	pos2 := domain.ReconstitutePosition(2, domain.StanceMitigated, "fixed", human,
		domain.PositionInputs{AcceptedProposalID: "p2", FaultlineRef: "fl-1"}, fixedClock{}.Now())
	return domain.ReconstituteFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1",
		[]domain.MatchedComponent{comp("pkg:a")}, domain.StagePositionEstablished,
		[]domain.GovernanceProposal{p1}, []domain.Position{pos1, pos2}, 5)
}

func TestReadService_GetFinding(t *testing.T) {
	repo := newRepo()
	repo.seed(findingWithPositions(t))
	rs := app.NewReadService(repo, fakeProjection{})

	f, err := rs.GetFinding(context.Background(), "fnd-1")
	if err != nil || f.ID() != "fnd-1" || len(f.Positions()) != 2 {
		t.Fatalf("get finding = %+v err=%v", f, err)
	}

	// By key.
	if _, ok, err := rs.GetFindingByKey(context.Background(), "rel-1", "fl-1"); err != nil || !ok {
		t.Errorf("by key: ok=%v err=%v", ok, err)
	}
	if _, ok, _ := rs.GetFindingByKey(context.Background(), "rel-x", "fl-x"); ok {
		t.Error("unknown key should be not found")
	}

	// Error propagates.
	ge := newRepo()
	ge.getByIDErr = errors.New("db down")
	if _, err := app.NewReadService(ge, fakeProjection{}).GetFinding(context.Background(), "fnd-1"); err == nil {
		t.Error("get error: expected error")
	}
}

func TestReadService_GetPosition(t *testing.T) {
	repo := newRepo()
	repo.seed(findingWithPositions(t))
	rs := app.NewReadService(repo, fakeProjection{})
	ctx := context.Background()

	// Latest (version <= 0).
	if pos, ok, err := rs.GetPosition(ctx, "fnd-1", 0); err != nil || !ok || pos.Version() != 2 {
		t.Errorf("latest = %+v ok=%v err=%v", pos, ok, err)
	}
	// Specific version.
	if pos, ok, err := rs.GetPosition(ctx, "fnd-1", 1); err != nil || !ok || pos.Stance() != domain.StanceAffected {
		t.Errorf("v1 = %+v ok=%v err=%v", pos, ok, err)
	}
	// Unknown version.
	if _, ok, _ := rs.GetPosition(ctx, "fnd-1", 9); ok {
		t.Error("unknown version should be not found")
	}
	// Finding with no position.
	repo.seed(identified(t, "fnd-2", "rel-2", "fl-2", "CVE-2"))
	if _, ok, _ := rs.GetPosition(ctx, "fnd-2", 0); ok {
		t.Error("no-position finding should return ok=false")
	}
	// Get error.
	ge := newRepo()
	ge.getByIDErr = errors.New("db down")
	if _, _, err := app.NewReadService(ge, fakeProjection{}).GetPosition(ctx, "fnd-1", 0); err == nil {
		t.Error("get error: expected error")
	}
}

func TestReadService_Projections(t *testing.T) {
	proj := fakeProjection{
		posture: []app.PostureEntry{{FindingID: "fnd-1", Stage: domain.StagePositionEstablished, Stance: domain.StanceAffected, HasPosition: true}},
		blast:   []string{"rel-1", "rel-2"},
	}
	rs := app.NewReadService(newRepo(), proj)
	ctx := context.Background()

	if got, err := rs.ReleasePosture(ctx, "rel-1"); err != nil || len(got) != 1 || got[0].FindingID != "fnd-1" {
		t.Errorf("posture = %+v err=%v", got, err)
	}
	if got, err := rs.FaultlineBlastRadius(ctx, "fl-1"); err != nil || len(got) != 2 {
		t.Errorf("blast = %+v err=%v", got, err)
	}

	// Errors propagate.
	bad := app.NewReadService(newRepo(), fakeProjection{err: errors.New("proj down")})
	if _, err := bad.ReleasePosture(ctx, "rel-1"); err == nil {
		t.Error("posture error: expected error")
	}
	if _, err := bad.FaultlineBlastRadius(ctx, "fl-1"); err == nil {
		t.Error("blast error: expected error")
	}
}
