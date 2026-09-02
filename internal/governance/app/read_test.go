package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
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
	p1, _ := domain.NewGovernanceProposal("p1", human, domain.StanceAffected, "v1", fixedClock{}.Now(), value.TrustAsserted)
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
	rs := app.NewReadService(repo, fakeProjection{}, nil, 0)

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
	if _, err := app.NewReadService(ge, fakeProjection{}, nil, 0).GetFinding(context.Background(), "fnd-1"); err == nil {
		t.Error("get error: expected error")
	}
}

func TestReadService_GetPosition(t *testing.T) {
	repo := newRepo()
	repo.seed(findingWithPositions(t))
	rs := app.NewReadService(repo, fakeProjection{}, nil, 0)
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
	if _, _, err := app.NewReadService(ge, fakeProjection{}, nil, 0).GetPosition(ctx, "fnd-1", 0); err == nil {
		t.Error("get error: expected error")
	}
}

// TestReleasePosture_QueueDerivesFromOpenCarriers is the EDR-VERDICT-01 D7 rule on the shape
// the arc was measured on (CVE-2025-47273 / MRF): one cleared carrier beside one open carrier
// keeps FULL urgency — a live occurrence is never discounted by its cleared neighbours — and
// only a Finding whose every carrier is cleared reads 0 and leaves the ranked queue. The
// binding validation criterion is "the finding must NOT disappear", and this test is its
// unit-level half.
func TestReleasePosture_QueueDerivesFromOpenCarriers(t *testing.T) {
	ctx := context.Background()
	cleared := domain.MatchedComponent{PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools",
		ClaimClass: "carrier", VerdictState: "cleared_vendor_fix", VerdictGrade: "observed"}
	open := domain.MatchedComponent{PURL: "pkg:pypi/setuptools@70.3.0", Name: "setuptools",
		ClaimClass: "carrier"} // no verdict recorded → open, the fail-safe direction
	scope := domain.MatchedComponent{PURL: "pkg:rpm/rhel/python3-ply@3.9-9.el8", Name: "python3-ply",
		ClaimClass: "scope"}

	proj := fakeProjection{posture: []app.PostureEntry{
		{FindingID: "fnd-mixed", BaseScore: 71, Components: []domain.MatchedComponent{cleared, open, scope}},
		{FindingID: "fnd-all-cleared", BaseScore: 71, Components: []domain.MatchedComponent{cleared, scope}},
		{FindingID: "fnd-no-components", BaseScore: 71},
	}}
	got, err := app.NewReadService(newRepo(), proj, nil, 0).ReleasePosture(ctx, "rel-1")
	if err != nil || len(got) != 3 {
		t.Fatalf("posture = %+v err=%v", got, err)
	}

	// One live carrier among cleared neighbours → FULL urgency, no proportional discount.
	if got[0].OpenCarriers != 1 || got[0].EffectivePriority != 71 || got[0].ResidualPriority != 71 {
		t.Errorf("mixed: open=%d eff=%d res=%d, want 1 / 71 / 71 — a live occurrence is never diluted",
			got[0].OpenCarriers, got[0].EffectivePriority, got[0].ResidualPriority)
	}
	// Every carrier cleared (the scope row neither holds nor releases) → 0, off the ranked queue.
	if got[1].OpenCarriers != 0 || got[1].EffectivePriority != 0 || got[1].ResidualPriority != 0 {
		t.Errorf("all-cleared: open=%d eff=%d res=%d, want 0 / 0 / 0 — nothing real remains open",
			got[1].OpenCarriers, got[1].EffectivePriority, got[1].ResidualPriority)
	}
	// No component rows on record (older data) → priorities untouched: missing evidence never clears.
	if got[2].OpenCarriers != 0 || got[2].EffectivePriority != 71 {
		t.Errorf("no-components: open=%d eff=%d, want 0 / 71 — absence of rows must not read as cleared",
			got[2].OpenCarriers, got[2].EffectivePriority)
	}
}

// MirrorComponentVerdict is pure mirroring (EDR-VERDICT-01 D5): the repo write happens, the
// Position is never touched.
func TestMirrorComponentVerdict(t *testing.T) {
	repo := newRepo()
	svc := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	comp := domain.MatchedComponent{PURL: "pkg:pypi/setuptools@39.2.0",
		VerdictState: "cleared_vendor_fix", VerdictGrade: "inferred",
		VerdictReason: "matched to vendor package python-setuptools at the distro version"}
	if err := svc.MirrorComponentVerdict(context.Background(), "rel-1", "fl-1", comp); err != nil {
		t.Fatalf("mirror: %v", err)
	}
	if repo.lastVerdict.PURL != comp.PURL || repo.lastVerdict.VerdictState != "cleared_vendor_fix" {
		t.Errorf("repo received %+v, want the mirrored verdict", repo.lastVerdict)
	}
}

type fakeBlast struct {
	customers int
	err       error
}

func (b fakeBlast) BlastRadius(context.Context, string) (int, error) { return b.customers, b.err }

func TestReadService_BlastMultiplier(t *testing.T) {
	ctx := context.Background()
	proj := fakeProjection{posture: []app.PostureEntry{{FindingID: "fnd-1", BaseScore: 50}}}

	// 5 unique customers → 1.4× → effective priority 70.
	got, err := app.NewReadService(newRepo(), proj, fakeBlast{customers: 5}, 0).ReleasePosture(ctx, "rel-1")
	if err != nil || len(got) != 1 {
		t.Fatalf("posture = %+v err=%v", got, err)
	}
	if got[0].Multiplier != 1.4 || got[0].EffectivePriority != 70 {
		t.Errorf("mult=%v eff=%d, want 1.4 / 70", got[0].Multiplier, got[0].EffectivePriority)
	}

	// Fail-safe: a blast-read error ⇒ 1.0× (effective == base), and the read still succeeds.
	g2, err := app.NewReadService(newRepo(), proj, fakeBlast{err: errors.New("registry down")}, 0).ReleasePosture(ctx, "rel-1")
	if err != nil || len(g2) != 1 || g2[0].Multiplier != 1.0 || g2[0].EffectivePriority != 50 {
		t.Errorf("fail-safe = %+v err=%v, want mult 1.0 / eff 50", g2, err)
	}

	// Nil reader ⇒ 1.0× as well.
	g3, _ := app.NewReadService(newRepo(), proj, nil, 0).ReleasePosture(ctx, "rel-1")
	if g3[0].Multiplier != 1.0 || g3[0].EffectivePriority != 50 {
		t.Errorf("nil reader = %+v, want mult 1.0 / eff 50", g3)
	}

	// A configured cap (< default) saturates sooner: cap=3 with 5 customers ⇒ 2.0× ⇒ effective 100.
	// (Also exercises the non-normalized NewReadService path where the caller supplies cap ≥ 2.)
	g4, _ := app.NewReadService(newRepo(), proj, fakeBlast{customers: 5}, 3).ReleasePosture(ctx, "rel-1")
	if g4[0].Multiplier != 2.0 || g4[0].EffectivePriority != 100 {
		t.Errorf("cap=3 = %+v, want mult 2.0 / eff 100", g4)
	}
}

func TestReadService_Projections(t *testing.T) {
	proj := fakeProjection{
		posture: []app.PostureEntry{{FindingID: "fnd-1", Stage: domain.StagePositionEstablished, Stance: domain.StanceAffected, HasPosition: true}},
		blast:   []string{"rel-1", "rel-2"},
	}
	rs := app.NewReadService(newRepo(), proj, nil, 0)
	ctx := context.Background()

	if got, err := rs.ReleasePosture(ctx, "rel-1"); err != nil || len(got) != 1 || got[0].FindingID != "fnd-1" {
		t.Errorf("posture = %+v err=%v", got, err)
	}
	if got, err := rs.FaultlineBlastRadius(ctx, "fl-1"); err != nil || len(got) != 2 {
		t.Errorf("blast = %+v err=%v", got, err)
	}

	// Errors propagate.
	bad := app.NewReadService(newRepo(), fakeProjection{err: errors.New("proj down")}, nil, 0)
	if _, err := bad.ReleasePosture(ctx, "rel-1"); err == nil {
		t.Error("posture error: expected error")
	}
	if _, err := bad.FaultlineBlastRadius(ctx, "fl-1"); err == nil {
		t.Error("blast error: expected error")
	}
}

// The release posture carries BOTH priority numbers (EDR-GOVERNANCE-01 D14): the intrinsic
// effective_priority, unchanged by any decision, and the disposition-aware residual_priority a
// human sorts the triage queue by. This is the defect the VM run surfaced — an accepted
// not_affected Finding still reported its full priority, so suppressed and unaddressed Findings
// sorted identically.
func TestReadService_ResidualPriorityReflectsTheGovernedStance(t *testing.T) {
	ctx := context.Background()
	proj := fakeProjection{posture: []app.PostureEntry{
		{FindingID: "open", BaseScore: 70, Stance: domain.StanceAffected},
		{FindingID: "suppressed", BaseScore: 70, Stance: domain.StanceNotAffected},
		{FindingID: "accepted", BaseScore: 70, Stance: domain.StanceAcceptedRisk},
		{FindingID: "mitigated", BaseScore: 70, Stance: domain.StanceMitigated},
		{FindingID: "deferred", BaseScore: 70, Stance: domain.StanceDeferred},
		{FindingID: "undecided", BaseScore: 70},
	}}
	got, err := app.NewReadService(newRepo(), proj, nil, 0).ReleasePosture(ctx, "rel-1")
	if err != nil {
		t.Fatalf("ReleasePosture: %v", err)
	}
	want := map[domain.FindingID]int{
		"open": 70, "suppressed": 0, "accepted": 0, "mitigated": 35, "deferred": 63, "undecided": 70,
	}
	for _, e := range got {
		if e.ResidualPriority != want[e.FindingID] {
			t.Errorf("%s: residual = %d, want %d", e.FindingID, e.ResidualPriority, want[e.FindingID])
		}
		// Whatever the disposition, the intrinsic number is untouched — that is what makes a
		// suppression reversible when D14's watcher re-surfaces it.
		if e.EffectivePriority != 70 {
			t.Errorf("%s: effective = %d, want 70 — a decision must not erase intrinsic severity", e.FindingID, e.EffectivePriority)
		}
	}
}

// The mitigated weight is the one operator-tunable input, and it must actually reach the
// projection rather than sit in config.
func TestReadService_WithMitigatedWeightOverridesTheDefault(t *testing.T) {
	ctx := context.Background()
	proj := fakeProjection{posture: []app.PostureEntry{{FindingID: "m", BaseScore: 80, Stance: domain.StanceMitigated}}}

	def, _ := app.NewReadService(newRepo(), proj, nil, 0).ReleasePosture(ctx, "rel-1")
	if def[0].ResidualPriority != 40 {
		t.Fatalf("default residual = %d, want 40 (80 x 0.5)", def[0].ResidualPriority)
	}
	over, _ := app.NewReadService(newRepo(), proj, nil, 0).WithMitigatedWeight(0.25).ReleasePosture(ctx, "rel-1")
	if over[0].ResidualPriority != 20 {
		t.Fatalf("overridden residual = %d, want 20 (80 x 0.25)", over[0].ResidualPriority)
	}
}
