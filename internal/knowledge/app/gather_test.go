package app_test

// The on-demand gather (G-AI-1's explicit half): one CVE, every wired source, ordinary
// Proposals. Same fold path as the sweeps — these tests mirror backfill_test's harness.

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
)

type gatherSrc struct {
	facts app.CVEFacts
	err   error
	calls int
}

func (g *gatherSrc) VulnsForCVE(context.Context, value.CVEID) (app.CVEFacts, error) {
	g.calls++
	return g.facts, g.err
}

func TestGatherCVE_FoldsWhatSourcesReturn(t *testing.T) {
	repo := newRepo()
	found := &gatherSrc{facts: app.CVEFacts{Proposal: proposalFor(t, "CVE-2026-0001", "nvd"), Found: true}}
	empty := &gatherSrc{} // a source with nothing is an honest answer, not a failure
	s := app.NewGatherService(foldSvc(repo),
		app.GatherSource{Name: "nvd", Src: found},
		app.GatherSource{Name: "quiet", Src: empty})

	res, err := s.GatherCVE(context.Background(), "CVE-2026-0001")
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if res.CVE != "CVE-2026-0001" || res.FaultlineID == "" {
		t.Fatalf("result = %+v, want a card created", res)
	}
	if len(res.Sources) != 2 || !res.Sources[0].Found || !res.Sources[0].Recorded || res.Sources[1].Found {
		t.Errorf("sources = %+v", res.Sources)
	}

	// A second gather of the same facts is a restatement: found, not recorded.
	res2, err := s.GatherCVE(context.Background(), "CVE-2026-0001")
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Sources[0].Found || res2.Sources[0].Recorded {
		t.Errorf("restatement = %+v, want found but not recorded", res2.Sources[0])
	}
}

func TestGatherCVE_WithdrawnRetiresAndSourceErrorsAreReported(t *testing.T) {
	repo := newRepo()
	dead := &gatherSrc{err: errors.New("nvd down")}
	withdrawn := &gatherSrc{facts: app.CVEFacts{Withdrawn: true}}
	s := app.NewGatherService(foldSvc(repo),
		app.GatherSource{Name: "dead", Src: dead},
		app.GatherSource{Name: "nvd", Src: withdrawn})

	res, err := s.GatherCVE(context.Background(), "CVE-2026-0002")
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	if res.Sources[0].Err == "" || res.Sources[0].Found {
		t.Errorf("dead source = %+v, want reported error", res.Sources[0])
	}
	if !res.Sources[1].Withdrawn {
		t.Errorf("withdrawn source = %+v", res.Sources[1])
	}
}

func TestGatherCVE_InvalidAndEnabled(t *testing.T) {
	s := app.NewGatherService(foldSvc(newRepo()), app.GatherSource{Name: "nvd", Src: &gatherSrc{}})
	if _, err := s.GatherCVE(context.Background(), "not-a-cve"); !errors.Is(err, app.ErrInvalidCVE) {
		t.Errorf("invalid cve err = %v", err)
	}
	if !s.Enabled() {
		t.Error("a service with a source must be enabled")
	}
	if app.NewGatherService(nil).Enabled() {
		t.Error("no sources must read disabled")
	}
	var nilSvc *app.GatherService
	if nilSvc.Enabled() {
		t.Error("nil service must read disabled")
	}
}

// A store failure is fatal — the gather must not claim to have recorded what it could not.
func TestGatherCVE_StoreFailuresAreFatal(t *testing.T) {
	broken := newRepo()
	broken.saveErr = errors.New("db down")
	s := app.NewGatherService(foldSvc(broken),
		app.GatherSource{Name: "nvd", Src: &gatherSrc{facts: app.CVEFacts{Proposal: proposalFor(t, "CVE-2026-0003", "nvd"), Found: true}}})
	if _, err := s.GatherCVE(context.Background(), "CVE-2026-0003"); err == nil {
		t.Error("fold store failure must be fatal")
	}

	// And the supersede path: withdrawn + a card present + failing save.
	seeded := newRepo()
	preSeed := app.NewGatherService(foldSvc(seeded),
		app.GatherSource{Name: "nvd", Src: &gatherSrc{facts: app.CVEFacts{Proposal: proposalFor(t, "CVE-2026-0004", "nvd"), Found: true}}})
	if _, err := preSeed.GatherCVE(context.Background(), "CVE-2026-0004"); err != nil {
		t.Fatal(err)
	}
	seeded.saveErr = errors.New("db down")
	s2 := app.NewGatherService(foldSvc(seeded),
		app.GatherSource{Name: "nvd", Src: &gatherSrc{facts: app.CVEFacts{Withdrawn: true}}})
	if _, err := s2.GatherCVE(context.Background(), "CVE-2026-0004"); err == nil {
		t.Error("supersede store failure must be fatal")
	}
}
