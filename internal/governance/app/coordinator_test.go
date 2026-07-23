package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

func TestCoordinator_OnComponentMatched(t *testing.T) {
	repo := newRepo()
	coord := app.NewCoordinator(writeSvc(repo))

	err := coord.OnComponentMatched(context.Background(), app.InboundComponentMatched{
		FaultlineID: "fl-1", CVE: "CVE-2024-1", ReleaseID: "rel-1",
		Components: []domain.MatchedComponent{comp("pkg:a")},
	})
	if err != nil {
		t.Fatalf("on match: %v", err)
	}
	if len(repo.order) != 1 {
		t.Fatalf("expected one finding, got %d", len(repo.order))
	}
	f := repo.byID[repo.order[0]]
	if f.ReleaseID() != "rel-1" || f.FaultlineID() != "fl-1" || len(f.Components()) != 1 {
		t.Errorf("finding = %+v", f)
	}

	// Error propagates.
	bad := newRepo()
	bad.getByKeyErr = errors.New("db down")
	if err := app.NewCoordinator(writeSvc(bad)).OnComponentMatched(context.Background(), app.InboundComponentMatched{FaultlineID: "fl-1", ReleaseID: "rel-1"}); err == nil {
		t.Error("expected error")
	}
}

func TestCoordinator_OnFaultlineEnriched(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	coord := app.NewCoordinator(writeSvc(repo))
	ctx := context.Background()

	// High severity → a re-prioritize proposal is raised.
	if err := coord.OnFaultlineEnriched(ctx, app.InboundFaultlineEnriched{FaultlineID: "fl-1", Severity: "critical"}); err != nil {
		t.Fatal(err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventProposalRaised}) {
		t.Errorf("notes = %v, want [proposal_raised]", got)
	}

	// A low-severity, non-KEV enrichment has no decision impact → no write.
	repo2 := newRepo()
	repo2.seed(identified(t, "fnd-2", "rel-2", "fl-2", "CVE-2"))
	coord2 := app.NewCoordinator(writeSvc(repo2))
	if err := coord2.OnFaultlineEnriched(ctx, app.InboundFaultlineEnriched{FaultlineID: "fl-2", Severity: "low"}); err != nil {
		t.Fatal(err)
	}
	if repo2.saveCalls != 0 {
		t.Error("low-severity enrichment must not write")
	}

	// KEV alone (medium severity) still warrants a proposal.
	repo3 := newRepo()
	repo3.seed(identified(t, "fnd-3", "rel-3", "fl-3", "CVE-3"))
	coord3 := app.NewCoordinator(writeSvc(repo3))
	if err := coord3.OnFaultlineEnriched(ctx, app.InboundFaultlineEnriched{FaultlineID: "fl-3", Severity: "medium", KEV: true}); err != nil {
		t.Fatal(err)
	}
	if repo3.saveCalls != 1 {
		t.Errorf("KEV enrichment should raise a proposal (saves=%d)", repo3.saveCalls)
	}
}

func TestCoordinator_OnFaultlineSuperseded(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-1"))
	coord := app.NewCoordinator(writeSvc(repo))

	if err := coord.OnFaultlineSuperseded(context.Background(), app.InboundFaultlineSuperseded{FaultlineID: "fl-1", CVE: "CVE-1"}); err != nil {
		t.Fatal(err)
	}
	// Superseded → a system Not-Affected proposal (flagged for review; not auto-decided
	// without a policy).
	f := repo.byID["fnd-1"]
	if len(f.Proposals()) != 1 || f.Proposals()[0].Stance() != domain.StanceNotAffected {
		t.Errorf("proposals = %+v", f.Proposals())
	}
}
