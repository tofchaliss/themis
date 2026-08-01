package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// --- EDR-VEX-01 D4: vendor VEX suppression overlay -----------------------------------

// withComponent seeds an Identified Finding carrying one matched component (PURL + name), so a
// vendor VEX statement can be matched against it.
func withComponent(t *testing.T, id, rel, fl, cve, purl, name string) domain.Finding {
	t.Helper()
	f := identified(t, id, rel, fl, cve)
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: purl, Name: name}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	return f
}

func notAffected(pkg, justification string) app.Applicability {
	return app.Applicability{Package: pkg, Status: "not_affected", Justification: justification}
}

// A vendor not_affected statement covering a Finding's component raises a SYSTEM not_affected
// Proposal — flagged for review, never auto-decided (EDR-VEX-01 D4).
func TestReactToEnrichment_ApplicabilityRaisesSystemNotAffected(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	s := writeSvc(repo) // no policies → never auto-accept

	sig := app.EnrichmentSignal{
		FaultlineID:     "fl-1",
		Applicabilities: []app.Applicability{notAffected("pkg:rpm/openssl", "vulnerable_code_not_present")}, // PURL-prefix match
	}
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatalf("react: %v", err)
	}
	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventProposalRaised}) {
		t.Errorf("notes = %v, want [proposal_raised]", got)
	}
	f := repo.byID["fnd-1"]
	if f.Stage() != domain.StageUnderInvestigation {
		t.Errorf("stage = %q, want under_investigation (flagged for review)", f.Stage())
	}
	if _, ok := f.CurrentPosition(); ok {
		t.Error("vendor VEX must never auto-establish a Position")
	}
	p := f.Proposals()[0]
	if p.Stance() != domain.StanceNotAffected || p.Proposer().Kind != domain.ActorSystem {
		t.Errorf("proposal = %+v, want system not_affected", p)
	}
}

// With a Governance policy that auto-accepts not_affected, the suppression completes: the
// Finding's Position flips to not_affected — the EDR-VEX-01 payoff.
func TestReactToEnrichment_ApplicabilitySuppressesUnderPolicy(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	policy := domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected)
	s := writeSvc(repo, policy)

	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Applicabilities: []app.Applicability{notAffected("openssl", "")}} // bare-name match, empty justification
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatalf("react: %v", err)
	}
	want := []string{app.EventProposalRaised, app.EventProposalAccepted, app.EventPositionEstablished}
	if got := noteTypes(repo.lastNotes); !eq(got, want) {
		t.Errorf("notes = %v, want %v", got, want)
	}
	pos, ok := repo.byID["fnd-1"].CurrentPosition()
	if !ok || pos.Stance() != domain.StanceNotAffected {
		t.Errorf("position = %+v ok=%v, want not_affected", pos, ok)
	}
}

// A vendor statement that covers no component of the Finding raises nothing.
func TestReactToEnrichment_ApplicabilityNoMatchSkips(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	s := writeSvc(repo)

	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Applicabilities: []app.Applicability{notAffected("zlib", "")}}
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != 0 {
		t.Error("a non-covering vendor statement must not write")
	}
}

// Only not_affected statements suppress; affected and empty-package statements are ignored.
func TestReactToEnrichment_ApplicabilityIgnoresNonNotAffected(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	s := writeSvc(repo)

	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Applicabilities: []app.Applicability{
		{Package: "openssl", Status: "affected"},   // not a suppression
		{Package: "", Status: "not_affected"},       // empty package — filtered out
	}}
	if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != 0 {
		t.Error("affected / empty-package statements must not raise a proposal")
	}
}

// A re-delivery of the same vendor statement raises no duplicate and performs no write.
func TestReactToEnrichment_ApplicabilityIdempotent(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	s := writeSvc(repo)
	ctx := context.Background()
	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Applicabilities: []app.Applicability{notAffected("openssl", "just")}}

	if err := s.ReactToEnrichment(ctx, sig); err != nil {
		t.Fatal(err)
	}
	saves := repo.saveCalls
	if err := s.ReactToEnrichment(ctx, sig); err != nil {
		t.Fatal(err)
	}
	if repo.saveCalls != saves {
		t.Errorf("re-delivery wrote (%d → %d); want idempotent", saves, repo.saveCalls)
	}
	if n := len(repo.byID["fnd-1"].Proposals()); n != 1 {
		t.Errorf("proposals = %d, want 1", n)
	}
}

// The FindingsByFaultline error in the applicability path propagates — reached when a
// not_affected statement is present but no severity/withdrawn re-prioritization is.
func TestReactToEnrichment_ApplicabilityByFaultlineErrorPropagates(t *testing.T) {
	fe := newRepo()
	fe.byFaultlineErr = errors.New("db down")
	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Applicabilities: []app.Applicability{notAffected("openssl", "")}}
	if err := writeSvc(fe).ReactToEnrichment(context.Background(), sig); err == nil {
		t.Error("byFaultline error in the applicability path must propagate")
	}
}

// A proposal-build failure in the applicability path (here a zero clock) propagates.
func TestReactToEnrichment_ApplicabilityProposalBuildErrorPropagates(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	badClock := app.NewFindingService(repo, &seqIDs{}, zeroClock{})
	sig := app.EnrichmentSignal{FaultlineID: "fl-1", Applicabilities: []app.Applicability{notAffected("openssl", "")}}
	if err := badClock.ReactToEnrichment(context.Background(), sig); err == nil {
		t.Error("zero-clock proposal build in the applicability path must error")
	}
}
