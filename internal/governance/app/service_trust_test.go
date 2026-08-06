package app_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// End-to-end through the service: a policy that would accept the stance cannot reach it,
// because the constitutional stage (T6) runs first. The proposal is still RAISED — the bar
// blocks automatic acceptance, not the proposal — so a human can still decide it.
func TestReactToEnrichment_InferredEvidenceIsNotAutoAccepted(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo, domain.NewPolicyRule("auto-affected", domain.StanceAffected))

	err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", KEV: true, SignalTrust: value.TrustInferred,
	})
	if err != nil {
		t.Fatalf("react: %v", err)
	}

	if got, want := noteTypes(repo.lastNotes), []string{app.EventProposalRaised}; !eq(got, want) {
		t.Errorf("notes = %v, want %v — raised but never accepted", got, want)
	}
	f := repo.byID["fnd-1"]
	if _, ok := f.CurrentPosition(); ok {
		t.Error("no Position may be established from Inferred evidence without a human")
	}
	if len(f.Proposals()) != 1 || !f.Proposals()[0].IsOpen() {
		t.Errorf("expected exactly one OPEN proposal awaiting a human, got %+v", f.Proposals())
	}
}

// The control: identical path, Observed evidence, and the same policy now accepts. Without
// this, the test above would pass even if the whole enrichment path were broken.
func TestReactToEnrichment_ObservedEvidenceStillAutoAccepts(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo, domain.NewPolicyRule("auto-affected", domain.StanceAffected))

	err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", KEV: true, SignalTrust: value.TrustObserved,
	})
	if err != nil {
		t.Fatalf("react: %v", err)
	}

	want := []string{app.EventProposalRaised, app.EventProposalAccepted, app.EventPositionEstablished}
	if got := noteTypes(repo.lastNotes); !eq(got, want) {
		t.Errorf("notes = %v, want %v", got, want)
	}
}

// TRUST-4 regression guard. knowledge.faultline_superseded.v1 carries no trust class, so
// the withdrawal path states Observed explicitly in evidenceTrustFor. Left unset it would
// read as Inferred, and this long-standing policy auto-accept would silently stop working —
// a vulnerability withdrawn upstream would start piling up in human review queues.
func TestReactToEnrichment_WithdrawnPathStillAutoAccepts(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo, domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected))

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Withdrawn: true,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	f := repo.byID["fnd-1"]
	if _, ok := f.CurrentPosition(); !ok {
		t.Fatal("a withdrawn CVE must still auto-accept — its evidence is a public record (Observed)")
	}
}

// A vendor VEX suppression rests on an Asserted statement, which is eligible for policy —
// the enterprise may choose to rely on its vendors. It is only Inferred that is barred.
func TestReactToApplicability_AssertedVendorStatementRemainsPolicyEligible(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:rpm/openssl@1.0.2", Name: "openssl"}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	s := writeSvc(repo, domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected))

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID:     "fl-1",
		Applicabilities: []app.Applicability{{Package: "openssl", Status: "not_affected", Justification: "vulnerable_code_not_present"}},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	got := repo.byID["fnd-1"]
	if _, ok := got.CurrentPosition(); !ok {
		t.Error("an Asserted vendor statement should remain eligible for policy auto-accept")
	}
}

// Covers the remaining evidenceTrustFor branches. KEV and high severity rest on different
// field-groups (signals vs headline), so a proposal driven by both inherits the weaker of
// the two — a conclusion is never better than its weakest input (T3).
func TestReactToEnrichment_EvidenceTrustFoldsOnlyContributingGroups(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sig        app.EnrichmentSignal
		autoAccept bool
	}{
		{
			name: "kev and high severity fold to the weaker group",
			sig: app.EnrichmentSignal{
				FaultlineID: "fl-1", KEV: true, HighSeverity: true,
				SignalTrust: value.TrustObserved, HeadlineTrust: value.TrustInferred,
			},
			autoAccept: false,
		},
		{
			name: "high severity alone rests on the headline only",
			sig: app.EnrichmentSignal{
				FaultlineID: "fl-1", HighSeverity: true,
				HeadlineTrust: value.TrustObserved,
				// An unset SignalTrust must NOT poison this: no exploit signal drove the
				// stance, so folding that group in would wrongly bar a well-evidenced proposal.
			},
			autoAccept: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo()
			repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
			s := writeSvc(repo, domain.NewPolicyRule("auto-affected", domain.StanceAffected))

			if err := s.ReactToEnrichment(context.Background(), tc.sig); err != nil {
				t.Fatalf("react: %v", err)
			}
			_, established := repo.byID["fnd-1"].CurrentPosition()
			if established != tc.autoAccept {
				t.Errorf("auto-accepted = %v, want %v", established, tc.autoAccept)
			}
		})
	}
}
