package app_test

import (
	"context"
	"errors"
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

// TRUST-4 wire-compatibility guard. A superseded event predating the Trust field decodes to an
// empty class, and evidenceTrustFor falls back to the Observed this code used to state
// unconditionally. Without that fallback an empty class reads as Inferred under MaxTrust and
// this long-standing auto-accept silently stops working — a vulnerability withdrawn upstream
// would start piling up in human review queues.
func TestReactToEnrichment_WithdrawnPathStillAutoAccepts(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo, domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected))

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Withdrawn: true, // no WithdrawnTrust — the pre-TRUST-4 wire shape
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	f := repo.byID["fnd-1"]
	if _, ok := f.CurrentPosition(); !ok {
		t.Fatal("a withdrawn CVE must still auto-accept — its evidence is a public record (Observed)")
	}
}

// TRUST-4, the point of the change: the withdrawal's class is now SOURCED, so a withdrawal
// reported by an Asserted source no longer clears the shipped rule's Observed floor (D15).
//
// Before this, Governance stated Observed for every withdrawal regardless of who reported it.
// That was right for NVD and wrong in general — it would have auto-suppressed a Finding on a
// vendor's unverifiable word, which is exactly what "Gathering Is Not Knowing" forbids.
func TestReactToEnrichment_WithdrawalFromAnAssertedSourceIsNotAutoAccepted(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	rule := domain.NewPolicyRule("auto-not-affected-observed", domain.StanceNotAffected).
		RequiringEvidence(value.TrustObserved)
	s := writeSvc(repo, rule)

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Withdrawn: true, WithdrawnTrust: value.TrustAsserted,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	f := repo.byID["fnd-1"]
	if _, ok := f.CurrentPosition(); ok {
		t.Fatal("an Asserted withdrawal must not clear the Observed floor — it waits for a human")
	}
	if len(f.Proposals()) == 0 {
		t.Fatal("the proposal must still be RAISED — barring auto-accept is not dropping the signal")
	}
}

// The same path with the class the real producer sends (NVD is Observed) does auto-accept, so
// the floor discriminates on provenance rather than simply blocking withdrawals.
func TestReactToEnrichment_WithdrawalFromAnObservedSourceIsAutoAccepted(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	rule := domain.NewPolicyRule("auto-not-affected-observed", domain.StanceNotAffected).
		RequiringEvidence(value.TrustObserved)
	s := writeSvc(repo, rule)

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Withdrawn: true, WithdrawnTrust: value.TrustObserved,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if _, ok := repo.byID["fnd-1"].CurrentPosition(); !ok {
		t.Fatal("an Observed withdrawal must auto-accept")
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

// The deterministic version-range verdict on an EXISTING Finding — the case correlation's
// own gate cannot reach, because that gate runs only at match time. A Finding born before
// the range was known is revisited here.
func TestReactToEnrichment_VersionRangeRaisesSystemNotAffected(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/foo@5.0", Name: "foo", Version: "5.0", Ecosystem: "pypi",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	s := writeSvc(repo, domain.NewPolicyRule("auto-not-affected", domain.StanceNotAffected))

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}

	got := repo.byID["fnd-1"]
	if len(got.Proposals()) != 1 || got.Proposals()[0].Stance() != domain.StanceNotAffected {
		t.Fatalf("proposals = %+v, want one system not_affected", got.Proposals())
	}
	if k := got.Proposals()[0].Proposer().Kind; k != domain.ActorSystem {
		t.Errorf("proposer kind = %q, want %q", k, domain.ActorSystem)
	}
	// Observed evidence clears the constitutional stage, so policy may auto-accept — a
	// provable verdict should not queue for a human.
	if _, ok := got.CurrentPosition(); !ok {
		t.Error("a provable, Observed verdict should be policy-auto-acceptable")
	}
}

// The D13 repair, asserted directly. writeSvc wires NO advisor, so AI is disabled — and the
// deterministic verdict is still produced. Before this group the version-range rule lived
// only in the AI runtime, so switching AI off silently lost a verdict Themis could compute
// from arithmetic.
func TestReactToEnrichment_VersionRangeVerdictProducedWithAIDisabled(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/foo@5.0", Name: "foo", Version: "5.0", Ecosystem: "pypi",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	s := writeSvc(repo) // no policies, and critically no advisor — AI is off

	// Sanity: with AI off the on-demand AI seam produces nothing at all.
	if _, produced, _, err := s.RecommendPosition(context.Background(), "fnd-1"); err != nil || produced {
		t.Fatalf("precondition: AI must be disabled, got produced=%v err=%v", produced, err)
	}
	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if len(repo.byID["fnd-1"].Proposals()) != 1 {
		t.Fatal("the deterministic verdict must be produced with AI switched off (D13)")
	}
}

// An in-range component must produce nothing: the rule proves absence only, never presence.
func TestReactToEnrichment_VersionRangeDefersWhenInRange(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/foo@2.0", Name: "foo", Version: "2.0", Ecosystem: "pypi",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	s := writeSvc(repo)

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if n := len(repo.byID["fnd-1"].Proposals()); n != 0 {
		t.Errorf("proposals = %d, want 0 — an in-range component is never a verdict", n)
	}
}

// Re-delivery is idempotent: the proposal id derives from the Finding, so a repeated
// enrichment raises nothing new.
func TestReactToEnrichment_VersionRangeIsIdempotent(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/foo@5.0", Name: "foo", Version: "5.0", Ecosystem: "pypi",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	s := writeSvc(repo)
	sig := app.EnrichmentSignal{FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved}

	for i := 0; i < 2; i++ {
		if err := s.ReactToEnrichment(context.Background(), sig); err != nil {
			t.Fatalf("react %d: %v", i, err)
		}
	}
	if n := len(repo.byID["fnd-1"].Proposals()); n != 1 {
		t.Errorf("proposals after re-delivery = %d, want 1", n)
	}
}

// Error paths: a store failure must surface, not be swallowed into a silently missing
// verdict. A dropped not_affected leaves a release looking vulnerable when it is not;
// a dropped error makes that indistinguishable from "the rule declined".
func TestReactToVersionRange_ErrorsPropagate(t *testing.T) {
	sig := app.EnrichmentSignal{
		FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved,
	}

	t.Run("findings lookup fails", func(t *testing.T) {
		repo := newRepo()
		repo.byFaultlineErr = errors.New("db down")
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), sig); err == nil {
			t.Error("expected the lookup error to propagate")
		}
	})

	t.Run("save fails", func(t *testing.T) {
		repo := newRepo()
		f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
		if _, err := f.AbsorbComponent(domain.MatchedComponent{
			PURL: "pkg:pypi/foo@5.0", Name: "foo", Version: "5.0", Ecosystem: "pypi",
		}); err != nil {
			t.Fatalf("absorb: %v", err)
		}
		repo.seed(f)
		repo.saveErr = errors.New("db down")
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), sig); err == nil {
			t.Error("expected the save error to propagate")
		}
	})
}

// A proposal-build failure in the version-range path (here a zero clock) propagates rather
// than silently dropping the verdict — mirroring the applicability path's guard.
func TestReactToVersionRange_ProposalBuildFailurePropagates(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/foo@5.0", Name: "foo", Version: "5.0", Ecosystem: "pypi",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	badClock := app.NewFindingService(repo, &seqIDs{}, zeroClock{})

	if err := badClock.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved,
	}); err == nil {
		t.Error("zero-clock proposal build in the version-range path must error")
	}
}

// --- FindingAssessment Domain Projection (EDR-TRUST-01 T10) ---------------------------

type stubKnowledge struct {
	k   app.FaultlineKnowledge
	err error
}

func (s stubKnowledge) GetFaultline(context.Context, string) (app.FaultlineKnowledge, error) {
	return s.k, s.err
}

func TestGetFindingAssessment(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	known := app.FaultlineKnowledge{FaultlineID: "fl-1", CVE: "CVE-2024-1", Severity: "high", KEV: true}

	t.Run("composes the finding with what Knowledge knows", func(t *testing.T) {
		read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(stubKnowledge{k: known})
		got, err := read.GetFindingAssessment(context.Background(), "fnd-1")
		if err != nil {
			t.Fatalf("assessment: %v", err)
		}
		if got.Finding.ID() != "fnd-1" || got.Knowledge.Severity != "high" || !got.Knowledge.KEV {
			t.Errorf("assessment = %+v", got)
		}
	})

	// Best-effort by design: an unreachable Knowledge degrades the VIEW, never the request.
	// Failing outright would make a Knowledge outage look like a missing Finding.
	t.Run("degrades to the finding alone when Knowledge is down", func(t *testing.T) {
		read := app.NewReadService(repo, fakeProjection{}, nil, 0).
			WithKnowledge(stubKnowledge{err: errors.New("knowledge down")})
		got, err := read.GetFindingAssessment(context.Background(), "fnd-1")
		if err != nil {
			t.Fatalf("a Knowledge outage must not fail the projection: %v", err)
		}
		if got.Finding.ID() != "fnd-1" {
			t.Errorf("finding half lost: %+v", got.Finding)
		}
		if got.Knowledge.FaultlineID != "" {
			t.Errorf("knowledge half = %+v, want empty so a consumer can tell", got.Knowledge)
		}
	})

	t.Run("no Knowledge seam wired", func(t *testing.T) {
		read := app.NewReadService(repo, fakeProjection{}, nil, 0)
		got, err := read.GetFindingAssessment(context.Background(), "fnd-1")
		if err != nil || got.Finding.ID() != "fnd-1" {
			t.Errorf("assessment = %+v err=%v", got, err)
		}
	})

	t.Run("an unknown finding is an error", func(t *testing.T) {
		read := app.NewReadService(newRepo(), fakeProjection{}, nil, 0)
		if _, err := read.GetFindingAssessment(context.Background(), "nope"); err == nil {
			t.Error("expected an error for an unknown Finding")
		}
	})
}

// --- Business Verification (EDR-TRUST-01 T8) --------------------------------------------

type stubAdvisor struct {
	rec      app.Recommendation
	produced bool
}

func (s stubAdvisor) RecommendPosition(context.Context, string) (app.Recommendation, bool, string, error) {
	return s.rec, s.produced, "", nil
}

// Governance validates the returned claim against ITS OWN truth before recording anything.
// The runtime's Grounding Verification proved the model reasoned only from the context it was
// handed — but that context was supplied to it. Only the context owner can confirm the claim
// is consistent with the system of record, which is what makes a stale or forged projection
// USELESS rather than merely unlikely to be accepted.
func TestRecommendPosition_BusinessVerification(t *testing.T) {
	newSvc := func(t *testing.T, evidence []string) (*app.FindingService, *fakeRepo) {
		t.Helper()
		repo := newRepo()
		f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
		if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:golang/x@1.0.0"}); err != nil {
			t.Fatalf("absorb: %v", err)
		}
		repo.seed(f)
		return writeSvc(repo).WithAdvisor(stubAdvisor{produced: true, rec: app.Recommendation{
			Stance: string(domain.StanceNotAffected), Capability: "recommend_position@v1",
			Reasoning: "why", Evidence: evidence,
		}}), repo
	}

	t.Run("a claim consistent with our truth is recorded", func(t *testing.T) {
		// Every reference resolves against the Finding Governance actually holds.
		s, repo := newSvc(t, []string{"fnd-1", "fl-1", "CVE-2024-1", "pkg:golang/x@1.0.0"})
		pid, produced, _, err := s.RecommendPosition(context.Background(), "fnd-1")
		if err != nil || !produced || pid == "" {
			t.Fatalf("pid=%q produced=%v err=%v", pid, produced, err)
		}
		if n := len(repo.byID["fnd-1"].Proposals()); n != 1 {
			t.Errorf("proposals = %d, want 1", n)
		}
	})

	t.Run("a claim citing evidence we cannot vouch for is refused", func(t *testing.T) {
		// The forged/stale-projection case: the reasoning is internally consistent, the
		// runtime's own grounding check passed, and Governance still refuses — because this
		// component is not on this Finding.
		s, repo := newSvc(t, []string{"pkg:golang/never-shipped@9.9"})
		pid, produced, _, err := s.RecommendPosition(context.Background(), "fnd-1")
		if err != nil {
			t.Fatalf("a failed check is a silent no-proposal, never an error: %v", err)
		}
		if produced || pid != "" {
			t.Errorf("produced=%v pid=%q — an unvouchable claim must not be recorded", produced, pid)
		}
		if n := len(repo.byID["fnd-1"].Proposals()); n != 0 {
			t.Errorf("proposals = %d, want 0 — nothing may be recorded", n)
		}
	})

	t.Run("a claim citing another Finding is refused", func(t *testing.T) {
		s, _ := newSvc(t, []string{"fnd-999"})
		if _, produced, _, _ := s.RecommendPosition(context.Background(), "fnd-1"); produced {
			t.Error("evidence naming a different Finding must not vouch")
		}
	})
}

// --- AI-GROUND-1: fix SELECTION on the projection (EDR-TRUST-01 T9) --------------------

// withComponent seeds a Finding carrying one matched component, including its source package.
func findingWithComponent(t *testing.T, c domain.MatchedComponent) domain.Finding {
	t.Helper()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2007-4559")
	if _, err := f.AbsorbComponent(c); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	return f
}

// The exact failure measured on the VM 2026-08-07: a card holding 94 fix versions across every
// package CVE-2007-4559 touches was handed WHOLE to the model, which then reasoned that
// python3-ply 3.9-9.el8 was affected because it sorted below 0:0.1.7-16 — a version belonging to
// another package — and returned that at confidence 0.99.
//
// The projection must hand over only python-ply's fix. The rpm component resolves through its
// SOURCE name, which is the only key that joins python3-ply to python-ply.
func TestGetFindingAssessment_SelectsOnlyThisComponentsFixes(t *testing.T) {
	repo := newRepo()
	repo.seed(findingWithComponent(t, domain.MatchedComponent{
		PURL: "pkg:rpm/rocky/python3-ply@3.9-9.el8", Name: "python3-ply",
		Version: "3.9-9.el8", Ecosystem: "rpm", Source: "python-ply",
	}))
	known := app.FaultlineKnowledge{
		FaultlineID: "fl-1", CVE: "CVE-2007-4559",
		FixedVersions: []string{"0:0.1.7-16.module+el8.9.0", "0:3.11-10.module+el8.9.0", "0:5.4.1-1"},
		Fixes: []app.FixedVersion{
			{Package: "Cython", Version: "0:0.1.7-16.module+el8.9.0"},
			{Package: "python-ply", Version: "0:3.11-10.module+el8.9.0"},
			{Package: "PyYAML", Version: "0:5.4.1-1"},
		},
	}
	read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(stubKnowledge{k: known})
	got, err := read.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if len(got.Knowledge.FixedVersions) != 1 || got.Knowledge.FixedVersions[0] != "0:3.11-10.module+el8.9.0" {
		t.Errorf("fixed_versions = %v, want only python-ply's — another package's version is what produced a confidently wrong recommendation", got.Knowledge.FixedVersions)
	}
	if got.Knowledge.UnattributedFixes != 2 {
		t.Errorf("unattributed = %d, want 2 (Cython + PyYAML)", got.Knowledge.UnattributedFixes)
	}
}

// Maven publishes as groupId:artifactId while the PURL splits them with a slash, so the
// namespace key is what joins pkg:maven/org.eclipse.jetty/jetty-http to its published fix.
func TestGetFindingAssessment_MatchesMavenByNamespace(t *testing.T) {
	repo := newRepo()
	repo.seed(findingWithComponent(t, domain.MatchedComponent{
		PURL: "pkg:maven/org.eclipse.jetty/jetty-http@12.0.27", Name: "jetty-http",
		Version: "12.0.27", Ecosystem: "maven",
	}))
	known := app.FaultlineKnowledge{
		FaultlineID: "fl-1", CVE: "CVE-2007-4559",
		Fixes: []app.FixedVersion{
			{Package: "org.eclipse.jetty:jetty-http", Version: "12.0.28"},
			{Package: "org.apache.logging.log4j:log4j-core", Version: "2.17.1"},
		},
	}
	read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(stubKnowledge{k: known})
	got, _ := read.GetFindingAssessment(context.Background(), "fnd-1")
	if len(got.Knowledge.FixedVersions) != 1 || got.Knowledge.FixedVersions[0] != "12.0.28" {
		t.Errorf("fixed_versions = %v, want jetty's 12.0.28", got.Knowledge.FixedVersions)
	}
}

// The honest-absence contract. When no fix can be attributed to this component the list is
// EMPTY and the count is reported — never the union. An empty list plus "94 unattributable"
// leads a consumer to `insufficient`; the union leads it to a confident wrong answer.
func TestGetFindingAssessment_ReportsRatherThanGuessesWhenNothingMatches(t *testing.T) {
	repo := newRepo()
	repo.seed(findingWithComponent(t, domain.MatchedComponent{
		PURL: "pkg:rpm/rocky/somepkg@1.0", Name: "somepkg", Version: "1.0", Ecosystem: "rpm",
	}))

	t.Run("attributed fixes exist but none is ours", func(t *testing.T) {
		known := app.FaultlineKnowledge{FaultlineID: "fl-1", CVE: "CVE-2007-4559",
			FixedVersions: []string{"1.2.3", "4.5.6"},
			Fixes:         []app.FixedVersion{{Package: "other", Version: "1.2.3"}, {Package: "another", Version: "4.5.6"}}}
		read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(stubKnowledge{k: known})
		got, _ := read.GetFindingAssessment(context.Background(), "fnd-1")
		if len(got.Knowledge.FixedVersions) != 0 {
			t.Errorf("fixed_versions = %v, want empty — passing another package's fix is the defect", got.Knowledge.FixedVersions)
		}
		if got.Knowledge.UnattributedFixes != 2 {
			t.Errorf("unattributed = %d, want 2 so a consumer can tell this from 'no fix published'", got.Knowledge.UnattributedFixes)
		}
	})

	// A pre-KN-FIX-1 card, or one enriched only by sources that cannot attribute (NVD keys on
	// CPE, scanners report bare versions). The union must still not be passed on.
	t.Run("card carries no attribution at all", func(t *testing.T) {
		known := app.FaultlineKnowledge{FaultlineID: "fl-1", CVE: "CVE-2007-4559",
			FixedVersions: []string{"1.2.3", "4.5.6", "7.8.9"}}
		read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(stubKnowledge{k: known})
		got, _ := read.GetFindingAssessment(context.Background(), "fnd-1")
		if len(got.Knowledge.FixedVersions) != 0 {
			t.Errorf("fixed_versions = %v, want empty", got.Knowledge.FixedVersions)
		}
		if got.Knowledge.UnattributedFixes != 3 {
			t.Errorf("unattributed = %d, want 3", got.Knowledge.UnattributedFixes)
		}
	})
}
