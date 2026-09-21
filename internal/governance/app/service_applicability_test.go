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

// --- EDR-VEX-01 D4: vendor VEX suppression overlay -----------------------------------

// withComponent seeds an Identified Finding carrying one matched component (PURL + name), so a
// vendor VEX statement can be matched against it.
func withComponent(t *testing.T, id, rel, fl, cve, purl, name string) domain.Finding {
	t.Helper()
	f := identified(t, id, rel, fl, cve)
	// The version carries an `elN` marker so the release is PLACEABLE (EDR-VEX-02 D6): without
	// one, nothing on the Finding says which distro major it is, applicability is `unknown`, and
	// a vendor statement is correctly blocked. Every raise-path test below therefore needs it.
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: purl, Name: name, Version: "1.0.2k-16.el8_10",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	return f
}

// notAffected builds a statement scoped to the release the helpers above create (el8), so a test
// written about the RAISE path still exercises it. Use notAffectedScoped for the blocked paths.
func notAffected(pkg, justification string) app.Applicability {
	return notAffectedScoped(pkg, justification, value.FamilyEnterpriseLinux, "8")
}

func notAffectedScoped(pkg, justification, family, major string) app.Applicability {
	return app.Applicability{
		Package: pkg, Status: "not_affected", Justification: justification,
		Scope: value.ProductScope{Family: family, Major: major},
	}
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
		{Package: "openssl", Status: "affected"}, // not a suppression
		{Package: "", Status: "not_affected"},    // empty package — filtered out
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

// THE DECIDED MATRIX (EDR-VEX-02 validation order), at the Governance seam where it decides
// whether a Finding can be cleared. The release is placeable at el8 in every case; only the
// vendor's stated scope varies.
func TestReactToEnrichment_ApplicabilityMatrix(t *testing.T) {
	for _, tc := range []struct {
		name       string
		family     string
		major      string
		wantRaised bool
		why        string
	}{
		{"RHEL 8 — same family and major", value.FamilyEnterpriseLinux, "8", true,
			"the ~90 statements that genuinely apply to a Rocky 8.10 estate"},
		{"RHEL 7 — different major", value.FamilyEnterpriseLinux, "7", false,
			"THE measured defect: visible on the card, but cannot clear the Finding"},
		{"OpenShift Pipelines — different product", "openshift_pipelines", "1", false,
			"a KNOWN different product; note the major of 1 is never compared as an OS major"},
		{"unreadable scope — epistemic uncertainty", "", "", false,
			"blocked for the same fail-safe reason an unknown claim class acts as carrier"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newRepo()
			repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
			s := writeSvc(repo)

			err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
				FaultlineID: "fl-1",
				Applicabilities: []app.Applicability{
					notAffectedScoped("openssl", "vulnerable_code_not_present", tc.family, tc.major),
				},
			})
			if err != nil {
				t.Fatalf("react: %v", err)
			}
			var raised bool
			for _, p := range repo.byID["fnd-1"].Proposals() {
				if p.Stance() == domain.StanceNotAffected {
					raised = true
				}
			}
			if raised != tc.wantRaised {
				t.Errorf("not_affected proposal raised = %v, want %v — %s", raised, tc.wantRaised, tc.why)
			}
		})
	}
}

// D1/D8: a blocked statement is not mutated and not discarded. The vendor's own words survive
// exactly as received — Themis records its determination elsewhere, never by editing the evidence.
func TestReactToEnrichment_BlockedStatementIsNeitherMutatedNorDiscarded(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/httpd@2.4", "httpd"))
	stmt := notAffectedScoped("httpd", "Red Hat: not affected in Red Hat Enterprise Linux 7",
		value.FamilyEnterpriseLinux, "7")
	before := stmt

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Applicabilities: []app.Applicability{stmt},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if stmt != before {
		t.Errorf("the vendor statement was mutated: %+v, was %+v", stmt, before)
	}
	if stmt.Status != "not_affected" {
		t.Errorf("Status = %q — the vendor's assertion must never carry Themis's determination", stmt.Status)
	}
}

// A release nothing can place (no `elN` marker anywhere on the Finding) yields `unknown`, so even
// a statement that would otherwise match is blocked. Fail-safe: an unplaceable release must not
// be suppressed by a statement Themis cannot confirm applies to it.
func TestReactToEnrichment_UnplaceableReleaseBlocks(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/requests@2.31.0", Name: "requests", Version: "2.31.0", // no EL marker
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID:     "fl-1",
		Applicabilities: []app.Applicability{notAffected("requests", "vulnerable_code_not_present")},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, p := range repo.byID["fnd-1"].Proposals() {
		if p.Stance() == domain.StanceNotAffected {
			t.Error("an unplaceable release must not be suppressed by a vendor statement")
		}
	}
}

// DEF_VEX_COVERING_FIRST_MATCH — the regression for D7's second half: selection among the
// statements covering one package must be by APPLICABILITY, not by array position.
//
// The concrete case, and it is the common one on this estate. Red Hat states httpd not_affected
// for RHEL 7 AND for RHEL 8. Before D7 the dedup key was the package name alone, so only one of
// them survived; now both are kept — and they sort by scope, so major 7 comes FIRST. A first-match
// reader on a Rocky 8.10 release therefore picks the RHEL 7 statement, determines `not_applicable`,
// and blocks — discarding the RHEL 8 statement sitting directly behind it, which applies exactly.
//
// Two correct halves (keep every product · block what does not apply) composing into a false
// negative. The order is deliberately 7-then-8 here because that is the order the view produces.
func TestReactToEnrichment_PicksApplicableStatementNotTheFirstOne(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/httpd@2.4", "httpd"))
	s := writeSvc(repo) // no policies → raise only, never auto-accept

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1",
		Applicabilities: []app.Applicability{
			notAffectedScoped("httpd", "not affected in Red Hat Enterprise Linux 7", value.FamilyEnterpriseLinux, "7"),
			notAffectedScoped("httpd", "not affected in Red Hat Enterprise Linux 8", value.FamilyEnterpriseLinux, "8"),
		},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}

	props := repo.byID["fnd-1"].Proposals()
	var raised []string
	for _, p := range props {
		if p.Stance() == domain.StanceNotAffected {
			raised = append(raised, p.Rationale())
		}
	}
	if len(raised) != 1 {
		t.Fatalf("not_affected proposals = %d (%v), want 1 raised from the APPLICABLE statement", len(raised), raised)
	}
	// The rationale carries the vendor justification, so it identifies WHICH statement was used.
	if !strings.Contains(raised[0], "Enterprise Linux 8") {
		t.Errorf("rationale = %q, want the RHEL 8 statement — the RHEL 7 one does not apply to this release", raised[0])
	}
}

// The mirror: when NO covering statement is applicable, nothing is raised. The fallback exists so
// the block is made against a statement that was really seen, not so it can be acted on.
func TestReactToEnrichment_NoApplicableStatementRaisesNothing(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/httpd@2.4", "httpd"))

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1",
		Applicabilities: []app.Applicability{
			notAffectedScoped("httpd", "RHEL 7", value.FamilyEnterpriseLinux, "7"),
			notAffectedScoped("httpd", "RHEL 9", value.FamilyEnterpriseLinux, "9"),
			notAffectedScoped("httpd", "OpenShift Pipelines", "redhat/openshift_pipelines", "1"),
		},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, p := range repo.byID["fnd-1"].Proposals() {
		if p.Stance() == domain.StanceNotAffected {
			t.Errorf("raised %q — no statement applies to this release", p.Rationale())
		}
	}
}

// EDR-VEX-02 D2, the VISIBLE half: a blocked statement must still reach the reviewer. It raises
// no Proposal — the block is structural — so without the assessment carrying it, "Red Hat said
// nothing" and "Red Hat spoke about another product" would look identical.
//
// The three facts stay in three fields: the vendor's words, the scope the VENDOR stated, and
// Themis's determination. None overwrites another.
func TestGetFindingAssessment_VendorStatementsCarryThemisDetermination(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2023-31122", "pkg:rpm/rocky/httpd@2.4", "httpd"))
	kn := stubKnowledge{k: app.FaultlineKnowledge{
		FaultlineID: "fl-1", CVE: "CVE-2023-31122",
		Applicabilities: []app.Applicability{
			notAffectedScoped("httpd", "Red Hat: not affected in Red Hat Enterprise Linux 7",
				value.FamilyEnterpriseLinux, "7"),
			notAffectedScoped("httpd", "Red Hat: not affected in Red Hat Enterprise Linux 8",
				value.FamilyEnterpriseLinux, "8"),
			notAffectedScoped("httpd", "Red Hat: not affected in OpenShift Pipelines",
				"openshift_pipelines", "1"),
			{Package: "httpd", Status: "not_affected", Justification: "no scope stated"},
		},
	}}
	read := app.NewReadService(repo, fakeProjection{}, nil, 0).WithKnowledge(kn)
	a, err := read.GetFindingAssessment(context.Background(), "fnd-1")
	if err != nil {
		t.Fatalf("assessment: %v", err)
	}
	if len(a.VendorStatements) != 4 {
		t.Fatalf("vendor statements = %d, want all 4 carried — none is discarded for being inapplicable",
			len(a.VendorStatements))
	}
	want := []string{"not_applicable", "applicable", "not_applicable", "unknown"}
	for i, w := range want {
		if got := a.VendorStatements[i].Applicability; got != w {
			t.Errorf("statement %d (%q) applicability = %q, want %q",
				i, a.VendorStatements[i].Justification, got, w)
		}
	}
	// The vendor's own words survive verbatim beside Themis's conclusion (D1/D8).
	for _, v := range a.VendorStatements {
		if v.Status != "not_affected" {
			t.Errorf("status = %q — the vendor's assertion must never carry Themis's determination", v.Status)
		}
	}
	// And the scope shown is the VENDOR's, not a rewritten one.
	if a.VendorStatements[0].ScopeMajor != "7" || a.VendorStatements[1].ScopeMajor != "8" {
		t.Errorf("scopes = %q/%q, want the vendor's 7 and 8",
			a.VendorStatements[0].ScopeMajor, a.VendorStatements[1].ScopeMajor)
	}
}
