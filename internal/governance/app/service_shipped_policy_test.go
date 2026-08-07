package app_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// These tests exercise the policy Themis actually SHIPS —
// domain.AutoAcceptObservedNotAffectedPolicy(), the single rule wired by cmd/governance
// (EDR-GOVERNANCE-01 D15) — rather than a permissive stand-in built for the test.
//
// The distinction matters. Every other policy test in this package constructs a floor-less
// NewPolicyRule("auto-not-affected", StanceNotAffected), which auto-accepts on ANY non-Inferred
// evidence. That is fine for exercising the surrounding machinery, but it means no test
// demonstrated what a real deployment does — the gap EDR-TRUST-01's VM verification recorded as
// TRUST-7 ("the constitutional bar is end-to-end unobservable") and the backlog's C3 cluster
// calls "believed correct, never demonstrated".
//
// The two system paths below reach raiseAndMaybeAutoAccept with the SAME stance, the SAME
// proposer kind, and different evidence — so they are the sharpest available demonstration
// that trust, not the producing component, decides (T1/T2).

// The version-range verdict is arithmetic over public ranges: anyone with the installed version
// and the published range re-derives it. Observed evidence, so the shipped rule accepts it and
// the Finding is suppressed without a human.
func TestShippedPolicy_AutoAcceptsTheProvableVersionRangeVerdict(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:pypi/foo@5.0", Name: "foo", Version: "5.0", Ecosystem: "pypi",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)
	s := writeSvc(repo, domain.AutoAcceptObservedNotAffectedPolicy())

	// The installed 5.0 is provably outside [1.0, 3.0), and the range came from a public record.
	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", AffectedRanges: []string{">= 1.0, < 3.0"}, RangeTrust: value.TrustObserved,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}

	want := []string{app.EventProposalRaised, app.EventProposalAccepted, app.EventPositionEstablished}
	if got := noteTypes(repo.lastNotes); !eq(got, want) {
		t.Fatalf("notes = %v, want %v — the whole governed road, raise through Position", got, want)
	}
	pos, ok := repo.byID["fnd-1"].CurrentPosition()
	if !ok || pos.Stance() != domain.StanceNotAffected {
		t.Fatalf("position = %+v ok=%v, want not_affected", pos, ok)
	}
	// The POLICY is the authority, never the proposer (D11) — that is what makes an unattended
	// decision auditable.
	if pos.Actor().Kind != domain.ActorPolicy || pos.Actor().ID != "auto-not-affected-observed" {
		t.Fatalf("deciding actor = %+v, want the named policy as authority", pos.Actor())
	}
}

// The same stance, from the same system actor, on Asserted evidence: a vendor saying their own
// build is not affected. It PASSES the constitutional bar (T4 stops only Inferred) and is still
// refused, by the shipped rule's Observed floor. This is "Gathering Is Not Knowing" (EDR-VEX-01)
// holding in code — and it is the case a floor-less test policy silently gets wrong.
func TestShippedPolicy_LeavesVendorVEXSuppressionForAHuman(t *testing.T) {
	repo := newRepo()
	repo.seed(withComponent(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1", "pkg:rpm/openssl@1.0.2", "openssl"))
	s := writeSvc(repo, domain.AutoAcceptObservedNotAffectedPolicy())

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID:     "fl-1",
		Applicabilities: []app.Applicability{notAffected("openssl", "vulnerable_code_not_present")},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}

	if got := noteTypes(repo.lastNotes); !eq(got, []string{app.EventProposalRaised}) {
		t.Fatalf("notes = %v, want ONLY a raised proposal — a vendor's word must not self-accept", got)
	}
	got := repo.byID["fnd-1"]
	if _, ok := got.CurrentPosition(); ok {
		t.Fatal("no Position may exist: the vendor statement is gathered, not obeyed")
	}
	// It is recorded and open — waiting for a human, not discarded.
	if len(got.Proposals()) != 1 || !got.Proposals()[0].IsOpen() {
		t.Fatalf("proposals = %+v, want one OPEN proposal awaiting a decision", got.Proposals())
	}
	if c := got.Proposals()[0].EvidenceTrust(); c != value.TrustAsserted {
		t.Fatalf("evidence class = %q, want %q — the reason it was refused", c, value.TrustAsserted)
	}
}

// An `affected` verdict is never automatic, even on Observed evidence: it would be a decision
// nobody made about work someone must now do. Nothing is lost by leaving it open, because an
// undecided Finding already sits at full residual_priority (D14) and is already in the queue.
func TestShippedPolicy_NeverAutoAcceptsAffected(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	s := writeSvc(repo, domain.AutoAcceptObservedNotAffectedPolicy())

	// A KEV listing raises the system `affected` re-evaluation proposal (D6).
	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", KEV: true, HighSeverity: true,
		HeadlineTrust: value.TrustObserved, SignalTrust: value.TrustObserved, RangeTrust: value.TrustObserved,
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if _, ok := repo.byID["fnd-1"].CurrentPosition(); ok {
		t.Fatal("an affected proposal must never be auto-accepted, however good its evidence")
	}
}
