package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

var resEpoch = time.Unix(1_700_000_000, 0).UTC()

// acceptedOn builds a Finding whose current Position was established by accepting a
// proposal resting on the given evidence class.
func acceptedOn(t *testing.T, pid string, proposer domain.Actor, class value.TrustClass) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	p, err := domain.NewGovernanceProposal(
		domain.ProposalID(pid), proposer, domain.StanceNotAffected, "because", resEpoch, class)
	if err != nil {
		t.Fatalf("new proposal: %v", err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatalf("raise: %v", err)
	}
	decider := domain.Actor{Kind: domain.ActorHuman, ID: "analyst-1"}
	if _, err := f.AcceptProposal(domain.ProposalID(pid), decider, resEpoch); err != nil {
		t.Fatalf("accept: %v", err)
	}
	return f
}

// An acceptance resting on a vendor's Asserted statement carries a reservation naming both
// the class and who supplied the evidence — so "how sound was that call?" has an answer
// months later.
func TestCurrentReservation_AssertedEvidenceIsReservedAndNamesTheProposer(t *testing.T) {
	vendor := domain.Actor{Kind: domain.ActorSystem, ID: "vex-applicability"}
	f := acceptedOn(t, "p1", vendor, value.TrustAsserted)

	r, ok := f.CurrentReservation()
	if !ok {
		t.Fatal("expected a reservation on an acceptance resting on Asserted evidence")
	}
	if r.EvidenceTrust != value.TrustAsserted {
		t.Errorf("EvidenceTrust = %q, want %q", r.EvidenceTrust, value.TrustAsserted)
	}
	if r.Proposer != vendor {
		t.Errorf("Proposer = %+v, want %+v", r.Proposer, vendor)
	}
}

func TestCurrentReservation_ObservedEvidenceHasNothingToCaveat(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "version-range"}
	if _, ok := acceptedOn(t, "p1", system, value.TrustObserved).CurrentReservation(); ok {
		t.Error("an acceptance on Observed evidence must carry no reservation")
	}
}

// A Position whose evidence was never stated is reserved, not silently trusted.
func TestCurrentReservation_UnstatedEvidenceIsReserved(t *testing.T) {
	system := domain.Actor{Kind: domain.ActorSystem, ID: "legacy"}
	r, ok := acceptedOn(t, "p1", system, value.TrustClass("")).CurrentReservation()
	if !ok || r.EvidenceTrust != value.TrustInferred {
		t.Errorf("unset evidence: reservation=%+v ok=%v, want Inferred + reserved", r, ok)
	}
}

func TestCurrentReservation_NoPositionMeansNoReservation(t *testing.T) {
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	if _, ok := f.CurrentReservation(); ok {
		t.Error("a Finding with no Position has nothing to reserve")
	}
}

// The lifting path — the property that justifies deriving rather than storing. A later
// Position version established on Observed evidence carries NO reservation, with no
// migration and no backfill: the history simply shows the caveat disappear. A stored flag
// would have needed rewriting on the old row, or would have gone stale on it.
func TestCurrentReservation_LiftsWhenBetterEvidenceEstablishesANewVersion(t *testing.T) {
	vendor := domain.Actor{Kind: domain.ActorSystem, ID: "vex-applicability"}
	f := acceptedOn(t, "p1", vendor, value.TrustAsserted)
	if _, ok := f.CurrentReservation(); !ok {
		t.Fatal("precondition: v1 should be reserved")
	}

	// Better evidence arrives — a signed artifact makes the same claim re-derivable.
	stronger, err := domain.NewGovernanceProposal(
		"p2", domain.Actor{Kind: domain.ActorSystem, ID: "build-manifest"},
		domain.StanceNotAffected, "confirmed from a signed build manifest", resEpoch, value.TrustObserved)
	if err != nil {
		t.Fatalf("new proposal: %v", err)
	}
	if err := f.RaiseProposal(stronger); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if _, err := f.AcceptProposal("p2", domain.Actor{Kind: domain.ActorHuman, ID: "analyst-1"}, resEpoch); err != nil {
		t.Fatalf("accept: %v", err)
	}

	if _, ok := f.CurrentReservation(); ok {
		t.Error("the new version rests on Observed evidence — its reservation must have lifted")
	}
	// History is intact: both versions are retained, and v1's caveat is still explicable
	// from its own inputs. Nothing was rewritten.
	if len(f.Positions()) != 2 {
		t.Fatalf("positions = %d, want 2 (append-only)", len(f.Positions()))
	}
}

// A Position whose accepted proposal is not present cannot be vouched for. This is the
// partial-projection case — a Finding reconstituted with position history but without the
// proposal that established it. Reserving is the safe reading: the alternative would imply
// the decision was well-evidenced precisely when we cannot tell.
func TestCurrentReservation_MissingAcceptedProposalIsReserved(t *testing.T) {
	pos := domain.ReconstitutePosition(1, domain.StanceNotAffected, "why",
		domain.Actor{Kind: domain.ActorHuman, ID: "analyst-1"},
		domain.PositionInputs{AcceptedProposalID: "p-gone", FaultlineRef: "fl-1"}, resEpoch)

	f := domain.ReconstituteFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1", nil,
		domain.StagePositionEstablished, nil /* no proposals */, []domain.Position{pos}, 1)

	r, ok := f.CurrentReservation()
	if !ok || r.EvidenceTrust != value.TrustInferred {
		t.Errorf("reservation = %+v ok=%v, want reserved as %q", r, ok, value.TrustInferred)
	}
}
