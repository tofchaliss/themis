package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

func TestFindingLifecycleEvents(t *testing.T) {
	f := newFinding(t)

	opened := domain.NewFindingOpened(f, epoch)
	if opened.FindingID != "fnd-1" || opened.ReleaseID != "rel-1" || opened.FaultlineID != "fl-1" ||
		opened.CVE != "CVE-2024-1" || !opened.OccurredAt.Equal(epoch) {
		t.Errorf("opened = %+v", opened)
	}
	if e := domain.NewFindingResolved(f, epoch); e.FindingID != "fnd-1" || !e.OccurredAt.Equal(epoch) {
		t.Errorf("resolved = %+v", e)
	}
	if e := domain.NewFindingReopened(f, epoch); e.FindingID != "fnd-1" || !e.OccurredAt.Equal(epoch) {
		t.Errorf("reopened = %+v", e)
	}
	if e := domain.NewFindingArchived(f, epoch); e.FindingID != "fnd-1" || !e.OccurredAt.Equal(epoch) {
		t.Errorf("archived = %+v", e)
	}
}

func TestProposalEvents(t *testing.T) {
	f := newFinding(t)
	p := proposal(t, "p1", system, domain.StanceNotAffected)

	raised := domain.NewProposalRaised(f, p, epoch)
	if raised.FindingID != "fnd-1" || raised.ProposalID != "p1" || raised.Stance != domain.StanceNotAffected ||
		raised.ProposerKind != domain.ActorSystem || !raised.OccurredAt.Equal(epoch) {
		t.Errorf("raised = %+v", raised)
	}

	pos := domain.ReconstitutePosition(1, domain.StanceNotAffected, "x", human, domain.PositionInputs{}, epoch)
	accepted := domain.NewProposalAccepted(f, p.ID(), pos, epoch)
	if accepted.FindingID != "fnd-1" || accepted.ProposalID != "p1" || accepted.PositionVersion != 1 {
		t.Errorf("accepted = %+v", accepted)
	}

	if e := domain.NewProposalRejected(f, p.ID(), epoch); e.FindingID != "fnd-1" || e.ProposalID != "p1" {
		t.Errorf("rejected = %+v", e)
	}
}

func TestNewPositionEvent(t *testing.T) {
	f := newFinding(t)

	v1 := domain.ReconstitutePosition(1, domain.StanceAffected, "confirmed", human, domain.PositionInputs{}, epoch)
	established, revised := domain.NewPositionEvent(f, v1, epoch)
	if established == nil || revised != nil {
		t.Fatalf("v1 should be PositionEstablished: est=%v rev=%v", established, revised)
	}
	if established.Version != 1 || established.Stance != domain.StanceAffected ||
		established.ReleaseID != "rel-1" || established.FaultlineID != "fl-1" || established.CVE != "CVE-2024-1" {
		t.Errorf("established = %+v", established)
	}

	v2 := domain.ReconstitutePosition(2, domain.StanceMitigated, "fixed", human, domain.PositionInputs{}, epoch)
	established, revised = domain.NewPositionEvent(f, v2, epoch)
	if revised == nil || established != nil {
		t.Fatalf("v2 should be PositionRevised: est=%v rev=%v", established, revised)
	}
	if revised.Version != 2 || revised.Stance != domain.StanceMitigated {
		t.Errorf("revised = %+v", revised)
	}
}
