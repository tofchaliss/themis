package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

var (
	accT0    = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	accHuman = domain.Actor{Kind: domain.ActorHuman, ID: "alice"}
)

func proposed(t *testing.T, stance domain.Stance) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2026-1")
	if err != nil {
		t.Fatal(err)
	}
	p, err := domain.NewGovernanceProposal("p1", accHuman, stance, "why", accT0, value.TrustObserved)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestValidTreatment(t *testing.T) {
	for _, tr := range []domain.Treatment{"", domain.TreatmentAccept, domain.TreatmentTransfer, domain.TreatmentAvoid, domain.TreatmentMitigateLater} {
		if !domain.ValidTreatment(tr) {
			t.Errorf("%q invalid", tr)
		}
	}
	if domain.ValidTreatment("ignore") {
		t.Error("ignore is valid")
	}
}

// Q3: a person accepting an accepted_risk names the owner; the terms are recorded, trimmed, on
// the Position.
func TestAcceptanceTermsRecordedOnThePosition(t *testing.T) {
	f := proposed(t, domain.StanceAcceptedRisk)
	pos, err := f.AcceptProposalWith("p1", accHuman, accT0, domain.AcceptanceTerms{
		ReviewBy: accT0.Add(90 * 24 * time.Hour), Owner: "  bob@example.test ", Treatment: " transfer ", Proof: " https://x.test/r/1 ",
	})
	if err != nil {
		t.Fatal(err)
	}
	in := pos.Inputs()
	if in.Owner != "bob@example.test" || in.Treatment != domain.TreatmentTransfer || in.Proof != "https://x.test/r/1" || !in.ReviewBy.Equal(accT0.Add(90*24*time.Hour)) {
		t.Fatalf("inputs = %+v", in)
	}
}

func TestAcceptanceOwnerRequiredFromAPersonQ3(t *testing.T) {
	f := proposed(t, domain.StanceAcceptedRisk)
	if _, err := f.AcceptProposalWith("p1", accHuman, accT0, domain.AcceptanceTerms{Owner: "  "}); !errors.Is(err, domain.ErrOwnerRequired) {
		t.Fatalf("no owner: %v", err)
	}
	if p, _ := f.Proposals()[0], 0; !p.IsOpen() {
		t.Fatal("a refused acceptance decided the proposal")
	}
	// A policy may sign without one; deferred never requires one.
	if _, err := f.AcceptProposalWith("p1", domain.Actor{Kind: domain.ActorPolicy, ID: "vex"}, accT0, domain.AcceptanceTerms{}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	d := proposed(t, domain.StanceDeferred)
	if _, err := d.AcceptProposal("p1", accHuman, accT0); err != nil {
		t.Fatalf("deferred: %v", err)
	}
}

func TestAcceptanceTermsRefusals(t *testing.T) {
	f := proposed(t, domain.StanceAcceptedRisk)
	if _, err := f.AcceptProposalWith("p1", accHuman, accT0, domain.AcceptanceTerms{Owner: "o", Treatment: "ignore"}); !errors.Is(err, domain.ErrInvalidTreatment) {
		t.Fatalf("bad treatment: %v", err)
	}
	for _, terms := range []domain.AcceptanceTerms{{Owner: "o"}, {Treatment: domain.TreatmentAvoid}, {Proof: "doc-1"}} {
		n := proposed(t, domain.StanceNotAffected)
		if _, err := n.AcceptProposalWith("p1", accHuman, accT0, terms); !errors.Is(err, domain.ErrTermsNotApplicable) {
			t.Fatalf("terms %+v on not_affected: %v", terms, err)
		}
	}
	n := proposed(t, domain.StanceNotAffected)
	pos, err := n.AcceptProposal("p1", accHuman, accT0, accT0.Add(time.Hour))
	if err != nil || !pos.Inputs().ReviewBy.Equal(accT0.Add(time.Hour)) {
		t.Fatalf("review-by alone on not_affected: %+v %v", pos.Inputs(), err)
	}
}

func TestReviewDueSoonAndWindow(t *testing.T) {
	f := proposed(t, domain.StanceAcceptedRisk)
	rb := accT0.Add(10 * 24 * time.Hour)
	pos, err := f.AcceptProposalWith("p1", accHuman, accT0, domain.AcceptanceTerms{ReviewBy: rb, Owner: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	w := domain.DefaultReviewWarning
	if !domain.ReviewDueWithin(pos, accT0, w) {
		t.Error("10 days ahead is within 14")
	}
	if domain.ReviewDueWithin(pos, rb, w) || domain.ReviewDueWithin(pos, rb.Add(time.Hour), w) {
		t.Error("a date that has arrived or passed is expiry, not a warning")
	}
	if domain.ReviewDueWithin(pos, accT0, 24*time.Hour) {
		t.Error("10 days ahead is outside a 1-day window")
	}
	g := proposed(t, domain.StanceDeferred)
	none, _ := g.AcceptProposal("p1", accHuman, accT0)
	if domain.ReviewDueWithin(none, accT0, w) {
		t.Error("no review date is never due")
	}
	ev := domain.NewReviewDueSoon(f, pos, accT0)
	if ev.FindingID != "fnd-1" || ev.CVE != "CVE-2026-1" || ev.Stance != "accepted_risk" || ev.PositionVersion != 1 ||
		!ev.ReviewBy.Equal(rb) || ev.Owner != "bob" || !ev.OccurredAt.Equal(accT0) || ev.ReleaseID != "rel-1" || ev.FaultlineID != "fl-1" {
		t.Fatalf("event = %+v", ev)
	}
}
