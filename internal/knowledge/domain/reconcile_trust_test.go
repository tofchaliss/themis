package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// trustPolicy for these tests: a public record, a vendor, and a model.
func trustPolicy() domain.TrustPolicy {
	return domain.NewTrustPolicy(map[string]value.TrustClass{
		"osv":    value.TrustObserved,
		"nvd":    value.TrustObserved,
		"kev":    value.TrustObserved,
		"redhat": value.TrustAsserted,
		"ai":     value.TrustInferred,
	})
}

// The headline is winner-take-all, so it inherits exactly the winning source's class —
// it is not folded across losing candidates, which contributed nothing to it.
func TestReconcile_HeadlineTrustIsTheWinnersClass(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	v := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "nvd", value.SeverityHigh),
		vulnFacts(t, "redhat", value.SeverityCritical),
	}, prec, trustPolicy())

	if v.SeveritySource != "redhat" {
		t.Fatalf("precondition: expected redhat to win the headline, got %q", v.SeveritySource)
	}
	if v.HeadlineTrust != value.TrustAsserted {
		t.Fatalf("HeadlineTrust = %q, want %q (the winner's class)", v.HeadlineTrust, value.TrustAsserted)
	}
}

// Ranges are a union, so the group takes the highest-risk class among everything that
// contributed to it (T3).
func TestReconcile_RangeTrustFoldsAcrossContributors(t *testing.T) {
	prec := domain.NewPrecedence("nvd", "osv")
	v := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "osv", value.SeverityHigh, "<3.0"),
		vulnFacts(t, "redhat", value.SeverityHigh, "<2.0"),
	}, prec, trustPolicy())

	if v.RangeTrust != value.TrustAsserted {
		t.Fatalf("RangeTrust = %q, want %q — a union is only as good as its weakest contributor",
			v.RangeTrust, value.TrustAsserted)
	}
}

// The case that justifies per-field-group trust rather than one class for the view. A
// vendor VEX statement (Asserted) sits on the card, but the affected ranges came purely
// from a public record. If the view carried a single class, the Asserted statement would
// drag the ranges down and a provable version-range verdict — computed only from Observed
// evidence — would be wrongly barred from policy auto-acceptance in Governance.
func TestReconcile_AssertedApplicabilityDoesNotContaminateObservedRanges(t *testing.T) {
	prec := domain.NewPrecedence("nvd", "osv")
	v := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "osv", value.SeverityHigh, "<3.0"),
		applic(t, "redhat", "openssl", "not_affected"),
	}, prec, trustPolicy())

	if len(v.Applicabilities) != 1 {
		t.Fatalf("precondition: expected the vendor statement to be held, got %d", len(v.Applicabilities))
	}
	if v.RangeTrust != value.TrustObserved {
		t.Fatalf("RangeTrust = %q, want %q — an Asserted statement elsewhere on the card must not "+
			"contaminate evidence it did not contribute to", v.RangeTrust, value.TrustObserved)
	}
}

func TestReconcile_SignalTrustFoldsAcrossSignalSources(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	at := time.Date(2026, 8, 6, 0, 0, 0, 0, time.UTC)
	v := domain.Reconcile([]domain.Proposal{
		exploit(t, "kev", at, 0.4, true, false),
		exploit(t, "ai", at.Add(time.Hour), 0.9, false, true),
	}, prec, trustPolicy())

	if v.SignalTrust != value.TrustInferred {
		t.Fatalf("SignalTrust = %q, want %q", v.SignalTrust, value.TrustInferred)
	}
}

// A group with no contributor stays unset. That is safe by construction: value.MaxTrust
// reads an unset class as Inferred, so a consumer that folds one in without checking
// degrades to the most conservative answer instead of silently claiming Observed.
func TestReconcile_TrustIsUnsetWhenNothingContributed(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	v := domain.Reconcile([]domain.Proposal{
		exploit(t, "kev", time.Now(), 0.4, true, false),
	}, prec, trustPolicy())

	if v.RangeTrust != "" || v.HeadlineTrust != "" {
		t.Fatalf("expected unset range/headline trust, got %q / %q", v.RangeTrust, v.HeadlineTrust)
	}
	if got := value.MaxTrust(v.RangeTrust); got != value.TrustInferred {
		t.Fatalf("an unset class must degrade to %q under MaxTrust, got %q", value.TrustInferred, got)
	}
}

// A trust change is a view change: Governance re-evaluates on evidence getting weaker or
// stronger, so it must fire FaultlineEnriched (D8).
func TestFoldProposal_TrustChangeCountsAsViewChange(t *testing.T) {
	prec := domain.NewPrecedence("nvd", "osv")
	policy := trustPolicy()
	f, err := domain.NewFaultline("FL-1", cve(t, "CVE-2024-0001"))
	if err != nil {
		t.Fatalf("NewFaultline: %v", err)
	}

	f.FoldProposal(vulnFacts(t, "osv", value.SeverityHigh, "<3.0"), prec, policy)
	// A second contributor adds no new range and does not win the headline, but it does
	// weaken the range group's trust from Observed to Asserted.
	res := f.FoldProposal(vulnFacts(t, "redhat", value.SeverityLow, "<3.0"), prec, policy)
	if !res.ViewChanged {
		t.Fatal("expected ViewChanged: the range group's trust weakened to Asserted")
	}
}
