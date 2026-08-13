package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func summaryFacts(sev value.Severity, summary string) domain.VulnFacts {
	return domain.VulnFacts{Severity: sev, Summary: summary}
}

func mustProposal(t *testing.T, source string, at time.Time, f domain.VulnFacts) domain.Proposal {
	t.Helper()
	p, err := domain.NewVulnFactsProposal(source, at, f)
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

var (
	t0 = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(24 * time.Hour)
)

func openTrust() domain.TrustPolicy { return domain.NewTrustPolicy(nil) }

func TestReconcileSummaryFollowsPrecedence(t *testing.T) {
	prec := domain.NewPrecedence("nvd", "osv")
	view := domain.Reconcile([]domain.Proposal{
		mustProposal(t, "osv", t1, summaryFacts(value.SeverityHigh, "osv words")),
		mustProposal(t, "nvd", t0, summaryFacts(value.SeverityHigh, "nvd words")),
	}, prec, openTrust())

	if view.Summary != "nvd words" || view.SummarySource != "nvd" {
		t.Fatalf("summary = %q from %q, want nvd to win by precedence despite being older", view.Summary, view.SummarySource)
	}
}

// The race is independent of the severity headline: a higher-authority source that carries
// severity but NO prose must not blank the summary a lower-authority source supplied.
func TestReconcileSummaryIndependentOfHeadline(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	view := domain.Reconcile([]domain.Proposal{
		mustProposal(t, "redhat", t1, summaryFacts(value.SeverityCritical, "")), // severity, no prose
		mustProposal(t, "osv", t0, summaryFacts(value.SeverityHigh, "a heap overflow in libfoo")),
	}, prec, openTrust())

	if view.SeveritySource != "redhat" {
		t.Fatalf("headline source = %q, want redhat", view.SeveritySource)
	}
	if view.Summary != "a heap overflow in libfoo" || view.SummarySource != "osv" {
		t.Fatalf("summary = %q from %q, want osv's prose to survive a summary-less headline winner", view.Summary, view.SummarySource)
	}
}

func TestReconcileSummaryTiebreaks(t *testing.T) {
	prec := domain.NewPrecedence()

	// same rank: newer observation wins
	v := domain.Reconcile([]domain.Proposal{
		mustProposal(t, "a", t0, summaryFacts(value.SeverityLow, "old")),
		mustProposal(t, "a", t1, summaryFacts(value.SeverityLow, "new")),
	}, prec, openTrust())
	if v.Summary != "new" {
		t.Fatalf("recency tiebreak: got %q", v.Summary)
	}

	// same rank + time: lower source name wins (deterministic, order-independent)
	v = domain.Reconcile([]domain.Proposal{
		mustProposal(t, "zeta", t0, summaryFacts(value.SeverityLow, "zeta words")),
		mustProposal(t, "alpha", t0, summaryFacts(value.SeverityLow, "alpha words")),
	}, prec, openTrust())
	if v.SummarySource != "alpha" {
		t.Fatalf("source tiebreak: got %q", v.SummarySource)
	}

	// same rank + time + source: lower text wins — the order made total
	v = domain.Reconcile([]domain.Proposal{
		mustProposal(t, "a", t0, summaryFacts(value.SeverityLow, "bbb")),
		mustProposal(t, "a", t0, summaryFacts(value.SeverityLow, "aaa")),
	}, prec, openTrust())
	if v.Summary != "aaa" {
		t.Fatalf("text tiebreak: got %q", v.Summary)
	}
}

// A summary change alone is a view change: it must fire FaultlineEnriched so downstream
// learns the card gained its description.
func TestSummaryChangeIsAViewChange(t *testing.T) {
	fl, err := domain.NewFaultline("F1", mustCVE(t, "CVE-2026-1111"))
	if err != nil {
		t.Fatalf("faultline: %v", err)
	}
	prec := domain.NewPrecedence("osv")
	fl.FoldProposal(mustProposal(t, "osv", t0, summaryFacts(value.SeverityHigh, "")), prec, openTrust())

	res := fl.FoldProposal(mustProposal(t, "osv", t1, summaryFacts(value.SeverityHigh, "now with prose")), prec, openTrust())
	if !res.ViewChanged {
		t.Fatal("a gained summary must report a view change")
	}
}

// And a verbatim restatement including the summary stays deduped (KN-PROPOSAL-BLOAT-1).
func TestSummaryRestatementIsNotRecorded(t *testing.T) {
	fl, err := domain.NewFaultline("F1", mustCVE(t, "CVE-2026-1111"))
	if err != nil {
		t.Fatalf("faultline: %v", err)
	}
	prec := domain.NewPrecedence("osv")
	facts := summaryFacts(value.SeverityHigh, "same words")
	fl.FoldProposal(mustProposal(t, "osv", t0, facts), prec, openTrust())

	res := fl.FoldProposal(mustProposal(t, "osv", t1, facts), prec, openTrust())
	if res.Recorded {
		t.Fatal("identical facts incl. summary must dedup")
	}
}

func mustCVE(t *testing.T, s string) value.CVEID {
	t.Helper()
	c, err := value.NewCVEID(s)
	if err != nil {
		t.Fatalf("cve: %v", err)
	}
	return c
}

func TestTruncateSummary(t *testing.T) {
	if got := domain.TruncateSummary("  a\nb\t c  "); got != "a b c" {
		t.Fatalf("whitespace collapse: %q", got)
	}
	long := strings.Repeat("x", 600)
	got := domain.TruncateSummary(long)
	if r := []rune(got); len(r) != 480 || !strings.HasSuffix(got, "…") {
		t.Fatalf("cap: len=%d suffix=%q", len(r), got[len(got)-3:])
	}
	if got := domain.TruncateSummary(""); got != "" {
		t.Fatalf("empty stays empty, got %q", got)
	}
}

func TestVulnFactsCopyCarriesSummary(t *testing.T) {
	p := mustProposal(t, "osv", t0, summaryFacts(value.SeverityLow, "kept"))
	f, ok := p.VulnFacts()
	if !ok || f.Summary != "kept" {
		t.Fatalf("summary dropped by the defensive copy: %+v ok=%v", f, ok)
	}
}
