package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// 2026-10-14: the proposal log is append-only, and ranges used to be a union across TIME as
// well as across sources — so the lone `>=0` the old OSV pairing wrote stayed on every Go card
// after the translator was fixed, and nothing could displace it. A source's LATER statement
// now replaces its earlier ranges; other sources' ranges still join the union.
func TestReconcile_LaterRangesFromASourceReplaceItsEarlierOnes(t *testing.T) {
	fl, err := domain.NewFaultline("F1", mustCVE(t, "CVE-2015-5739"))
	if err != nil {
		t.Fatal(err)
	}
	prec := domain.NewPrecedence("osv")
	c, _ := value.NewCVSS(7.5, "")
	stmt := func(src string, at time.Time, ranges ...string) domain.Proposal {
		p, err := domain.NewVulnFactsProposal(src, at, domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: ranges})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	fl.FoldProposal(stmt("osv", t0, ">=0", "<1.4.3"), prec, openTrust()) // the old, wrong shape
	fl.FoldProposal(stmt("nvd", t0, "<=1.4.2"), prec, openTrust())       // another source's bound
	fl.FoldProposal(stmt("osv", t1, ">=0,<1.4.3"), prec, openTrust())    // the corrected statement
	got := fl.View().AffectedRanges
	want := []string{"<=1.4.2", ">=0,<1.4.3"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("ranges = %v, want %v (osv's later word replaces its earlier one; nvd's stays)", got, want)
	}
	// And the card is now provably out of range for a modern build.
	r := value.AffectedRange{Ecosystem: "go", Groups: got}
	if v := r.Applicability("go1.27.1"); v != value.RangeOutOfRange {
		t.Fatalf("go1.27.1 against %v = %s, want out_of_range", got, v)
	}
}
