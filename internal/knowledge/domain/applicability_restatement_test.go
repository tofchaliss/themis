package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// EDR-VEX-02 D17: a feed emits N statements per poll, one per (package, product, status). With
// the latest-only restatement rule each of the N differed from the one recorded just before it,
// so every poll re-appended all N. A statement equal to ANY recorded one from its source is a
// restatement: three statements folded on two polls leave three proposals, not six.
func TestApplicabilityRestatementIsAgainstTheSet(t *testing.T) {
	fl, err := domain.NewFaultline("F1", mustCVE(t, "CVE-2022-30632"))
	if err != nil {
		t.Fatal(err)
	}
	prec := domain.NewPrecedence("redhat")
	el8 := value.ProductScope{Family: "enterprise-linux", Major: "8"}
	el9 := value.ProductScope{Family: "enterprise-linux", Major: "9"}
	statements := []domain.Applicability{
		{Package: "git-lfs", Status: domain.StatusFixed, Scope: el8, Advisory: "RHSA-2022:7129", FixedVersion: "git-lfs-0:2.13.3-3.el8_6"},
		{Package: "osbuild-composer", Status: domain.StatusWillNotFix, Scope: el8},
		{Package: "conmon", Status: domain.StatusNotAffected, Scope: el9},
	}
	poll := func(at int64) int {
		recorded := 0
		for _, a := range statements {
			p, err := domain.NewApplicabilityProposal("redhat", t0.Add(0).Add(0), a)
			if err != nil {
				t.Fatal(err)
			}
			_ = at
			if fl.FoldProposal(p, prec, openTrust()).Recorded {
				recorded++
			}
		}
		return recorded
	}
	if n := poll(0); n != 3 {
		t.Fatalf("first poll recorded %d, want 3", n)
	}
	if n := poll(1); n != 0 {
		t.Fatalf("second poll recorded %d, want 0 (every statement is a restatement)", n)
	}
	if got := len(fl.View().Applicabilities); got != 3 {
		t.Fatalf("view holds %d statements, want 3", got)
	}
	// A genuinely new statement still records.
	p, _ := domain.NewApplicabilityProposal("redhat", t1, domain.Applicability{Package: "curl", Status: domain.StatusAffected, Scope: el8})
	if !fl.FoldProposal(p, prec, openTrust()).Recorded {
		t.Fatal("a new statement must be recorded")
	}
}
