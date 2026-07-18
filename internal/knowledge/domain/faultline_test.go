package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func cve(t *testing.T, s string) value.CVEID {
	t.Helper()
	c, err := value.NewCVEID(s)
	if err != nil {
		t.Fatalf("cve %q: %v", s, err)
	}
	return c
}

func vulnFacts(t *testing.T, source string, sev value.Severity, ranges ...string) domain.Proposal {
	t.Helper()
	p, err := domain.NewVulnFactsProposal(source, obs, domain.VulnFacts{Severity: sev, CVSS: mustCVSS(t, 7.5), AffectedRanges: ranges})
	if err != nil {
		t.Fatalf("vuln facts proposal: %v", err)
	}
	return p
}

func TestNewFaultline(t *testing.T) {
	f, err := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if f.ID() != "fl-1" || f.CVE().String() != "CVE-2024-1" || f.Stage() != domain.StageCreated || f.Version() != 0 {
		t.Errorf("faultline = %+v", f)
	}
	if len(f.Proposals()) != 0 || f.View().Severity != value.SeverityUnknown {
		t.Errorf("fresh card not empty: %+v", f.View())
	}

	if _, err := domain.NewFaultline("", cve(t, "CVE-2024-1")); err == nil {
		t.Error("empty id: expected error")
	}
	if _, err := domain.NewFaultline("fl-1", value.CVEID{}); err == nil {
		t.Error("zero cve: expected error")
	}
}

func TestFoldProposal(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))

	// First fold → view changes, stage advances to Enriched, version bumps.
	if r := f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"), prec); !r.ViewChanged {
		t.Error("first fold should change the view")
	}
	if f.Stage() != domain.StageEnriched || f.Version() != 1 {
		t.Errorf("after first fold: stage=%s version=%d", f.Stage(), f.Version())
	}
	if f.View().Severity != value.SeverityHigh || f.View().SeveritySource != "nvd" {
		t.Errorf("view = %+v", f.View())
	}

	// Folding an identical fact again changes nothing (but is still recorded).
	if r := f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"), prec); r.ViewChanged {
		t.Error("duplicate fold should not change the view")
	}
	if len(f.Proposals()) != 2 || f.Version() != 2 {
		t.Errorf("duplicate not recorded: proposals=%d version=%d", len(f.Proposals()), f.Version())
	}

	// A higher-authority source overrides the headline severity.
	if r := f.FoldProposal(vulnFacts(t, "redhat", value.SeverityCritical), prec); !r.ViewChanged {
		t.Error("higher-authority fold should change the view")
	}
	if f.View().Severity != value.SeverityCritical || f.View().SeveritySource != "redhat" {
		t.Errorf("redhat should win: %+v", f.View())
	}
}

func TestLifecycleLadder(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec) // → Enriched

	if !f.MarkCorrelated() || f.Stage() != domain.StageCorrelated {
		t.Errorf("MarkCorrelated: stage=%s", f.Stage())
	}
	// Folding after Correlated must not regress the stage.
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec)
	if f.Stage() != domain.StageCorrelated {
		t.Errorf("fold regressed stage to %s", f.Stage())
	}

	if !f.MarkMature() || f.Stage() != domain.StageMature {
		t.Errorf("MarkMature: stage=%s", f.Stage())
	}
	// A lower target is a no-op.
	if f.MarkCorrelated() {
		t.Error("MarkCorrelated on a Mature card should be a no-op")
	}

	if !f.Supersede() || f.Stage() != domain.StageSuperseded {
		t.Errorf("Supersede: stage=%s", f.Stage())
	}
	// Superseded is terminal.
	if f.Supersede() {
		t.Error("Supersede on a superseded card should be a no-op")
	}
	verBefore := f.Version()
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityLow), prec) // still recorded, stage frozen
	if f.Stage() != domain.StageSuperseded {
		t.Errorf("fold moved a superseded card to %s", f.Stage())
	}
	if f.Version() != verBefore+1 {
		t.Error("fold should still bump version on a superseded card")
	}
}

func TestReconstitute(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	p := vulnFacts(t, "nvd", value.SeverityHigh, "<3.0")
	view := domain.Reconcile([]domain.Proposal{p}, prec)

	f := domain.Reconstitute("fl-9", cve(t, "CVE-2024-9"), []domain.Proposal{p}, view, domain.StageCorrelated, 5)
	if f.ID() != "fl-9" || f.Stage() != domain.StageCorrelated || f.Version() != 5 {
		t.Errorf("reconstituted = %+v", f)
	}
	if len(f.Proposals()) != 1 || f.View().Severity != value.SeverityHigh {
		t.Errorf("reconstituted state wrong: %+v", f.View())
	}
}
