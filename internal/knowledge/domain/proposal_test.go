package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

var obs = time.Unix(1_700_000_000, 0)

func mustCVSS(t *testing.T, score float64) value.CVSS {
	t.Helper()
	c, err := value.NewCVSS(score, "")
	if err != nil {
		t.Fatalf("cvss: %v", err)
	}
	return c
}

func TestProposalKind_Valid(t *testing.T) {
	for _, k := range []domain.ProposalKind{domain.KindVulnFacts, domain.KindExploitSignal, domain.KindApplicability} {
		if !k.Valid() {
			t.Errorf("%q should be valid", k)
		}
	}
	if domain.ProposalKind("bogus").Valid() {
		t.Error("bogus kind reported valid")
	}
}

func TestNewVulnFactsProposal(t *testing.T) {
	ranges := []string{"<3.0.11"}
	p, err := domain.NewVulnFactsProposal("nvd", obs, domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: mustCVSS(t, 7.5), AffectedRanges: ranges, FixedVersions: []string{"3.0.11"},
	})
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if p.Source() != "nvd" || p.Kind() != domain.KindVulnFacts || !p.ObservedAt().Equal(obs.UTC()) {
		t.Errorf("proposal = %+v", p)
	}
	f, ok := p.VulnFacts()
	if !ok || f.Severity != value.SeverityHigh || len(f.AffectedRanges) != 1 {
		t.Errorf("vuln facts = %+v ok=%v", f, ok)
	}
	// Defensive copy: mutating the caller's slice must not change the proposal.
	ranges[0] = "mutated"
	f2, _ := p.VulnFacts()
	if f2.AffectedRanges[0] == "mutated" {
		t.Error("VulnFacts did not defensively copy AffectedRanges")
	}
	// Wrong-kind accessors return false.
	if _, ok := p.ExploitSignal(); ok {
		t.Error("ExploitSignal on a vuln-facts proposal should be false")
	}
	if _, ok := p.Applicability(); ok {
		t.Error("Applicability on a vuln-facts proposal should be false")
	}

	if _, err := domain.NewVulnFactsProposal("", obs, domain.VulnFacts{Severity: value.SeverityHigh}); err == nil {
		t.Error("empty source: expected error")
	}
	if _, err := domain.NewVulnFactsProposal("nvd", time.Time{}, domain.VulnFacts{Severity: value.SeverityHigh}); err == nil {
		t.Error("zero time: expected error")
	}
	if _, err := domain.NewVulnFactsProposal("nvd", obs, domain.VulnFacts{Severity: value.Severity("bogus")}); err == nil {
		t.Error("invalid severity: expected error")
	}
}

func TestNewExploitSignalProposal(t *testing.T) {
	p, err := domain.NewExploitSignalProposal("kev", obs, domain.ExploitSignal{EPSS: 0.4, KEV: true})
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	s, ok := p.ExploitSignal()
	if !ok || s.EPSS != 0.4 || !s.KEV {
		t.Errorf("exploit signal = %+v ok=%v", s, ok)
	}
	if _, ok := p.VulnFacts(); ok {
		t.Error("VulnFacts on an exploit proposal should be false")
	}

	for name, epss := range map[string]float64{"negative": -0.1, "tooHigh": 1.1} {
		if _, err := domain.NewExploitSignalProposal("epss", obs, domain.ExploitSignal{EPSS: epss}); err == nil {
			t.Errorf("%s EPSS: expected error", name)
		}
	}
	if _, err := domain.NewExploitSignalProposal("", obs, domain.ExploitSignal{}); err == nil {
		t.Error("empty source: expected error")
	}
}

func TestNewApplicabilityProposal(t *testing.T) {
	p, err := domain.NewApplicabilityProposal("redhat", obs, domain.Applicability{Package: "openssl", Status: "not_affected", Justification: "not compiled"})
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	a, ok := p.Applicability()
	if !ok || a.Package != "openssl" || a.Status != "not_affected" {
		t.Errorf("applicability = %+v ok=%v", a, ok)
	}

	for name, app := range map[string]domain.Applicability{
		"emptyPackage": {Package: "", Status: "affected"},
		"emptyStatus":  {Package: "openssl", Status: ""},
	} {
		if _, err := domain.NewApplicabilityProposal("redhat", obs, app); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := domain.NewApplicabilityProposal("", obs, domain.Applicability{Package: "p", Status: "affected"}); err == nil {
		t.Error("empty source: expected error")
	}
}
