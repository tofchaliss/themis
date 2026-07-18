package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func TestKnowledgeEvents(t *testing.T) {
	at := time.Unix(1_700_000_500, 0)
	prec := domain.NewPrecedence("nvd")
	f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec)
	f.FoldProposal(exploit(t, "kev", at, 0.3, true, true), prec)

	created := domain.NewFaultlineCreated(f, at)
	if created.FaultlineID != "fl-1" || created.CVE != "CVE-2024-1" || !created.OccurredAt.Equal(at.UTC()) {
		t.Errorf("created = %+v", created)
	}

	enriched := domain.NewFaultlineEnriched(f, at)
	if enriched.Severity != value.SeverityHigh || !enriched.KEV || !enriched.ExploitPublic {
		t.Errorf("enriched snapshot = %+v", enriched)
	}

	if m := domain.NewFaultlineMatured(f, at); m.CVE != "CVE-2024-1" {
		t.Errorf("matured = %+v", m)
	}
	if s := domain.NewFaultlineSuperseded(f, at); s.FaultlineID != "fl-1" {
		t.Errorf("superseded = %+v", s)
	}

	comps := []domain.MatchedComponent{{PURL: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}}
	matched := domain.NewComponentMatched(f, "rel-1", comps, at)
	if matched.ReleaseID != "rel-1" || matched.CVE != "CVE-2024-1" || len(matched.Components) != 1 {
		t.Errorf("component matched = %+v", matched)
	}
	// Defensive copy: mutating the caller's slice must not change the event.
	comps[0].Name = "mutated"
	if matched.Components[0].Name == "mutated" {
		t.Error("NewComponentMatched did not defensively copy components")
	}
}
