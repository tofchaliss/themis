package domain_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestKnowledgeEvents(t *testing.T) {
	at := time.Unix(1_700_000_500, 0)
	prec := domain.NewPrecedence("nvd")
	f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, domain.NewTrustPolicy(nil))
	f.FoldProposal(exploit(t, "kev", at, 0.3, true, true), prec, domain.NewTrustPolicy(nil))

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
	if s := domain.NewFaultlineSuperseded(f, value.TrustObserved, at); s.FaultlineID != "fl-1" || s.Trust != value.TrustObserved {
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

// KN-SCAN-4(b): the retirement event carries the card's identity, the exact row, and a reason —
// and deliberately no superseded-by pointer, because the canonical row exists independently and
// needs no relationship to one that never denoted a distinct component.
func TestNewComponentRetired(t *testing.T) {
	f, err := domain.NewFaultline("fl-r", mustCVE(t, "CVE-2023-31122"))
	if err != nil {
		t.Fatalf("faultline: %v", err)
	}
	at := time.Date(2026, 9, 17, 12, 0, 0, 0, time.FixedZone("IST", 5*3600+1800))
	ev := domain.NewComponentRetired(f, "rel-1", "app:httpd@2.4.37", domain.RetiredDuplicateIdentity, at)

	if ev.FaultlineID != f.ID() || ev.CVE != "CVE-2023-31122" || ev.ReleaseID != "rel-1" {
		t.Errorf("event = %+v, want the card's identity and the release", ev)
	}
	if ev.PURL != "app:httpd@2.4.37" {
		t.Errorf("PURL = %q, want the exact row being retired", ev.PURL)
	}
	if ev.Reason != "duplicate_identity" {
		t.Errorf("reason = %q, want duplicate_identity", ev.Reason)
	}
	// UTC on the wire, like every other event here — a local zone would make two identical
	// facts compare unequal downstream.
	if ev.OccurredAt.Location() != time.UTC || !ev.OccurredAt.Equal(at) {
		t.Errorf("OccurredAt = %v, want the same instant in UTC", ev.OccurredAt)
	}
}
