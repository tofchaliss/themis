package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
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

func exploitSignal(t *testing.T, source string, epss float64) domain.Proposal {
	t.Helper()
	p, err := domain.NewExploitSignalProposal(source, obs, domain.ExploitSignal{EPSS: epss})
	if err != nil {
		t.Fatalf("exploit signal proposal: %v", err)
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
	if r := f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"), prec, domain.NewTrustPolicy(nil)); !r.ViewChanged {
		t.Error("first fold should change the view")
	}
	if f.Stage() != domain.StageEnriched || f.Version() != 1 {
		t.Errorf("after first fold: stage=%s version=%d", f.Stage(), f.Version())
	}
	if f.View().Severity != value.SeverityHigh || f.View().SeveritySource != "nvd" {
		t.Errorf("view = %+v", f.View())
	}

	// A source restating itself verbatim is NOT recorded (KN-PROPOSAL-BLOAT-1). This test
	// previously asserted the opposite — that every fold appends "for audit" — and that reading
	// produced 28,128 exploit-signal Proposals across 239 cards holding 221 distinct payloads.
	//
	// Append-only is intact: nothing is ever mutated or removed, and every DISTINCT value a
	// source has ever reported is still kept in order. What is dropped is a restatement carrying
	// no information but a timestamp.
	//
	// The cost, stated plainly: the card no longer records "we re-confirmed this at T2". That
	// question is answered per-source by `feed_health.last_success_at`, and since feeds are
	// relevance-bounded (D5 — a sweep visits every carded CVE together), per-source is a faithful
	// proxy for per-card. It is a real, small loss taken deliberately.
	if r := f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh, "<3.0"), prec, domain.NewTrustPolicy(nil)); r.ViewChanged {
		t.Error("duplicate fold should not change the view")
	}
	if len(f.Proposals()) != 1 || f.Version() != 1 {
		t.Errorf("a verbatim restatement must not be appended: proposals=%d version=%d", len(f.Proposals()), f.Version())
	}

	// A higher-authority source overrides the headline severity.
	if r := f.FoldProposal(vulnFacts(t, "redhat", value.SeverityCritical), prec, domain.NewTrustPolicy(nil)); !r.ViewChanged {
		t.Error("higher-authority fold should change the view")
	}
	if f.View().Severity != value.SeverityCritical || f.View().SeveritySource != "redhat" {
		t.Errorf("redhat should win: %+v", f.View())
	}
}

func TestLifecycleLadder(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, domain.NewTrustPolicy(nil)) // → Enriched

	if !f.MarkCorrelated() || f.Stage() != domain.StageCorrelated {
		t.Errorf("MarkCorrelated: stage=%s", f.Stage())
	}
	// Folding after Correlated must not regress the stage.
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, domain.NewTrustPolicy(nil))
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
	f.FoldProposal(vulnFacts(t, "nvd", value.SeverityLow), prec, domain.NewTrustPolicy(nil)) // still recorded, stage frozen
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
	view := domain.Reconcile([]domain.Proposal{p}, prec, domain.NewTrustPolicy(nil))

	f := domain.Reconstitute("fl-9", cve(t, "CVE-2024-9"), []domain.Proposal{p}, view, domain.StageCorrelated, 5)
	if f.ID() != "fl-9" || f.Stage() != domain.StageCorrelated || f.Version() != 5 {
		t.Errorf("reconstituted = %+v", f)
	}
	if len(f.Proposals()) != 1 || f.View().Severity != value.SeverityHigh {
		t.Errorf("reconstituted state wrong: %+v", f.View())
	}
}

// The dedup must not eat real history. These are the cases where a repeat IS an observation.
func TestFoldProposal_DedupPreservesGenuineHistory(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	pol := domain.NewTrustPolicy(nil)

	// A value that changes and later changes BACK is two genuine observations. Comparing against
	// the LATEST proposal from that source (not against any historical one) is what preserves it;
	// a "have I ever seen this payload" check would silently drop the return to 0.27.
	t.Run("a value that returns to an earlier one is recorded again", func(t *testing.T) {
		f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
		f.FoldProposal(exploitSignal(t, "epsskev", 0.27), prec, pol)
		f.FoldProposal(exploitSignal(t, "epsskev", 0.29), prec, pol)
		f.FoldProposal(exploitSignal(t, "epsskev", 0.27), prec, pol)
		if len(f.Proposals()) != 3 {
			t.Errorf("proposals = %d, want 3 — 0.27 → 0.29 → 0.27 is three observations, not two", len(f.Proposals()))
		}
	})

	// Two sources agreeing is corroboration — the substance of the precedence rule — and must
	// never be collapsed into one voice.
	t.Run("an identical payload from a DIFFERENT source is recorded", func(t *testing.T) {
		f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
		f.FoldProposal(exploitSignal(t, "epsskev", 0.27), prec, pol)
		f.FoldProposal(exploitSignal(t, "osv", 0.27), prec, pol)
		if len(f.Proposals()) != 2 {
			t.Errorf("proposals = %d, want 2 — corroboration from a second source is not a duplicate", len(f.Proposals()))
		}
	})

	// Only the same KIND collides. A source that reports facts and signals contributes both.
	t.Run("a different kind from the same source is recorded", func(t *testing.T) {
		f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
		f.FoldProposal(vulnFacts(t, "nvd", value.SeverityHigh), prec, pol)
		f.FoldProposal(exploitSignal(t, "nvd", 0.27), prec, pol)
		if len(f.Proposals()) != 2 {
			t.Errorf("proposals = %d, want 2 — facts and signals are different observations", len(f.Proposals()))
		}
	})

	// The suppression is only against the latest of the SAME source, so an interleaved third
	// party does not make a genuine duplicate look new.
	t.Run("an interleaved other source does not un-suppress a duplicate", func(t *testing.T) {
		f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
		f.FoldProposal(exploitSignal(t, "epsskev", 0.27), prec, pol)
		f.FoldProposal(exploitSignal(t, "osv", 0.99), prec, pol)
		f.FoldProposal(exploitSignal(t, "epsskev", 0.27), prec, pol)
		if len(f.Proposals()) != 2 {
			t.Errorf("proposals = %d, want 2 — epsskev repeated itself, osv in between is irrelevant", len(f.Proposals()))
		}
	})
}

// sameContentAs must never suppress what it cannot prove identical: a dropped observation is
// unrecoverable, a duplicate is merely waste. These are the payload shapes that must fall through
// to "different" rather than being collapsed.
func TestFoldProposal_DedupNeverSuppressesWhatItCannotCompare(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	pol := domain.NewTrustPolicy(nil)

	t.Run("applicability statements compare by content", func(t *testing.T) {
		f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
		f.FoldProposal(applicability(t, "redhat", "openssl", "not_affected"), prec, pol)
		f.FoldProposal(applicability(t, "redhat", "openssl", "not_affected"), prec, pol)
		if len(f.Proposals()) != 1 {
			t.Errorf("proposals = %d, want 1 — an identical vendor statement is a restatement", len(f.Proposals()))
		}
		// A CHANGED statement is a real event: the vendor revised their position.
		f.FoldProposal(applicability(t, "redhat", "openssl", "affected"), prec, pol)
		if len(f.Proposals()) != 2 {
			t.Errorf("proposals = %d, want 2 — a vendor changing their statement is history", len(f.Proposals()))
		}
	})

	t.Run("differing fix attribution is a change", func(t *testing.T) {
		f, _ := domain.NewFaultline("fl-1", cve(t, "CVE-2024-1"))
		f.FoldProposal(vulnFactsWithFix(t, "osv", "python-ply", "0:3.11-10"), prec, pol)
		f.FoldProposal(vulnFactsWithFix(t, "osv", "python-ply", "0:3.11-11"), prec, pol)
		if len(f.Proposals()) != 2 {
			t.Errorf("proposals = %d, want 2 — a new fix version is a new fact", len(f.Proposals()))
		}
	})
}

func applicability(t *testing.T, source, pkg, status string) domain.Proposal {
	t.Helper()
	p, err := domain.NewApplicabilityProposal(source, obs, domain.Applicability{Package: pkg, Status: status})
	if err != nil {
		t.Fatalf("applicability proposal: %v", err)
	}
	return p
}

func vulnFactsWithFix(t *testing.T, source, pkg, version string) domain.Proposal {
	t.Helper()
	p, err := domain.NewVulnFactsProposal(source, obs, domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: mustCVSS(t, 7.5),
		Fixes: []domain.FixedVersion{{Package: pkg, Version: version}},
	})
	if err != nil {
		t.Fatalf("vuln facts proposal: %v", err)
	}
	return p
}
