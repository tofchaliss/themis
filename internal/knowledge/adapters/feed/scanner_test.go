package feed_test

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func TestScannerACL_Translate(t *testing.T) {
	r := feed.NewRegistry()
	out, err := r.Translate("scanner", golden(t, "scanner"))
	if err != nil {
		t.Fatalf("translate scanner: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d proposals, want 1", len(out))
	}
	if out[0].CVE.String() != "CVE-2024-5000" {
		t.Errorf("cve = %s", out[0].CVE.String())
	}
	if out[0].Proposal.Source() != "scanner" {
		t.Errorf("source = %s, want scanner", out[0].Proposal.Source())
	}
	vf, ok := out[0].Proposal.VulnFacts()
	if !ok || vf.Severity != value.SeverityHigh || vf.CVSS.Score() != 7.5 {
		t.Errorf("vuln facts = %+v ok=%v, want high/7.5", vf, ok)
	}
	if len(vf.FixedVersions) != 1 || vf.FixedVersions[0] != "2.0" {
		t.Errorf("fixed = %v", vf.FixedVersions)
	}
}

func TestScannerACL_HelpfulRejections(t *testing.T) {
	r := feed.NewRegistry()
	cases := map[string]string{
		"bad json": `{`,
		"no cve":   `{"cve":"not-a-cve","observed_at":"2026-07-20T00:00:00Z"}`,
		"bad time": `{"cve":"CVE-2024-5000","observed_at":"yesterday"}`,
	}
	for name, raw := range cases {
		if _, err := r.Translate("scanner", []byte(raw)); err == nil {
			t.Errorf("%s: expected a rejection", name)
		}
	}
}

// A scanner Proposal carries NO special authority: even when the scanner reports a newer,
// higher severity, a distro-authoritative source wins the reconciled headline by precedence
// (D2 / CON-0002). This is the guardrail that makes "honor scanner findings" safe.
func TestScannerACL_NoSpecialAuthority(t *testing.T) {
	r := feed.NewRegistry()
	// Scanner: critical + newer.
	scanOut, err := r.Translate("scanner", []byte(
		`{"cve":"CVE-2024-6000","observed_at":"2026-07-22T00:00:00Z","severity":"critical","cvss_score":9.9}`))
	if err != nil {
		t.Fatalf("translate scanner: %v", err)
	}
	// Distro (Rocky): high + older, but authoritative.
	rockyCVSS, _ := value.NewCVSS(8.0, "")
	rocky, err := domain.NewVulnFactsProposal("rocky", time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: rockyCVSS})
	if err != nil {
		t.Fatalf("build rocky proposal: %v", err)
	}

	// Precedence ranks the distro first; "scanner" is unlisted → lowest authority.
	prec := domain.NewPrecedence("rocky", "nvd")
	view := domain.Reconcile([]domain.Proposal{scanOut[0].Proposal, rocky}, prec)

	if view.Severity != value.SeverityHigh || view.SeveritySource != "rocky" {
		t.Errorf("headline = %s (source %q), want high (rocky) — the scanner must not win despite being newer/critical",
			view.Severity, view.SeveritySource)
	}
}
