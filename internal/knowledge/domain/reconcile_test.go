package domain_test

import (
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

func exploit(t *testing.T, source string, at time.Time, epss float64, kev, pub bool) domain.Proposal {
	t.Helper()
	p, err := domain.NewExploitSignalProposal(source, at, domain.ExploitSignal{EPSS: epss, KEV: kev, ExploitPublic: pub})
	if err != nil {
		t.Fatalf("exploit proposal: %v", err)
	}
	return p
}

func applic(t *testing.T, source, pkg, status string) domain.Proposal {
	t.Helper()
	p, err := domain.NewApplicabilityProposal(source, obs, domain.Applicability{Package: pkg, Status: status})
	if err != nil {
		t.Fatalf("applicability proposal: %v", err)
	}
	return p
}

func TestReconcile_Precedence(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")

	// Higher-authority source wins the headline severity (not worst-case).
	v := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "osv", value.SeverityCritical),
		vulnFacts(t, "nvd", value.SeverityMedium),
		vulnFacts(t, "redhat", value.SeverityLow),
	}, prec)
	if v.Severity != value.SeverityLow || v.SeveritySource != "redhat" {
		t.Errorf("precedence: got %s from %s, want low from redhat", v.Severity, v.SeveritySource)
	}

	// Unlisted sources share the lowest rank; a full tie (same severity + score) breaks
	// on source name (lexical), deterministically.
	v2 := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "zvendor", value.SeverityHigh),
		vulnFacts(t, "avendor", value.SeverityHigh),
	}, prec)
	if v2.SeveritySource != "avendor" {
		t.Errorf("tiebreak: got %s, want avendor (lexical)", v2.SeveritySource)
	}

	// Same rank + same time → higher severity wins the tie (deterministic).
	v4 := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "zvendor", value.SeverityHigh),
		vulnFacts(t, "avendor", value.SeverityMedium),
	}, prec)
	if v4.Severity != value.SeverityHigh || v4.SeveritySource != "zvendor" {
		t.Errorf("higher-severity tiebreak: got %s from %s, want high from zvendor", v4.Severity, v4.SeveritySource)
	}

	// SeverityUnknown proposals never win the headline.
	v3 := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "redhat", value.SeverityUnknown),
		vulnFacts(t, "nvd", value.SeverityHigh),
	}, prec)
	if v3.Severity != value.SeverityHigh || v3.SeveritySource != "nvd" {
		t.Errorf("unknown-severity should not win: %+v", v3)
	}
}

func TestReconcile_UnionAndSignals(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	older := time.Unix(1_600_000_000, 0)
	newer := time.Unix(1_700_000_000, 0)

	withFixes, err := domain.NewVulnFactsProposal("nvd", obs, domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: mustCVSS(t, 7.5), FixedVersions: []string{"3.0.11", "2.0.9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "nvd", value.SeverityHigh, "<2.0", "<3.0"),
		vulnFacts(t, "osv", value.SeverityMedium, "<3.0", "<4.0"),
		withFixes,
		exploit(t, "kev", older, 0.1, true, false),
		exploit(t, "epss", newer, 0.7, false, true),
	}, prec)

	if got := v.AffectedRanges; len(got) != 3 || got[0] != "<2.0" || got[2] != "<4.0" {
		t.Errorf("ranges union not sorted/deduped: %v", got)
	}
	if got := v.FixedVersions; len(got) != 2 || got[0] != "2.0.9" || got[1] != "3.0.11" {
		t.Errorf("fixed-versions union not sorted: %v", got)
	}
	if !v.KEV || !v.ExploitPublic {
		t.Errorf("signals OR: KEV=%v pub=%v", v.KEV, v.ExploitPublic)
	}
	if v.EPSS != 0.7 {
		t.Errorf("EPSS latest = %v, want 0.7", v.EPSS)
	}

	// Equal timestamps → higher EPSS wins (deterministic).
	v2 := domain.Reconcile([]domain.Proposal{
		exploit(t, "a", newer, 0.2, false, false),
		exploit(t, "b", newer, 0.9, false, false),
	}, prec)
	if v2.EPSS != 0.9 {
		t.Errorf("EPSS equal-time tiebreak = %v, want 0.9", v2.EPSS)
	}
}

func TestReconcile_ApplicabilityAndEmpty(t *testing.T) {
	prec := domain.NewPrecedence()

	justified := func(pkg, status, why string) domain.Proposal {
		p, err := domain.NewApplicabilityProposal("redhat", obs, domain.Applicability{Package: pkg, Status: status, Justification: why})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	v := domain.Reconcile([]domain.Proposal{
		applic(t, "redhat", "openssl", "not_affected"),
		applic(t, "redhat", "openssl", "not_affected"), // exact duplicate → deduped
		applic(t, "alpine", "zlib", "affected"),
		// Same package + status, different justification → not deduped; sorts by justification.
		justified("curl", "affected", "reason-b"),
		justified("curl", "affected", "reason-a"),
	}, prec)
	if len(v.Applicabilities) != 4 {
		t.Fatalf("applicabilities = %d, want 4", len(v.Applicabilities))
	}
	if v.Applicabilities[0].Package != "curl" || v.Applicabilities[0].Justification != "reason-a" {
		t.Errorf("justification tiebreak not sorted: %+v", v.Applicabilities)
	}
	if v.Applicabilities[2].Package != "openssl" || v.Applicabilities[3].Package != "zlib" {
		t.Errorf("applicabilities not sorted by package: %+v", v.Applicabilities)
	}

	empty := domain.Reconcile(nil, prec)
	if empty.Severity != value.SeverityUnknown || empty.AffectedRanges != nil || empty.Applicabilities != nil {
		t.Errorf("empty reconcile = %+v", empty)
	}
}

// TestReconcile_OrderIndependent is the determinism property (D2): the same Proposals
// in any order reconcile to the same enterprise view.
func TestReconcile_OrderIndependent(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	rapid.Check(t, func(rt *rapid.T) {
		ps := genProposals(rt)
		want := domain.Reconcile(ps, prec)

		shuffled := append([]domain.Proposal(nil), ps...)
		for i := len(shuffled) - 1; i > 0; i-- {
			j := rapid.IntRange(0, i).Draw(rt, "swap")
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		got := domain.Reconcile(shuffled, prec)

		if !viewEqual(want, got) {
			rt.Fatalf("order-dependent view:\n want %+v\n got  %+v", want, got)
		}
	})
}

func genProposals(rt *rapid.T) []domain.Proposal {
	sources := []string{"redhat", "nvd", "osv", "zvendor", "ai-cap"}
	severities := []value.Severity{
		value.SeverityUnknown, value.SeverityLow, value.SeverityMedium, value.SeverityHigh, value.SeverityCritical,
	}
	n := rapid.IntRange(0, 6).Draw(rt, "n")
	ps := make([]domain.Proposal, 0, n)
	for i := 0; i < n; i++ {
		src := rapid.SampledFrom(sources).Draw(rt, "src")
		switch rapid.IntRange(0, 2).Draw(rt, "kind") {
		case 0:
			sev := rapid.SampledFrom(severities).Draw(rt, "sev")
			score := rapid.Float64Range(0, 10).Draw(rt, "score")
			cvss, _ := value.NewCVSS(score, "")
			rngs := rapid.SliceOfN(rapid.SampledFrom([]string{"<1.0", "<2.0", "<3.0"}), 0, 3).Draw(rt, "rng")
			p, _ := domain.NewVulnFactsProposal(src, obs, domain.VulnFacts{Severity: sev, CVSS: cvss, AffectedRanges: rngs})
			ps = append(ps, p)
		case 1:
			epss := rapid.Float64Range(0, 1).Draw(rt, "epss")
			p, _ := domain.NewExploitSignalProposal(src, obs,
				domain.ExploitSignal{EPSS: epss, KEV: rapid.Bool().Draw(rt, "kev"), ExploitPublic: rapid.Bool().Draw(rt, "pub")})
			ps = append(ps, p)
		default:
			pkg := rapid.SampledFrom([]string{"openssl", "zlib"}).Draw(rt, "pkg")
			status := rapid.SampledFrom([]string{"affected", "not_affected"}).Draw(rt, "status")
			p, _ := domain.NewApplicabilityProposal(src, obs, domain.Applicability{Package: pkg, Status: status})
			ps = append(ps, p)
		}
	}
	return ps
}

func viewEqual(a, b domain.EnterpriseView) bool {
	if a.Severity != b.Severity || a.CVSS != b.CVSS || a.SeveritySource != b.SeveritySource ||
		a.EPSS != b.EPSS || a.KEV != b.KEV || a.ExploitPublic != b.ExploitPublic {
		return false
	}
	if len(a.AffectedRanges) != len(b.AffectedRanges) || len(a.FixedVersions) != len(b.FixedVersions) ||
		len(a.Applicabilities) != len(b.Applicabilities) {
		return false
	}
	for i := range a.AffectedRanges {
		if a.AffectedRanges[i] != b.AffectedRanges[i] {
			return false
		}
	}
	for i := range a.FixedVersions {
		if a.FixedVersions[i] != b.FixedVersions[i] {
			return false
		}
	}
	for i := range a.Applicabilities {
		if a.Applicabilities[i] != b.Applicabilities[i] {
			return false
		}
	}
	return true
}
