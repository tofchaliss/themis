package domain_test

import (
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
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
	}, prec, domain.NewTrustPolicy(nil))
	if v.Severity != value.SeverityLow || v.SeveritySource != "redhat" {
		t.Errorf("precedence: got %s from %s, want low from redhat", v.Severity, v.SeveritySource)
	}

	// Unlisted sources share the lowest rank; a full tie (same severity + score) breaks
	// on source name (lexical), deterministically.
	v2 := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "zvendor", value.SeverityHigh),
		vulnFacts(t, "avendor", value.SeverityHigh),
	}, prec, domain.NewTrustPolicy(nil))
	if v2.SeveritySource != "avendor" {
		t.Errorf("tiebreak: got %s, want avendor (lexical)", v2.SeveritySource)
	}

	// Same rank + same time → higher severity wins the tie (deterministic).
	v4 := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "zvendor", value.SeverityHigh),
		vulnFacts(t, "avendor", value.SeverityMedium),
	}, prec, domain.NewTrustPolicy(nil))
	if v4.Severity != value.SeverityHigh || v4.SeveritySource != "zvendor" {
		t.Errorf("higher-severity tiebreak: got %s from %s, want high from zvendor", v4.Severity, v4.SeveritySource)
	}

	// SeverityUnknown proposals never win the headline.
	v3 := domain.Reconcile([]domain.Proposal{
		vulnFacts(t, "redhat", value.SeverityUnknown),
		vulnFacts(t, "nvd", value.SeverityHigh),
	}, prec, domain.NewTrustPolicy(nil))
	if v3.Severity != value.SeverityHigh || v3.SeveritySource != "nvd" {
		t.Errorf("unknown-severity should not win: %+v", v3)
	}
}

func TestReconcile_UnionAndSignals(t *testing.T) {
	prec := domain.NewPrecedence("nvd")
	older := time.Unix(1_600_000_000, 0)
	newer := time.Unix(1_700_000_000, 0)

	withFixes, err := domain.NewVulnFactsProposal("nvd", obs, domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: mustCVSS(t, 7.5), Fixes: domain.UnattributedFixes([]string{"3.0.11", "2.0.9"}),
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
	}, prec, domain.NewTrustPolicy(nil))

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
	}, prec, domain.NewTrustPolicy(nil))
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
	}, prec, domain.NewTrustPolicy(nil))
	if len(v.Applicabilities) != 4 {
		t.Fatalf("applicabilities = %d, want 4", len(v.Applicabilities))
	}
	if v.Applicabilities[0].Package != "curl" || v.Applicabilities[0].Justification != "reason-a" {
		t.Errorf("justification tiebreak not sorted: %+v", v.Applicabilities)
	}
	if v.Applicabilities[2].Package != "openssl" || v.Applicabilities[3].Package != "zlib" {
		t.Errorf("applicabilities not sorted by package: %+v", v.Applicabilities)
	}

	empty := domain.Reconcile(nil, prec, domain.NewTrustPolicy(nil))
	if empty.Severity != value.SeverityUnknown || empty.AffectedRanges != nil || empty.Applicabilities != nil {
		t.Errorf("empty reconcile = %+v", empty)
	}
}

// TestReconcile_OrderIndependentProperty is the determinism property (D2): the same Proposals
// in any order reconcile to the same enterprise view.
//
// The name must end in `Property` — `make test-property` selects with `-run 'Property|Prop_'`,
// so a rapid test named otherwise runs ONLY at rapid's default 100 examples under `make test`
// and never in the deep nightly run. This one was missed by that convention until 2026-08-07,
// which meant the single most important invariant in Knowledge was excluded from every 1000-,
// 5000- and 20000-example sweep the project has ever done.
func TestReconcile_OrderIndependentProperty(t *testing.T) {
	prec := domain.NewPrecedence("redhat", "nvd", "osv")
	rapid.Check(t, func(rt *rapid.T) {
		ps := genProposals(rt)
		want := domain.Reconcile(ps, prec, domain.NewTrustPolicy(nil))

		shuffled := append([]domain.Proposal(nil), ps...)
		for i := len(shuffled) - 1; i > 0; i-- {
			j := rapid.IntRange(0, i).Draw(rt, "swap")
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}
		got := domain.Reconcile(shuffled, prec, domain.NewTrustPolicy(nil))

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

// FixesFor is what makes a fix actionable: it answers "what fixes MY component?" where the flat
// FixedVersions can only answer "is anything published?". The distinction is KN-FIX-1 — a union
// across every package a CVE affects, read as if it were about one of them, both misled
// operators and silently dropped 31 live vulnerabilities on one release.
func TestEnterpriseView_FixesForIsExactAndExcludesUnattributed(t *testing.T) {
	v := domain.Reconcile([]domain.Proposal{
		fixesProposal(t, "osv",
			domain.FixedVersion{Package: "glibc", Version: "0:2.28-251.el8_10.38"},
			domain.FixedVersion{Package: "perl-Carp", Version: "0:1.42-397.el8"},
			domain.FixedVersion{Version: "9.9.9"}, // unattributed
		),
	}, domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil))

	if got := v.FixesFor("glibc", "rpm"); len(got) != 1 || got[0] != "0:2.28-251.el8_10.38" {
		t.Fatalf("FixesFor(glibc) = %v, want only glibc's fix", got)
	}
	// Case-insensitive, because package names arrive from feeds with inconsistent casing.
	if got := v.FixesFor("GLIBC", "rpm"); len(got) != 1 {
		t.Errorf("FixesFor is case-sensitive; got %v", got)
	}
	// An UNATTRIBUTED fix is not a wildcard. "The source did not say which package" is not
	// evidence about any package, so it must never satisfy a per-component decision.
	if got := v.FixesFor("openssl", "rpm"); len(got) != 0 {
		t.Fatalf("FixesFor(openssl) = %v, want none — an unattributed fix must not match everything", got)
	}
	if got := v.FixesFor("", "rpm"); len(got) != 0 {
		t.Errorf("FixesFor(\"\") = %v, want none", got)
	}
	// The flat list still carries everything, including the unattributed one, for "is a fix
	// published?" — it just cannot be used to decide.
	if len(v.FixedVersions) != 3 {
		t.Errorf("FixedVersions = %v, want all 3 versions", v.FixedVersions)
	}
}

// fixesProposal builds a vuln-facts Proposal carrying explicitly attributed fixes.
func fixesProposal(t *testing.T, source string, fixes ...domain.FixedVersion) domain.Proposal {
	t.Helper()
	c, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, Fixes: fixes})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

// A change in the FIXES is a view change even when the flat version list is identical — the
// package attribution is part of what the card knows, and Governance re-evaluates on it.
func TestReconcile_FixAttributionChangeIsAViewChange(t *testing.T) {
	prec, pol := domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil)
	f, err := domain.NewFaultline("FL-1", cve(t, "CVE-2024-0001"))
	if err != nil {
		t.Fatalf("NewFaultline: %v", err)
	}
	f.FoldProposal(fixesProposal(t, "osv", domain.FixedVersion{Version: "1.0"}), prec, pol)
	// Same version, now attributed. The flat list is unchanged; the card's knowledge is not.
	res := f.FoldProposal(fixesProposal(t, "osv", domain.FixedVersion{Package: "glibc", Version: "1.0"}), prec, pol)
	if !res.ViewChanged {
		t.Fatal("expected ViewChanged: a fix gaining its package changes what the card can decide")
	}
}

// A fix set that differs only in LENGTH is still a different view — the short-circuit in
// equalFixes must not report equality just because the shared prefix matches.
func TestReconcile_FixCountChangeIsAViewChange(t *testing.T) {
	prec, pol := domain.NewPrecedence("osv"), domain.NewTrustPolicy(nil)
	f, err := domain.NewFaultline("FL-1", cve(t, "CVE-2024-0001"))
	if err != nil {
		t.Fatalf("NewFaultline: %v", err)
	}
	f.FoldProposal(fixesProposal(t, "osv", domain.FixedVersion{Package: "glibc", Version: "1.0"}), prec, pol)
	res := f.FoldProposal(fixesProposal(t, "osv",
		domain.FixedVersion{Package: "glibc", Version: "1.0"},
		domain.FixedVersion{Package: "glibc", Version: "2.0"}), prec, pol)
	if !res.ViewChanged {
		t.Fatal("expected ViewChanged: a second published fix is new knowledge")
	}
}

// KN-MODULE-1: when a card holds both a direct fix and a module-stream rebuild for the same
// package, the direct fix is offered first — "upgrade python3-ply to 3.11-10" beats "rebuild the
// python39 module" as an instruction. Neither is dropped: the module rebuild is valid remediation
// on a modular system, and the fixed-verdict engine needs the full set.
func TestFixesFor_PrefersADirectFixOverAModuleStreamRebuild(t *testing.T) {
	v := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "python-ply", Version: "0:3.11-10.module+el8.10.0+1582+bc278001"},
		{Package: "python-ply", Version: "0:3.11-11.el8"},
		{Package: "python-ply", Version: "0:3.11-10.module+el8.9.0+1418+f0d66789"},
		{Package: "PyYAML", Version: "0:5.4.1-1.el8"},
	}}
	got := v.FixesFor("python-ply", "rpm")
	if len(got) != 3 {
		t.Fatalf("FixesFor = %v, want all three python-ply fixes — none may be dropped", got)
	}
	if got[0] != "0:3.11-11.el8" {
		t.Errorf("first fix = %q, want the direct 0:3.11-11.el8 — a consumer showing one row shows this", got[0])
	}
}

// StrictFixesFor is the verdict-grade selection (EDR-VEX-01 D9): only positively-stamped
// bounds qualify. The fixture is the measured KN-FIX-3 shared card — an apk bound, an
// UNSTAMPED rpm NEVRA, and a foreign-stamped fix on one CVE. Fail-open FixesFor returns
// the unstamped one too (display must never hide a fix); the strict selection must not,
// or the max-bound verdict would be silently blocked forever on every shared card.
func TestStrictFixesFor_OnlyPositivelyStampedBoundsQualify(t *testing.T) {
	v := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "perl", Version: "5.30.3-r0", Ecosystem: "apk"},
		{Package: "perl", Version: "perl-4:5.26.3-419.el8"}, // unstamped: neither proves nor blocks
		{Package: "perl", Version: "4:5.16.3-299.el7_9", Ecosystem: "rpm"},
		{Package: "openssl", Version: "3.1.4-r5", Ecosystem: "apk"}, // other package never answers
	}}
	got := v.StrictFixesFor("perl", "apk")
	if len(got) != 1 || got[0] != "5.30.3-r0" {
		t.Fatalf("StrictFixesFor(perl, apk) = %v, want exactly the stamped apk bound", got)
	}
	if got := v.StrictFixesFor("perl", "alpine"); len(got) != 1 {
		t.Fatalf("feed ecosystem name must canonicalize (alpine→apk), got %v", got)
	}
	if got := v.StrictFixesFor("perl", "rpm"); len(got) != 1 || got[0] != "4:5.16.3-299.el7_9" {
		t.Fatalf("StrictFixesFor(perl, rpm) = %v, want exactly the stamped rpm fix", got)
	}
}

// No positive identity on either side → no verdict-grade evidence at all.
func TestStrictFixesFor_UnknownEcosystemOrBlankPackageAnswersNothing(t *testing.T) {
	v := domain.EnterpriseView{Fixes: []domain.FixedVersion{
		{Package: "perl", Version: "5.30.3-r0", Ecosystem: "apk"},
	}}
	if got := v.StrictFixesFor("perl", ""); got != nil {
		t.Fatalf("unknown component ecosystem must select nothing, got %v", got)
	}
	if got := v.StrictFixesFor("  ", "apk"); got != nil {
		t.Fatalf("blank package must select nothing, got %v", got)
	}
	if got := v.StrictFixesFor("PERL", "apk"); len(got) != 1 {
		t.Fatalf("package match stays case-insensitive like FixesFor, got %v", got)
	}
}

// Carrier products are a UNION across flaw-describing sources, and blanks are dropped.
//
// Union is the fail-safe direction: a carrier named by ANY source keeps its components classified
// as carriers, so a source that is silent about attribution can never demote one to `scope`
// (EDR-CORRELATION-01 D4).
func TestReconcileUnionsCarrierProducts(t *testing.T) {
	at := time.Unix(1_700_000_000, 0).UTC()
	mk := func(src string, carriers ...string) domain.Proposal {
		p, err := domain.NewVulnFactsProposal(src, at, domain.VulnFacts{
			Severity: value.SeverityHigh, CarrierProducts: carriers,
		})
		if err != nil {
			t.Fatalf("proposal: %v", err)
		}
		return p
	}
	v := domain.Reconcile([]domain.Proposal{
		mk("nvd", "pyyaml", "  "), // a blank must not become a carrier
		mk("osv", "urllib3", "pyyaml"),
	}, domain.NewPrecedence("nvd", "osv"), domain.NewTrustPolicy(nil))

	if len(v.CarrierProducts) != 2 {
		t.Fatalf("CarrierProducts = %v, want the two real names, deduped and blank-free", v.CarrierProducts)
	}
	// Sorted, so a card renders and diffs deterministically.
	if v.CarrierProducts[0] != "pyyaml" || v.CarrierProducts[1] != "urllib3" {
		t.Errorf("CarrierProducts = %v, want [pyyaml urllib3]", v.CarrierProducts)
	}
	// No source naming a carrier ⇒ empty ⇒ every component classifies as unknown ⇒ carrier.
	bare := domain.Reconcile([]domain.Proposal{mk("nvd")}, domain.NewPrecedence("nvd", "osv"), domain.NewTrustPolicy(nil))
	if len(bare.CarrierProducts) != 0 {
		t.Errorf("CarrierProducts = %v, want empty when nobody attributes", bare.CarrierProducts)
	}
}

// The measured KN-FIX-3 card (CVE-2020-10543): Red Hat states fixes as full NEVRAs, OSV as bare
// EVRs, and D7's Alpine feed adds an apk bound — one Rocky perl drawer rendered FOUR fixes,
// three wrong for it. Reconciliation must (a) collapse the two rpm normalizations of the SAME
// fix into one entry, and (b) let FixesFor answer per ecosystem.
func TestReconcile_OneNEVRANormalizationAndEcosystemScoping(t *testing.T) {
	v := domain.Reconcile([]domain.Proposal{
		fixesProposal(t, "redhat",
			domain.FixedVersion{Package: "perl", Version: "perl-4:5.26.3-419.el8", Ecosystem: "rpm"},
			domain.FixedVersion{Package: "perl", Version: "perl-4:5.16.3-299.el7_9", Ecosystem: "rpm"},
		),
		fixesProposal(t, "osv",
			domain.FixedVersion{Package: "perl", Version: "4:5.26.3-419.el8", Ecosystem: "rpm"},
		),
		fixesProposal(t, "alpine",
			domain.FixedVersion{Package: "perl", Version: "5.30.3-r0", Ecosystem: "apk"},
		),
	}, domain.NewPrecedence("redhat", "osv"), domain.NewTrustPolicy(nil))

	// 4 contributed forms, 3 real fixes: the Red Hat and OSV spellings of the EL8 fix are one.
	if len(v.Fixes) != 3 {
		t.Fatalf("Fixes = %v, want 3 — the two rpm forms of the EL8 fix must collapse", v.Fixes)
	}
	for _, f := range v.Fixes {
		if strings.HasPrefix(f.Version, "perl-") {
			t.Errorf("fix %v kept its name prefix — rpm versions must normalize through one path", f)
		}
	}
	if got := v.FixesFor("perl", "rpm"); len(got) != 2 {
		t.Errorf("FixesFor(perl, rpm) = %v, want the two rpm fixes and never the apk bound", got)
	}
	if got := v.FixesFor("perl", "apk"); len(got) != 1 || got[0] != "5.30.3-r0" {
		t.Errorf("FixesFor(perl, apk) = %v, want only the apk bound", got)
	}
	// An unknown COMPONENT ecosystem filters nothing — absence of evidence never hides a fix.
	if got := v.FixesFor("perl", ""); len(got) != 3 {
		t.Errorf("FixesFor(perl, \"\") = %v, want all 3", got)
	}
}

// The ecosystem merge is a SET, not a pairwise fold, so it is order-independent (D2): exactly one
// known ecosystem wins; conflicting known ones resolve to unknown (which filters nothing — fail
// open); a source that did not say never dilutes one that did.
func TestReconcile_FixEcosystemMergeIsOrderIndependent(t *testing.T) {
	known := fixesProposal(t, "redhat", domain.FixedVersion{Package: "foo", Version: "1.2.3-1", Ecosystem: "rpm"})
	unknown := fixesProposal(t, "nvd", domain.FixedVersion{Package: "foo", Version: "1.2.3-1"})
	conflicting := fixesProposal(t, "alpine", domain.FixedVersion{Package: "foo", Version: "1.2.3-1", Ecosystem: "apk"})
	prec, trust := domain.NewPrecedence("redhat"), domain.NewTrustPolicy(nil)

	for _, order := range [][]domain.Proposal{{known, unknown}, {unknown, known}} {
		v := domain.Reconcile(order, prec, trust)
		if len(v.Fixes) != 1 || v.Fixes[0].Ecosystem != "rpm" {
			t.Errorf("known+unknown → %v, want one fix carrying rpm", v.Fixes)
		}
	}
	for _, order := range [][]domain.Proposal{{known, conflicting}, {conflicting, known}} {
		v := domain.Reconcile(order, prec, trust)
		if len(v.Fixes) != 1 || v.Fixes[0].Ecosystem != "" {
			t.Errorf("conflicting ecosystems → %v, want one fix resolved to unknown", v.Fixes)
		}
	}
}
