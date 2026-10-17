package app_test

import (
	"fmt"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeInventory struct {
	inv app.Inventory
	err error
}

func (f fakeInventory) GetInventory(_ context.Context, _ string) (app.Inventory, error) {
	return f.inv, f.err
}

type fakeDiscovery struct {
	byPURL map[string][]app.ProposalFor
	err    error
}

func (f fakeDiscovery) VulnsForPackage(_ context.Context, c app.InventoryComponent) ([]app.ProposalFor, error) {
	return f.byPURL[c.PURL], f.err
}

type fakeMatches struct {
	recorded map[string]bool
	// byPURL keeps the first-recorded Match per component, so tests can assert what rode
	// the record (claim class, detection origin) and not merely that one happened.
	byPURL map[string]app.Match
	err    error
	calls  int
}

func newMatches() *fakeMatches {
	return &fakeMatches{recorded: map[string]bool{}, byPURL: map[string]app.Match{}}
}

func (f *fakeMatches) RecordMatch(_ context.Context, m app.Match) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	key := m.ReleaseID + "|" + string(m.FaultlineID) + "|" + m.Component.PURL
	if f.recorded[key] {
		return false, nil
	}
	f.recorded[key] = true
	f.byPURL[m.Component.PURL] = m
	return true, nil
}

func inventoryOf(purls ...string) app.Inventory {
	inv := app.Inventory{}
	for _, p := range purls {
		inv.Components = append(inv.Components, app.InventoryComponent{PURL: p})
	}
	return inv
}

func correlation(t *testing.T, inv app.InventoryReader, disc app.PackageVulnSource, matches app.MatchRecorder, repo app.Repository) *app.CorrelationService {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	return app.NewCorrelationService(inv, disc, fold, matches, fixedClock{})
}

func TestCorrelate_MatchesAndIdempotent(t *testing.T) {
	ctx := context.Background()
	inv := fakeInventory{inv: inventoryOf("pkg:deb/debian/openssl@3.0", "pkg:deb/debian/zlib@1.3")}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		"pkg:deb/debian/openssl@3.0": {{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "nvd", value.SeverityHigh)}},
		// zlib has no discovered vulns.
	}}
	matches := newMatches()
	repo := newRepo()
	s := correlation(t, inv, disc, matches, repo)

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 1 {
		t.Errorf("new matches = %d, want 1", n)
	}
	// The card was created by the fold.
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-1"); !found {
		t.Error("expected the folded faultline to exist")
	}
	// Every discovery-path match — the re-discovery sweep included, it runs through this same
	// Correlate — is stamped `discovery`, distinguishing it from a scanner's (KN-SCAN-2).
	if got := matches.byPURL["pkg:deb/debian/openssl@3.0"].DetectionOrigin; got != app.OriginDiscovery {
		t.Errorf("detection origin = %q, want %q", got, app.OriginDiscovery)
	}

	// Re-running records no new matches (idempotent).
	n2, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatal(err)
	}
	if n2 != 0 {
		t.Errorf("idempotent re-run new matches = %d, want 0", n2)
	}
}

func TestCorrelate_SkipsOutOfRange(t *testing.T) {
	ctx := context.Background()
	// The component's installed version (3.0) is provably OUTSIDE the reconciled affected range
	// (<2.0), so correlation must NOT record a match — Knowledge applies its own backport-aware
	// range knowledge (D3), catching what OSV's query-time filter would have admitted.
	comp := app.InventoryComponent{PURL: "pkg:pypi/urllib3@3.0", Name: "urllib3", Version: "3.0", Ecosystem: "pypi"}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		comp.PURL: {{CVE: cve(t, "CVE-2024-9"), Proposal: vulnFactsRanged(t, "nvd", ">=0,<2.0")}},
	}}
	matches := newMatches()
	repo := newRepo()
	s := correlation(t, inv, disc, matches, repo)

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 0 || matches.calls != 0 {
		t.Errorf("out-of-range component recorded a match (n=%d, RecordMatch calls=%d), want none", n, matches.calls)
	}
	// The card is still folded — the CVE is real intelligence; only THIS release's occurrence is
	// not affected. Correlation folds the Proposal before it gates the release-scoped match.
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-9"); !found {
		t.Error("expected the folded faultline to exist even though the component is out of range")
	}
}

// KN-GO-1 (measured 2026-10-14): the estate's Go programs carry `pkg:golang/stdlib@1.27.1` with
// the version spelled `go1.27.1`, the way the toolchain prints it. Against CVE-2022-30632's range
// (fixed 1.17.12 / 1.18.4) the prefix sorted below every digit, so 1.27.1 read as OLDER than
// 1.17.12 and a four-year-old, long-fixed flaw opened a Finding — and OSV, asked for `go1.27.1`,
// returned every stdlib advisory ever published. The range gate must read the number.
func TestCorrelate_GoStdlibToolchainSpellingIsOutOfRange(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{PURL: "pkg:golang/stdlib@1.27.1", Name: "stdlib", Version: "go1.27.1", Ecosystem: "golang"}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		comp.PURL: {{CVE: cve(t, "CVE-2022-30632"), Proposal: vulnFactsRanged(t, "osv", "<1.17.12", ">=1.18.0-0,<1.18.4")}},
	}}
	matches := newMatches()
	repo := newRepo()
	s := correlation(t, inv, disc, matches, repo)

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 0 || matches.calls != 0 {
		t.Errorf("go1.27.1 recorded a match against a range fixed in 1.17.12 (n=%d, calls=%d), want none", n, matches.calls)
	}
}

func TestCorrelate_RecordsRPMFixedAsCleared(t *testing.T) {
	ctx := context.Background()
	// The installed RHEL-8 build (release 17) is at/above the Red Hat RHEL-8 fix (release 16), so
	// it carries the backported fix. The occurrence IS recorded — "checked and fine" must be a
	// visible row, not silence (EDR-VERDICT-01 D2) — with an observed-grade clearance stating
	// its premise, and stamped with the card version it was judged against.
	comp := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/openssl@1.0.2k-17.el8_10", Name: "openssl",
		Version: "1.0.2k-17.el8_10", Ecosystem: "rhel",
	}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		comp.PURL: {{CVE: cve(t, "CVE-2024-11"), Proposal: vulnFactsFixed(t, "redhat", "openssl-1.0.2k-16.el8_10")}},
	}}
	matches := newMatches()
	repo := newRepo()
	s := correlation(t, inv, disc, matches, repo)

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 1 || matches.calls != 1 {
		t.Fatalf("a fixed occurrence must be RECORDED as cleared (n=%d, RecordMatch calls=%d)", n, matches.calls)
	}
	m := matches.byPURL[comp.PURL]
	if m.Verdict.State != domain.VerdictClearedVendorFix {
		t.Errorf("verdict state = %q, want cleared_vendor_fix", m.Verdict.State)
	}
	if m.Verdict.Grade != domain.VerdictGradeObserved {
		t.Errorf("verdict grade = %q, want observed — a direct version compare is direct evidence", m.Verdict.Grade)
	}
	if !strings.Contains(m.Verdict.Reason, "1.0.2k-16.el8_10") {
		t.Errorf("the clearance must name the bound it rests on, got %q", m.Verdict.Reason)
	}
	if m.CardVersion <= 0 {
		t.Errorf("CardVersion = %d, want the judged-against card version (> 0) for the re-verdict stamp", m.CardVersion)
	}
	// The card is still folded — the CVE is real intelligence; only THIS occurrence is fixed.
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-11"); !found {
		t.Error("expected the folded faultline to exist even though the component is fixed")
	}
}

// The apk analogue of the stream verdict (EDR-VEX-01 D9): installed at/above EVERY stamped apk
// bound → the branch's fix is present — recorded as a cleared occurrence (EDR-VERDICT-01 D2).
// The two bounds are two branches' fixes for one CVE — exactly the shape D7's cross-branch
// dedup produces.
func TestCorrelate_RecordsAPKFixedAsCleared(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{
		PURL: "pkg:apk/alpine/busybox@1.36.1-r0?distro=alpine-3.19", Name: "busybox",
		Version: "1.36.1-r0", Ecosystem: "apk",
	}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		comp.PURL: {{CVE: cve(t, "CVE-2024-21"), Proposal: vulnFactsFixedApk(t, "alpine", "busybox", "1.35.0-r10", "1.36.1-r0")}},
	}}
	matches := newMatches()
	repo := newRepo()
	s := correlation(t, inv, disc, matches, repo)

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 1 || matches.calls != 1 {
		t.Fatalf("a fixed apk occurrence must be RECORDED as cleared (n=%d, RecordMatch calls=%d)", n, matches.calls)
	}
	m := matches.byPURL[comp.PURL]
	if m.Verdict.State != domain.VerdictClearedVendorFix || m.Verdict.Grade != domain.VerdictGradeObserved {
		t.Errorf("verdict = %+v, want an observed-grade clearance", m.Verdict)
	}
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-21"); !found {
		t.Error("expected the folded faultline to exist even though the component is fixed")
	}
}

// The ownership bridge through the correlation door (EDR-VERDICT-01 D3/D4): the measured MRF
// shape — a pypi setuptools shadow beside its patched rpm on one inventory — clears at the
// INFERRED grade by default, and stays open when the operator arms strict mode. This is the
// service-level proof that the D4 switch actually reaches the judge.
func TestCorrelate_OwnershipBridgeAndStrictMode(t *testing.T) {
	ctx := context.Background()
	shadow := app.InventoryComponent{
		PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi",
	}
	rpm := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10", Name: "platform-python-setuptools",
		Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
	}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{shadow, rpm}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		shadow.PURL: {{CVE: cve(t, "CVE-2025-47273"), Proposal: vulnFactsFixedFor(t, "redhat", "python-setuptools", "0:39.2.0-9.el8_10")}},
	}}

	matches := newMatches()
	if _, err := correlation(t, inv, disc, matches, newRepo()).Correlate(ctx, "rel-1", "ev-1"); err != nil {
		t.Fatalf("correlate: %v", err)
	}
	m := matches.byPURL[shadow.PURL]
	if m.Verdict.State != domain.VerdictClearedVendorFix || m.Verdict.Grade != domain.VerdictGradeInferred {
		t.Errorf("default bridge: verdict = %+v, want an inferred clearance", m.Verdict)
	}

	strict := newMatches()
	if _, err := correlation(t, inv, disc, strict, newRepo()).WithInferredBridge(false).
		Correlate(ctx, "rel-1", "ev-1"); err != nil {
		t.Fatalf("strict correlate: %v", err)
	}
	if m := strict.byPURL[shadow.PURL]; !m.Verdict.State.IsOpen() {
		t.Errorf("strict mode: verdict = %+v, must stay open without explicit ownership evidence", m.Verdict)
	}
}

// The D9 busybox scenario: installed BETWEEN two branches' bounds must stay a match. "≥ any
// bound" would clear the v3.19 install with the v3.18 bound — the cross-branch false-"fixed"
// the max-bound rule exists to prevent.
func TestCorrelate_KeepsAPKBetweenBranchBounds(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{
		PURL: "pkg:apk/alpine/busybox@1.36.0-r2?distro=alpine-3.19", Name: "busybox",
		Version: "1.36.0-r2", Ecosystem: "apk",
	}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		comp.PURL: {{CVE: cve(t, "CVE-2024-22"), Proposal: vulnFactsFixedApk(t, "alpine", "busybox", "1.35.0-r10", "1.36.1-r0")}},
	}}
	matches := newMatches()
	s := correlation(t, inv, disc, matches, newRepo())

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 1 {
		t.Fatalf("recorded %d matches, want 1 — below one branch's bound means the fix may be missing here", n)
	}
}

// Fail-closed for verdicts (D9): a bound with no positive apk stamp — the shared-card shape —
// neither proves fixed nor blocks; with no stamped apk evidence the occurrence stays a match.
func TestCorrelate_APKVerdictNeverDecidesOnUnstampedBounds(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{
		PURL: "pkg:apk/alpine/perl@5.30.3-r0?distro=alpine-3.12", Name: "perl",
		Version: "5.30.3-r0", Ecosystem: "apk",
	}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		// An UNSTAMPED bound numerically below the install (vulnFactsFixedFor stamps nothing) —
		// under fail-open reading it would "prove" fixed; the strict selection must ignore it.
		comp.PURL: {{CVE: cve(t, "CVE-2024-23"), Proposal: vulnFactsFixedFor(t, "osv", "perl", "5.26.3")}},
	}}
	matches := newMatches()
	s := correlation(t, inv, disc, matches, newRepo())

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 1 {
		t.Fatalf("recorded %d matches, want 1 — an unstamped bound must never fire the apk verdict", n)
	}
}

// KN-FIX-1 regression. The fixed-verdict must use THIS item's own Proposal, never the card's
// reconciled FixedVersions — which is a union across every package the CVE affects, with no
// package association.
//
// Here glibc 2.28-251.el8_10.31 is genuinely vulnerable (its own fix is .38), but a SECOND
// package on the same card carries a lower same-stream fix (perl-Carp 1.42-397.el8). Reading the
// union, 2.28 clears 1.42, the verdict fires, and the glibc match is silently dropped — a false
// negative with no Finding, no log line and no metric. Reading the item's own Proposal, only
// glibc's fix is considered and the match survives.
func TestCorrelate_FixedVerdictIgnoresAnotherPackagesFix(t *testing.T) {
	ctx := context.Background()
	vulnerable := app.InventoryComponent{
		PURL: "pkg:rpm/rocky/glibc@2.28-251.el8_10.31", Name: "glibc",
		Version: "2.28-251.el8_10.31", Ecosystem: "rocky",
	}
	// A second component on the SAME CVE whose fix is numerically far below glibc's version.
	other := app.InventoryComponent{
		PURL: "pkg:rpm/rocky/perl-Carp@1.42-396.el8", Name: "perl-Carp",
		Version: "1.42-396.el8", Ecosystem: "rocky",
	}
	// ORDER MATTERS, and that is part of what makes the bug insidious: the card accumulates the
	// union as items fold, so the trap only springs for a component processed AFTER another
	// package's fix has landed on the card. perl-Carp folds first here.
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{other, vulnerable}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		// perl-Carp's fix lands on the card first and is the trap.
		other.PURL: {{CVE: cve(t, "CVE-2024-99"), Proposal: vulnFactsFixedFor(t, "osv", "perl-Carp", "0:1.42-397.el8")}},
		// glibc's own fix (.38) is ABOVE the installed .31 — still vulnerable.
		vulnerable.PURL: {{CVE: cve(t, "CVE-2024-99"), Proposal: vulnFactsFixedFor(t, "osv", "glibc", "0:2.28-251.el8_10.38")}},
	}}
	matches := newMatches()
	s := correlation(t, inv, disc, matches, newRepo())

	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	// Both occurrences are vulnerable and both must be recorded. Before the fix, glibc's match
	// was dropped by perl-Carp's fix version.
	if n != 2 {
		t.Fatalf("recorded %d matches, want 2 — a fix for a DIFFERENT package must never drop a live one", n)
	}
}

func TestCorrelate_Errors(t *testing.T) {
	ctx := context.Background()
	proposals := map[string][]app.ProposalFor{"p": {{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "nvd", value.SeverityHigh)}}}

	// Inventory read error.
	if _, err := correlation(t, fakeInventory{err: errors.New("boom")}, fakeDiscovery{}, newMatches(), newRepo()).
		Correlate(ctx, "rel", "ev"); err == nil {
		t.Error("inventory error: expected error")
	}
	// Discovery error.
	if _, err := correlation(t, fakeInventory{inv: inventoryOf("p")}, fakeDiscovery{err: errors.New("boom")}, newMatches(), newRepo()).
		Correlate(ctx, "rel", "ev"); err == nil {
		t.Error("discovery error: expected error")
	}
	// Fold error (repo save fails).
	badRepo := newRepo()
	badRepo.saveErr = errors.New("write failed")
	if _, err := correlation(t, fakeInventory{inv: inventoryOf("p")}, fakeDiscovery{byPURL: proposals}, newMatches(), badRepo).
		Correlate(ctx, "rel", "ev"); err == nil {
		t.Error("fold error: expected error")
	}
	// Match-record error.
	if _, err := correlation(t, fakeInventory{inv: inventoryOf("p")}, fakeDiscovery{byPURL: proposals}, &fakeMatches{recorded: map[string]bool{}, err: errors.New("boom")}, newRepo()).
		Correlate(ctx, "rel", "ev"); err == nil {
		t.Error("record error: expected error")
	}
}

func TestCoordinator_OnEvidenceRegistered(t *testing.T) {
	ctx := context.Background()
	inv := fakeInventory{inv: inventoryOf("p")}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{"p": {{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "nvd", value.SeverityHigh)}}}}
	matches := newMatches()
	coord := app.NewCoordinator(correlation(t, inv, disc, matches, newRepo()), nil)

	// A scanner-report (neither SBOM nor VEX) is ignored — it does not correlate. (VEX now has
	// its own apply path — see TestCoordinator_DispatchesByKind.)
	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{EvidenceID: "ev", ReleaseID: "rel", Kind: "scanner-report"}); err != nil {
		t.Fatalf("scanner-report: %v", err)
	}
	if matches.calls != 0 {
		t.Error("a non-SBOM/non-VEX kind should not correlate")
	}
	// SBOM evidence triggers correlation.
	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{EvidenceID: "ev", ReleaseID: "rel", Kind: "sbom"}); err != nil {
		t.Fatalf("sbom: %v", err)
	}
	if matches.calls == 0 {
		t.Error("SBOM should correlate")
	}
}

// TestCoordinator_SBOMReadErrorPropagates proves a failure in the correlation READ phase (the
// part now run outside the inbox transaction) surfaces from OnEvidenceRegistered — so the
// event is retried, and the inbox never opens a transaction for a read that failed.
func TestCoordinator_SBOMReadErrorPropagates(t *testing.T) {
	ctx := context.Background()
	coord := app.NewCoordinator(
		correlation(t, fakeInventory{err: errors.New("evidence down")}, fakeDiscovery{}, newMatches(), newRepo()), nil)
	if err := coord.OnEvidenceRegistered(ctx, app.EvidenceRegistered{EvidenceID: "ev", ReleaseID: "rel", Kind: "sbom"}); err == nil {
		t.Error("a read-phase (inventory) error must propagate from OnEvidenceRegistered")
	}
}

// componentPackage prefers the SOURCE package, because distro databases key on it (openssl-libs
// is fixed by the openssl advisory). Getting this wrong makes FixesFor match nothing and the
// fixed-verdict silently stop firing — a failure that looks like extra findings, not like a bug.
func TestCorrelate_FixedVerdictUsesTheSourcePackage(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/openssl-libs@1.0.2k-17.el8_10", Name: "openssl-libs",
		Version: "1.0.2k-17.el8_10", Ecosystem: "rhel", Source: "openssl",
	}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		// The fix is attributed to the SOURCE package, as a distro feed states it.
		comp.PURL: {{CVE: cve(t, "CVE-2024-12"), Proposal: vulnFactsFixedFor(t, "redhat", "openssl", "1.0.2k-16.el8_10")}},
	}}
	matches := newMatches()
	if n, err := correlation(t, inv, disc, matches, newRepo()).Correlate(ctx, "rel-1", "ev-1"); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v, want 1 recorded occurrence", n, err)
	}
	if m := matches.byPURL[comp.PURL]; m.Verdict.State != domain.VerdictClearedVendorFix {
		t.Errorf("verdict = %+v — the installed build carries the SOURCE package's fix and must be cleared", m.Verdict)
	}
}

// KN-SCAN-5: the hint is for the QUERY only. A distro purl with no `distro=` takes the release's
// distro from the first SBOM sibling that states one, else from its own namespace and EL
// marker; anything else is returned untouched.
func TestDiscoveryHint(t *testing.T) {
	rocky := []app.InventoryComponent{{PURL: "pkg:rpm/rocky/curl@7.61.1-34.el8_10?arch=x86_64&distro=rocky-8.10"}}
	cases := []struct {
		name string
		comp app.InventoryComponent
		sibs []app.InventoryComponent
		want string
	}{
		{"sibling distro", app.InventoryComponent{PURL: "pkg:rpm/redhat/binutils@2.30-128.el8_10", Version: "2.30-128.el8_10"}, rocky, "pkg:rpm/redhat/binutils@2.30-128.el8_10?distro=rocky-8.10"},
		{"namespace + el marker", app.InventoryComponent{PURL: "pkg:rpm/redhat/binutils@2.30-128.el8_10", Version: "2.30-128.el8_10"}, nil, "pkg:rpm/redhat/binutils@2.30-128.el8_10?distro=rhel-8"},
		{"rocky namespace", app.InventoryComponent{PURL: "pkg:rpm/rocky/httpd@2.4.37-65.module+el8.10.0+40257+286895ef.9?arch=x86_64", Version: "2.4.37-65.module+el8.10.0+40257+286895ef.9"}, nil, "pkg:rpm/rocky/httpd@2.4.37-65.module+el8.10.0+40257+286895ef.9?arch=x86_64&distro=rocky-8"},
		{"already qualified", app.InventoryComponent{PURL: "pkg:rpm/rocky/curl@1?distro=rocky-8.10", Version: "1"}, nil, "pkg:rpm/rocky/curl@1?distro=rocky-8.10"},
		{"not a distro purl", app.InventoryComponent{PURL: "pkg:golang/stdlib@1.27.1", Version: "go1.27.1"}, rocky, "pkg:golang/stdlib@1.27.1"},
		{"no marker, no sibling", app.InventoryComponent{PURL: "pkg:rpm/redhat/x@1", Version: "1"}, nil, "pkg:rpm/redhat/x@1"},
		{"unknown namespace", app.InventoryComponent{PURL: "pkg:rpm/suse/x@1-2.el8", Version: "1-2.el8"}, nil, "pkg:rpm/suse/x@1-2.el8"},
	}
	for _, c := range cases {
		if got := app.DiscoveryHint(c.comp, c.sibs).PURL; got != c.want {
			t.Errorf("%s: hint = %q, want %q", c.name, got, c.want)
		}
	}
}

// KN-SCAN-5: discovery is asked with the hint, the match is recorded under the ORIGINAL purl
// at discovery origin, and the range gate still applies.
func TestDiscoverComponents_RecordsUnderTheOriginalPURL(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{PURL: "pkg:rpm/redhat/binutils@2.30-128.el8_10", Name: "binutils", Version: "2.30-128.el8_10", Ecosystem: "rpm", Source: "binutils"}
	hinted := "pkg:rpm/redhat/binutils@2.30-128.el8_10?distro=rhel-8"
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{
		hinted: {
			{CVE: cve(t, "CVE-2024-1"), Proposal: vulnFacts(t, "osv", value.SeverityHigh)},
			{CVE: cve(t, "CVE-2024-2"), Proposal: vulnFactsRanged(t, "osv", "<2.0")}, // out of range: gated
		},
	}}
	matches := newMatches()
	s := correlation(t, fakeInventory{}, disc, matches, newRepo())

	n, err := s.DiscoverComponents(ctx, "rel-1", []app.InventoryComponent{comp}, nil)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if n != 1 {
		t.Fatalf("new matches = %d, want 1 (the out-of-range one is gated)", n)
	}
	m, ok := matches.byPURL[comp.PURL]
	if !ok {
		t.Fatalf("match recorded under %v, want the original purl %q", matches.byPURL, comp.PURL)
	}
	if m.DetectionOrigin != app.OriginDiscovery || m.CVE != "CVE-2024-1" {
		t.Errorf("match = origin %q cve %q, want discovery / CVE-2024-1", m.DetectionOrigin, m.CVE)
	}
	if _, hintedRecorded := matches.byPURL[hinted]; hintedRecorded {
		t.Error("the hinted purl must never be recorded")
	}
}

func TestDiscoverComponents_EdgesAndErrors(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{PURL: "pkg:rpm/redhat/binutils@2.30-128.el8_10", Version: "2.30-128.el8_10", Ecosystem: "rpm"}
	// A feed error surfaces (the sweep skips the release and retries later).
	s := correlation(t, fakeInventory{}, fakeDiscovery{err: errors.New("osv down")}, newMatches(), newRepo())
	if _, err := s.DiscoverComponents(ctx, "rel-1", []app.InventoryComponent{comp}, nil); err == nil {
		t.Fatal("expected the discovery error to surface")
	}
	// Nothing discovered: nothing recorded, no error.
	matches := newMatches()
	s = correlation(t, fakeInventory{}, fakeDiscovery{}, matches, newRepo())
	if n, err := s.DiscoverComponents(ctx, "rel-1", []app.InventoryComponent{comp}, nil); err != nil || n != 0 || matches.calls != 0 {
		t.Fatalf("empty discovery: n=%d err=%v calls=%d", n, err, matches.calls)
	}
	// A distro purl with no namespace has nothing to derive a distro from.
	if got := app.DiscoveryHint(app.InventoryComponent{PURL: "pkg:rpm/x@1-2.el8", Version: "1-2.el8"}, nil).PURL; got != "pkg:rpm/x@1-2.el8" {
		t.Errorf("no-namespace purl hint = %q, want unchanged", got)
	}
}

// KN-RANGE-ECO-1 (measured 2026-10-16): CVE-2019-17596's card holds Go's `<1.13.2` beside an
// Oracle appliance's `<21.1.1.1.0`. Read as one union, the Oracle range "contains" go1.27.1 and
// the stdlib component matched; judged against the Go statement, it is provably out of range
// and no match is recorded. A card with no statements still judges the flat list.
func TestCorrelate_ForeignProductRangeDoesNotHoldAGoComponent(t *testing.T) {
	ctx := context.Background()
	comp := app.InventoryComponent{PURL: "pkg:golang/stdlib@1.27.1", Name: "stdlib", Version: "go1.27.1", Ecosystem: "golang"}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{comp}}}
	c, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal("osv", time.Unix(1_700_000_000, 0), domain.VulnFacts{
		Severity: value.SeverityHigh, CVSS: c,
		AffectedRanges: []string{"<1.13.2", "<21.1.1.1.0"},
		RangeStatements: []value.RangeStatement{
			{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"},
			{Ecosystem: "oracle", Package: "weblogic", Range: "<21.1.1.1.0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{comp.PURL: {{CVE: cve(t, "CVE-2019-17596"), Proposal: p}}}}
	matches := newMatches()
	n, err := correlation(t, inv, disc, matches, newRepo()).Correlate(ctx, "rel-1", "ev-1")
	if err != nil {
		t.Fatalf("correlate: %v", err)
	}
	if n != 0 || matches.calls != 0 {
		t.Fatalf("the Oracle range held the Go component: n=%d calls=%d, want none", n, matches.calls)
	}
	// Without statements the same flat list keeps the match (today's behaviour, the defect).
	flat := fakeDiscovery{byPURL: map[string][]app.ProposalFor{comp.PURL: {{CVE: cve(t, "CVE-2019-17596"), Proposal: vulnFactsRanged(t, "nvd", "<1.13.2", "<21.1.1.1.0")}}}}
	matches2 := newMatches()
	if n, _ := correlation(t, inv, flat, matches2, newRepo()).Correlate(ctx, "rel-1", "ev-1"); n != 1 {
		t.Fatalf("flat list: n=%d, want the match kept", n)
	}
}

// --- KN-SANITY-1: the fan-out guard ----------------------------------------------------------

type sanityRec struct {
	flags []app.SuspectFanout
	err   error
}

func (r *sanityRec) RecordSuspectFanout(_ context.Context, f app.SuspectFanout) error {
	if r.err != nil {
		return r.err
	}
	r.flags = append(r.flags, f)
	return nil
}

func manyCVEs(t *testing.T, n, offset int) []app.ProposalFor {
	t.Helper()
	out := make([]app.ProposalFor, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, app.ProposalFor{CVE: cve(t, fmt.Sprintf("CVE-2020-%d", offset+i)), Proposal: vulnFactsRanged(t, "osv")})
	}
	return out
}

// The KN-GO-1 shape, caught the day it happens: a Go component spelled `toolchain-go1.27.1` (unparseable)
// draws 60 CVEs → flagged, recorded, every open occurrence's verdict carries the reason; the
// matches are still recorded (nothing dropped). A parseable version with the same long history
// is not flagged; below the threshold nothing is flagged; the guard off flags nothing; a
// recorder failure surfaces.
func TestCorrelate_FanoutGuardFlagsAnUnparseableVersion(t *testing.T) {
	ctx := context.Background()
	odd := app.InventoryComponent{PURL: "pkg:golang/stdlib@toolchain-go1.27.1", Name: "stdlib", Version: "toolchain-go1.27.1", Ecosystem: "golang"}
	fine := app.InventoryComponent{PURL: "pkg:rpm/rocky/binutils@2.30-128.el8_10", Name: "binutils", Version: "2.30-128.el8_10", Ecosystem: "rpm"}
	inv := fakeInventory{inv: app.Inventory{Components: []app.InventoryComponent{odd, fine}}}
	disc := fakeDiscovery{byPURL: map[string][]app.ProposalFor{odd.PURL: manyCVEs(t, 60, 10000), fine.PURL: manyCVEs(t, 60, 20000)}}
	rec := &sanityRec{}
	matches := newMatches()
	s := correlation(t, inv, disc, matches, newRepo()).WithFanoutGuard(50, rec)
	n, err := s.Correlate(ctx, "rel-1", "ev-1")
	if err != nil || n != 120 {
		t.Fatalf("correlate: n=%d err=%v, want all 120 matches recorded (nothing dropped)", n, err)
	}
	if len(rec.flags) != 1 || rec.flags[0].PURL != odd.PURL || rec.flags[0].CVEs != 60 || rec.flags[0].ReleaseID != "rel-1" || !strings.Contains(rec.flags[0].Reason, "cannot read") {
		t.Fatalf("flags = %+v, want one for the unparseable Go spelling", rec.flags)
	}
	if r := matches.byPURL[odd.PURL].Verdict.Reason; !strings.Contains(r, "suspect fan-out") {
		t.Fatalf("suspect occurrence verdict reason = %q, want the guard's reason", r)
	}
	if r := matches.byPURL[fine.PURL].Verdict.Reason; strings.Contains(r, "suspect fan-out") {
		t.Fatalf("binutils (parseable, long history) must not carry the reason, got %q", r)
	}
	// Below the threshold: nothing.
	rec2 := &sanityRec{}
	if _, err := correlation(t, inv, fakeDiscovery{byPURL: map[string][]app.ProposalFor{odd.PURL: manyCVEs(t, 10, 30000)}}, newMatches(), newRepo()).WithFanoutGuard(50, rec2).Correlate(ctx, "rel-1", "ev-1"); err != nil || len(rec2.flags) != 0 {
		t.Fatalf("below threshold: flags=%d err=%v", len(rec2.flags), err)
	}
	// Guard off: nothing, even at 60.
	rec3 := &sanityRec{}
	if _, err := correlation(t, inv, disc, newMatches(), newRepo()).WithFanoutGuard(0, rec3).Correlate(ctx, "rel-1", "ev-1"); err != nil || len(rec3.flags) != 0 {
		t.Fatalf("guard off: flags=%d err=%v", len(rec3.flags), err)
	}
	// Recorder failure surfaces.
	if _, err := correlation(t, inv, disc, newMatches(), newRepo()).WithFanoutGuard(50, &sanityRec{err: errors.New("db")}).Correlate(ctx, "rel-1", "ev-1"); err == nil {
		t.Fatal("a recorder failure must surface")
	}
	// The scanner road is guarded the same way.
	rec4 := &sanityRec{}
	fold := app.NewFaultlineService(newRepo(), &seqIDs{}, fixedClock{}, domain.NewPrecedence("nvd"), domain.NewTrustPolicy(nil))
	corr := app.NewCorrelationService(fakeInventory{}, disc, fold, newMatches(), fixedClock{}).WithFanoutGuard(50, rec4)
	if _, err := corr.DiscoverComponents(ctx, "rel-2", []app.InventoryComponent{odd}, nil); err != nil || len(rec4.flags) != 1 || rec4.flags[0].ReleaseID != "rel-2" {
		t.Fatalf("scanner road: flags=%+v err=%v", rec4.flags, err)
	}
	if _, err := app.NewCorrelationService(fakeInventory{}, disc, fold, newMatches(), fixedClock{}).WithFanoutGuard(50, &sanityRec{err: errors.New("db")}).DiscoverComponents(ctx, "rel-2", []app.InventoryComponent{odd}, nil); err == nil {
		t.Fatal("scanner road: a recorder failure must surface")
	}
}
