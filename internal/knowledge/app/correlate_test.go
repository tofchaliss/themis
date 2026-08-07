package app_test

import (
	"context"
	"errors"
	"testing"

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
	err      error
	calls    int
}

func newMatches() *fakeMatches { return &fakeMatches{recorded: map[string]bool{}} }

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

func TestCorrelate_SkipsRPMFixedByStream(t *testing.T) {
	ctx := context.Background()
	// The installed RHEL-8 build (release 17) is at/above the Red Hat RHEL-8 fix (release 16), so
	// it carries the backported fix — correlation records NO match for this occurrence (fixed, not
	// affected), even though the CVE is real (EDR-VEX-01 Phase 3, stream-scoped fixed verdict).
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
	if n != 0 || matches.calls != 0 {
		t.Errorf("a build at/above its same-stream vendor fix must record no match (n=%d, RecordMatch calls=%d)", n, matches.calls)
	}
	// The card is still folded — the CVE is real intelligence; only THIS release's occurrence is fixed.
	if _, found, _ := repo.GetByCVE(ctx, "CVE-2024-11"); !found {
		t.Error("expected the folded faultline to exist even though the component is fixed")
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
	if n, err := correlation(t, inv, disc, matches, newRepo()).Correlate(ctx, "rel-1", "ev-1"); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, want 0 — the installed build carries the source package's fix", n, err)
	}
}
