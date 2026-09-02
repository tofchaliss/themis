package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type fakeStale struct {
	rows []app.StaleOccurrence
	err  error
}

func (f fakeStale) StaleVerdictOccurrences(context.Context, int) ([]app.StaleOccurrence, error) {
	return f.rows, f.err
}

type fakeEvidenceLedger struct {
	ev    map[string]string // releaseID -> evidenceID
	err   error
	calls int
}

func (f *fakeEvidenceLedger) EvidenceForRelease(_ context.Context, releaseID string) (string, bool, error) {
	f.calls++
	if f.err != nil {
		return "", false, f.err
	}
	ev, ok := f.ev[releaseID]
	return ev, ok, nil
}

type fakeRelComps struct {
	comps map[string][]app.InventoryComponent
	err   error
}

func (f fakeRelComps) MatchComponentsForRelease(_ context.Context, releaseID string) ([]app.InventoryComponent, error) {
	return f.comps[releaseID], f.err
}

type countingInventory struct {
	inv   app.Inventory
	err   error
	calls int
}

func (c *countingInventory) GetInventory(context.Context, string) (app.Inventory, error) {
	c.calls++
	return c.inv, c.err
}

// seedCard folds one fix-carrying proposal so the repo holds a real card (version 1) whose
// view the judge reads.
func seedCard(t *testing.T, repo *fakeRepo, cveID, pkg, fix string) domain.Faultline {
	t.Helper()
	fold := app.NewFaultlineService(repo, &seqIDs{}, fixedClock{}, domain.NewPrecedence("redhat"), domain.NewTrustPolicy(nil))
	f, _, err := fold.FoldProposal(context.Background(), cve(t, cveID), vulnFactsFixedFor(t, "redhat", pkg, fix))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// The sweep on the measured KN-VERDICT-1 history: a pre-feature row (stamp behind, state open)
// whose release's correlated inventory holds the patched rpm — re-judged through the same
// bridge intake uses, cleared at the inferred grade, stamped with the card version, and
// counted as a CHANGE. A second row already cleared re-judges to the same conclusion and is
// counted as re-judged only.
func TestReverdictSweep_ClearsStaleHistory(t *testing.T) {
	repo := newRepo()
	card := seedCard(t, repo, "CVE-2025-47273", "python-setuptools", "0:39.2.0-9.el8_10")
	shadow := app.InventoryComponent{PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi"}
	rpm := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10", Name: "platform-python-setuptools",
		Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
	}
	stale := fakeStale{rows: []app.StaleOccurrence{
		{ReleaseID: "rel-1", FaultlineID: card.ID(), CVE: "CVE-2025-47273", Component: shadow, Current: domain.VerdictOpen},
		{ReleaseID: "rel-1", FaultlineID: card.ID(), CVE: "CVE-2025-47273", Component: rpm, Current: domain.VerdictClearedVendorFix},
	}}
	ledger := &fakeEvidenceLedger{ev: map[string]string{"rel-1": "ev-1"}}
	inv := &countingInventory{inv: app.Inventory{Components: []app.InventoryComponent{shadow, rpm}}}
	matches := newMatches()

	svc := app.NewReverdictService(stale, ledger, fakeRelComps{}, inv, repo, matches, fixedClock{}, 0)
	rejudged, changed, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rejudged != 2 || changed != 1 {
		t.Errorf("rejudged=%d changed=%d, want 2/1 — one flip, one confirmation", rejudged, changed)
	}
	m := matches.byPURL[shadow.PURL]
	if m.Verdict.State != domain.VerdictClearedVendorFix || m.Verdict.Grade != domain.VerdictGradeInferred {
		t.Errorf("shadow verdict = %+v, want the inferred clearance", m.Verdict)
	}
	if m.CardVersion != card.Version() {
		t.Errorf("stamp = %d, want the judged-against card version %d", m.CardVersion, card.Version())
	}
	// Context caching: two rows, one release, one card — one ledger read, one inventory read.
	if ledger.calls != 1 || inv.calls != 1 {
		t.Errorf("ledger=%d inventory=%d calls, want 1/1 — context is per release, not per row", ledger.calls, inv.calls)
	}
}

// A release the ledger does not know (scanner-only) re-judges against its OWN recorded
// occurrences — post-D2 the scanner door records every examined component, so those rows are
// the report's candidate set.
func TestReverdictSweep_ScannerOnlyReleaseUsesItsOwnRows(t *testing.T) {
	repo := newRepo()
	card := seedCard(t, repo, "CVE-2025-47273", "python-setuptools", "0:39.2.0-9.el8_10")
	shadow := app.InventoryComponent{PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi"}
	rpm := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10", Name: "platform-python-setuptools",
		Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
	}
	stale := fakeStale{rows: []app.StaleOccurrence{
		{ReleaseID: "rel-scan", FaultlineID: card.ID(), CVE: "CVE-2025-47273", Component: shadow, Current: domain.VerdictOpen},
	}}
	relComps := fakeRelComps{comps: map[string][]app.InventoryComponent{"rel-scan": {shadow, rpm}}}
	matches := newMatches()

	svc := app.NewReverdictService(stale, &fakeEvidenceLedger{}, relComps, &countingInventory{}, repo, matches, fixedClock{}, 0)
	rejudged, changed, err := svc.Sweep(context.Background())
	if err != nil || rejudged != 1 || changed != 1 {
		t.Fatalf("rejudged=%d changed=%d err=%v, want 1/1/nil", rejudged, changed, err)
	}
	if m := matches.byPURL[shadow.PURL]; m.Verdict.State != domain.VerdictClearedVendorFix {
		t.Errorf("shadow verdict = %+v, want cleared via the match-row sibling set", m.Verdict)
	}
}

// Fail-safety of the context reads: a release whose evidence is unreachable this sweep is
// SKIPPED whole — judging with a poorer context than the evidence offers and stamping the
// result current would silently downgrade the verdict. Its rows stay stale for the next sweep.
func TestReverdictSweep_SkipsReleaseWhenContextUnavailable(t *testing.T) {
	repo := newRepo()
	card := seedCard(t, repo, "CVE-2025-47273", "python-setuptools", "0:39.2.0-9.el8_10")
	row := app.StaleOccurrence{ReleaseID: "rel-1", FaultlineID: card.ID(), CVE: "CVE-2025-47273",
		Component: app.InventoryComponent{PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi"}}
	stale := fakeStale{rows: []app.StaleOccurrence{row}}

	for name, svc := range map[string]*app.ReverdictService{
		"inventory read fails": app.NewReverdictService(stale, &fakeEvidenceLedger{ev: map[string]string{"rel-1": "ev-1"}},
			fakeRelComps{}, &countingInventory{err: errors.New("evidence down")}, repo, newMatches(), fixedClock{}, 0),
		"ledger read fails": app.NewReverdictService(stale, &fakeEvidenceLedger{err: errors.New("db hiccup")},
			fakeRelComps{}, &countingInventory{}, repo, newMatches(), fixedClock{}, 0),
		"fallback rows fail": app.NewReverdictService(stale, &fakeEvidenceLedger{},
			fakeRelComps{err: errors.New("db hiccup")}, &countingInventory{}, repo, newMatches(), fixedClock{}, 0),
	} {
		rejudged, changed, err := svc.Sweep(context.Background())
		if err != nil || rejudged != 0 || changed != 0 {
			t.Errorf("%s: rejudged=%d changed=%d err=%v, want the release skipped silently", name, rejudged, changed, err)
		}
	}
}

// Real store faults surface (they are not feed gaps): the stale query, the card read, and the
// record write each propagate so the loop logs and retries.
func TestReverdictSweep_Errors(t *testing.T) {
	repo := newRepo()
	card := seedCard(t, repo, "CVE-2025-47273", "python-setuptools", "0:39.2.0-9.el8_10")
	row := app.StaleOccurrence{ReleaseID: "rel-1", FaultlineID: card.ID(), CVE: "CVE-2025-47273",
		Component: app.InventoryComponent{PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi"}}
	ledger := func() *fakeEvidenceLedger { return &fakeEvidenceLedger{ev: map[string]string{"rel-1": "ev-1"}} }
	inv := func() *countingInventory { return &countingInventory{} }

	if _, _, err := app.NewReverdictService(fakeStale{err: errors.New("query failed")}, ledger(), fakeRelComps{},
		inv(), repo, newMatches(), fixedClock{}, 0).Sweep(context.Background()); err == nil {
		t.Error("stale-query error must surface")
	}
	if _, _, err := app.NewReverdictService(fakeStale{rows: []app.StaleOccurrence{{ReleaseID: "rel-1", FaultlineID: "ghost", CVE: "CVE-2025-47273"}}},
		ledger(), fakeRelComps{}, inv(), repo, newMatches(), fixedClock{}, 0).Sweep(context.Background()); err == nil {
		t.Error("card-read error must surface")
	}
	bad := newMatches()
	bad.err = errors.New("write failed")
	if _, _, err := app.NewReverdictService(fakeStale{rows: []app.StaleOccurrence{row}}, ledger(), fakeRelComps{},
		inv(), repo, bad, fixedClock{}, 0).Sweep(context.Background()); err == nil {
		t.Error("record error must surface")
	}
	// Empty queue: nothing to do, no reads made.
	if rejudged, changed, err := app.NewReverdictService(fakeStale{}, ledger(), fakeRelComps{},
		inv(), repo, newMatches(), fixedClock{}, 0).Sweep(context.Background()); err != nil || rejudged != 0 || changed != 0 {
		t.Errorf("empty sweep = %d/%d/%v, want 0/0/nil", rejudged, changed, err)
	}
}

// Strict mode threads through to the judge, exactly as on the intake doors.
func TestReverdictSweep_StrictMode(t *testing.T) {
	repo := newRepo()
	card := seedCard(t, repo, "CVE-2025-47273", "python-setuptools", "0:39.2.0-9.el8_10")
	shadow := app.InventoryComponent{PURL: "pkg:pypi/setuptools@39.2.0", Name: "setuptools", Version: "39.2.0", Ecosystem: "pypi"}
	rpm := app.InventoryComponent{
		PURL: "pkg:rpm/rhel/platform-python-setuptools@39.2.0-9.el8_10", Name: "platform-python-setuptools",
		Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
	}
	matches := newMatches()
	svc := app.NewReverdictService(
		fakeStale{rows: []app.StaleOccurrence{{ReleaseID: "rel-1", FaultlineID: card.ID(), CVE: "CVE-2025-47273", Component: shadow, Current: domain.VerdictOpen}}},
		&fakeEvidenceLedger{ev: map[string]string{"rel-1": "ev-1"}}, fakeRelComps{},
		&countingInventory{inv: app.Inventory{Components: []app.InventoryComponent{shadow, rpm}}},
		repo, matches, fixedClock{}, 0).WithInferredBridge(false)
	if _, changed, err := svc.Sweep(context.Background()); err != nil || changed != 0 {
		t.Errorf("strict sweep changed=%d err=%v, want no clearance without explicit ownership", changed, err)
	}
	if m := matches.byPURL[shadow.PURL]; !m.Verdict.State.IsOpen() {
		t.Errorf("strict mode cleared: %+v", m.Verdict)
	}
}

// Nudge is non-blocking and coalescing: a burst collapses to one pending wake-up.
func TestReverdictNudge(t *testing.T) {
	svc := app.NewReverdictService(fakeStale{}, &fakeEvidenceLedger{}, fakeRelComps{}, &countingInventory{}, newRepo(), newMatches(), fixedClock{}, 0)
	svc.Nudge()
	svc.Nudge() // must not block
	select {
	case <-svc.NudgeC():
	default:
		t.Fatal("a nudge must be pending")
	}
	select {
	case <-svc.NudgeC():
		t.Fatal("burst must coalesce to one pending wake-up")
	default:
	}
}
