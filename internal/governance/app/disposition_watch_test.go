package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// suppressed seeds a Finding carrying an accepted suppressing Position, recorded with the given
// exploit signals — i.e. a decision somebody took, on a premise.
// suppressed builds a Finding carrying an accepted SUPPRESSING Position that was decided with the
// given exploit signals — i.e. a decision somebody took, on a stated premise.
//
// Built directly on the aggregate rather than driven through a policy, because the fixture's job
// is to establish a known premise, not to exercise the acceptance path. Routing it through
// ReactToEnrichment made the test depend on which stance a policy happened to accept first.
func suppressed(t *testing.T, stance domain.Stance, decidedWith domain.ExploitSignals) domain.Finding {
	t.Helper()
	f, err := domain.NewFinding("fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	// The premise must be on the Finding BEFORE the decision: AcceptProposal snapshots it, which
	// is the whole mechanism under test.
	f.RefreshSignals(decidedWith)

	at := time.Unix(1_700_000_000, 0).UTC()
	p, err := domain.NewGovernanceProposal("p1", domain.Actor{Kind: domain.ActorHuman, ID: "analyst"},
		stance, "decided", at, value.TrustObserved)
	if err != nil {
		t.Fatalf("new proposal: %v", err)
	}
	if err := f.RaiseProposal(p); err != nil {
		t.Fatalf("raise: %v", err)
	}
	if _, err := f.AcceptProposal("p1", domain.Actor{Kind: domain.ActorHuman, ID: "analyst"}, at); err != nil {
		t.Fatalf("accept: %v", err)
	}
	pos, ok := f.CurrentPosition()
	if !ok || pos.Inputs().DecidedWith != decidedWith {
		t.Fatalf("fixture did not record the premise: ok=%v inputs=%+v", ok, pos.Inputs())
	}
	return f
}

// GOV-14b, the whole point: `residual_priority` zeroes a suppressed Finding and removes it from
// the queue. That is only safe because something re-surfaces it when the premise moves. The
// zeroing shipped 2026-08-06 and the watcher did not, so an acceptance was permanent in practice.
func TestReactToEnrichment_ResurfacesASuppressedFindingOnDrift(t *testing.T) {
	repo := newRepo()
	f := suppressed(t, domain.StanceNotAffected, domain.ExploitSignals{EPSS: 0.02})
	repo.seed(f)
	s := writeSvc(repo)

	// The world moves: the CVE enters KEV.
	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1",
		Signals:     domain.ExploitSignals{EPSS: 0.02, KEV: true},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}

	var stale *domain.DispositionStale
	for _, n := range repo.lastNotes {
		if n.EventType == app.EventDispositionStale {
			e := n.Event.(domain.DispositionStale)
			stale = &e
		}
	}
	if stale == nil {
		t.Fatalf("no disposition-stale event; notes=%v", noteTypes(repo.lastNotes))
	}
	if stale.Reason == "" {
		t.Error("the event must say WHAT moved — a re-surfaced Finding lands in a queue somebody already emptied")
	}
	// It re-opens the QUESTION, never the decision (D6/D11). Auto-revising a governed Position is
	// exactly the auto-deciding this context forbids.
	pos, ok := repo.byID["fnd-1"].CurrentPosition()
	if !ok || pos.Stance() != domain.StanceNotAffected {
		t.Errorf("the Position must be untouched, got ok=%v stance=%q", ok, pos.Stance())
	}
}

// The premise still holding must produce silence. A watcher that fires on every enrichment is a
// watcher people mute.
func TestReactToEnrichment_NoDriftIsSilent(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceNotAffected, domain.ExploitSignals{KEV: true, EPSS: 0.9}))
	s := writeSvc(repo)
	repo.lastNotes = nil

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1",
		Signals:     domain.ExploitSignals{KEV: true, EPSS: 0.9}, // unchanged
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, n := range repo.lastNotes {
		if n.EventType == app.EventDispositionStale {
			t.Fatalf("fired on an unchanged premise — the decision was taken knowing these signals")
		}
	}
}

// Only the SUPPRESSING stances are watched. An `affected` Finding is already in the queue; a
// disposition-stale event for it would be noise about something nobody has stopped looking at.
func TestReactToEnrichment_UnsuppressedFindingsAreNotWatched(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")) // no Position at all
	s := writeSvc(repo)

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1",
		Signals:     domain.ExploitSignals{KEV: true, ExploitPublic: true, EPSS: 0.99},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, n := range repo.lastNotes {
		if n.EventType == app.EventDispositionStale {
			t.Fatal("a Finding with no suppressing Position must not be re-surfaced")
		}
	}
}

// A withdrawal retires the CVE upstream. Re-surfacing a Finding because a dead CVE's stale EPSS
// moved is noise.
func TestReactToEnrichment_WithdrawalSkipsTheWatcher(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceNotAffected, domain.ExploitSignals{}))
	s := writeSvc(repo)
	repo.lastNotes = nil

	if err := s.ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Withdrawn: true, WithdrawnTrust: value.TrustObserved,
		Signals: domain.ExploitSignals{KEV: true, EPSS: 0.99},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, n := range repo.lastNotes {
		if n.EventType == app.EventDispositionStale {
			t.Fatal("a withdrawn CVE must not re-surface on signal drift")
		}
	}
}

// The threshold is configurable (THEMIS_EPSS_DRIFT_THRESHOLD): an estate that finds the default
// too chatty can raise it, and one that wants earlier warning can lower it.
func TestWithEPSSDriftThreshold(t *testing.T) {
	seed := func() *fakeRepo {
		r := newRepo()
		r.seed(suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{EPSS: 0.10}))
		return r
	}
	fired := func(repo *fakeRepo) bool {
		for _, n := range repo.lastNotes {
			if n.EventType == app.EventDispositionStale {
				return true
			}
		}
		return false
	}
	// A 0.15 rise: below the 0.20 default, above a 0.05 override.
	drifted := app.EnrichmentSignal{FaultlineID: "fl-1", Signals: domain.ExploitSignals{EPSS: 0.25}}

	repo := seed()
	if err := writeSvc(repo).ReactToEnrichment(context.Background(), drifted); err != nil {
		t.Fatalf("react: %v", err)
	}
	if fired(repo) {
		t.Error("a 0.15 rise fired at the 0.20 default")
	}

	repo = seed()
	if err := writeSvc(repo).WithEPSSDriftThreshold(0.05).ReactToEnrichment(context.Background(), drifted); err != nil {
		t.Fatalf("react: %v", err)
	}
	if !fired(repo) {
		t.Error("a 0.15 rise did not fire at a 0.05 threshold")
	}
}

// A read failure while scanning for suppressed Findings must surface, not be swallowed: the
// watcher is a safety net, and a net that fails quietly is worse than none.
func TestWatchDispositions_ReadFailureSurfaces(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{}))
	repo.getByIDErr = errors.New("db down")

	err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Signals: domain.ExploitSignals{KEV: true},
	})
	if err == nil {
		t.Fatal("a read failure in the disposition watch must surface")
	}
}

// A Position revised between the scan and the write must not be re-surfaced: somebody has just
// re-taken that decision, and sending them back to a queue they had already emptied is the fastest
// way to make a safety net ignored. The watcher re-checks inside the transaction for exactly this.
func TestWatchDispositions_SkipsAPositionRevisedUnderIt(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{}))

	// Between the scan and the write, the Finding is re-decided — no longer suppressed, so there
	// is nothing to re-surface. The watcher reads once to decide and once more under the write;
	// swapping what the SECOND read sees is what puts the re-check under test.
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n == 1 {
			return f // the scan still sees the suppression
		}
		return identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1") // re-decided beneath us
	}

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Signals: domain.ExploitSignals{KEV: true},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, n := range repo.lastNotes {
		if n.EventType == app.EventDispositionStale {
			t.Fatal("re-surfaced a Finding whose suppression had just been lifted")
		}
	}
}

// A SetSignals failure must surface. The premise a decision records is the input to the whole
// safety net, and silently skipping it would leave later Positions recording "nothing known" —
// which reads as drift on every subsequent enrichment.
func TestReactToEnrichment_SetSignalsFailureSurfaces(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	repo.setSignalsErr = errors.New("db down")

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Signals: domain.ExploitSignals{KEV: true},
	}); err == nil {
		t.Fatal("a SetSignals failure must surface — a decision with no recorded premise is worse than none")
	}
}

// The re-check inside the write sees the premise still holding — the value moved between the scan
// and the write, back to something that no longer counts as drift. Nothing is emitted.
func TestWatchDispositions_DriftDisappearsUnderTheWrite(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{EPSS: 0.01}))
	repo.onGetByID = func(n int, f domain.Finding) domain.Finding {
		if n == 1 {
			return f // the scan sees a premise of EPSS 0.01 → the incoming 0.9 is drift
		}
		// Under the write, the Position turns out to have been decided knowing 0.9 already.
		return suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{EPSS: 0.9})
	}

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Signals: domain.ExploitSignals{EPSS: 0.9},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	for _, n := range repo.lastNotes {
		if n.EventType == app.EventDispositionStale {
			t.Fatal("emitted for a premise that turned out to hold under the write")
		}
	}
}

// ReactToEnrichment walks the Faultline's Findings up to FIVE times — materialize band/fixes,
// disposition watch, re-prioritize, applicability, version-range — and each walk must surface its
// own read failure.
//
// A blanket error only ever exercises the FIRST walk, and adding the watcher in front of the other
// three silently made their error branches unreachable. Failing a specific call is what keeps each
// one honest.
func TestReactToEnrichment_EachFindingsWalkSurfacesItsOwnReadFailure(t *testing.T) {
	// A signal that drives every pass: drift for the watcher, KEV+high for the re-prioritize
	// proposal, a vendor statement for applicability, and a range for the version-range rule.
	sig := func() app.EnrichmentSignal {
		return app.EnrichmentSignal{
			FaultlineID: "fl-1", KEV: true, HighSeverity: true,
			Band:            "high",
			Signals:         domain.ExploitSignals{KEV: true},
			Applicabilities: []app.Applicability{{Package: "openssl", Status: "not_affected", Justification: "vulnerable_code_not_present"}},
			AffectedRanges:  []string{"<2.0.0"},
			RangeTrust:      value.TrustObserved,
		}
	}
	for call := 1; call <= 5; call++ {
		t.Run("walk "+string(rune('0'+call)), func(t *testing.T) {
			repo := newRepo()
			repo.seed(suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{}))
			repo.byFaultlineErrOnCall = call

			if err := writeSvc(repo).ReactToEnrichment(context.Background(), sig()); err == nil {
				t.Fatalf("a read failure on walk %d did not surface", call)
			}
		})
	}
}

// A write failure inside the watcher surfaces rather than being skipped: the whole point of the
// net is that its absence is noticed.
func TestWatchDispositions_WriteFailureSurfaces(t *testing.T) {
	repo := newRepo()
	repo.seed(suppressed(t, domain.StanceAcceptedRisk, domain.ExploitSignals{}))
	repo.saveErr = errors.New("db down")

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Signals: domain.ExploitSignals{KEV: true},
	}); err == nil {
		t.Fatal("a write failure in the disposition watch must surface")
	}
}

// DASH-2 / PLAN-3: the band and the per-component fix selection are MATERIALIZED onto each Finding
// at enrichment, so a release rollup carries both without a read per row.
//
// Rendering one posture table previously cost ~460 API calls — one Knowledge read per Faultline for
// the band, one Governance assessment per Finding for the component. A rollup whose cost is linear
// in its own length cannot serve a dashboard.
func TestReactToEnrichment_MaterializesBandAndSelectedFixes(t *testing.T) {
	repo := newRepo()
	f := identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{
		PURL: "pkg:rpm/rocky/python3-ply@3.9", Name: "python3-ply", Ecosystem: "rpm", Source: "python-ply",
	}); err != nil {
		t.Fatalf("absorb: %v", err)
	}
	repo.seed(f)

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1", Band: "high",
		Fixes: []app.FixedVersion{
			{Package: "python-ply", Version: "0:3.11-10"}, // this component's
			{Package: "PyYAML", Version: "0:5.4.1-1"},     // another package on the same card
		},
	}); err != nil {
		t.Fatalf("react: %v", err)
	}

	if repo.lastBand != "high" {
		t.Errorf("band = %q, want high", repo.lastBand)
	}
	// SELECTED, not the union: handing a Finding the whole card is what produced a recommendation
	// citing another package's version (AI-GROUND-1).
	if len(repo.lastFixes) != 1 || repo.lastFixes[0].Package != "python-ply" {
		t.Errorf("fixes = %+v, want only python-ply's", repo.lastFixes)
	}
}

// Nothing to stamp is a no-op, not a write. An older payload carries neither field, and rewriting
// every Finding on the Faultline to store the same empty values would be pure cost.
func TestReactToEnrichment_NoBandOrFixesIsANoOp(t *testing.T) {
	repo := newRepo()
	repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
	repo.lastBand = "sentinel"

	if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
		FaultlineID: "fl-1",
	}); err != nil {
		t.Fatalf("react: %v", err)
	}
	if repo.lastBand != "sentinel" {
		t.Errorf("band was written on an empty payload: %q", repo.lastBand)
	}
}

// Both failure paths surface: the Finding read that feeds the selection, and the write itself.
func TestMaterializeBandAndFixes_FailuresSurface(t *testing.T) {
	t.Run("read failure", func(t *testing.T) {
		repo := newRepo()
		repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
		repo.getByIDErr = errors.New("db down")
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
			FaultlineID: "fl-1", Band: "high",
		}); err == nil {
			t.Fatal("a Finding read failure must surface")
		}
	})
	t.Run("write failure", func(t *testing.T) {
		repo := newRepo()
		repo.seed(identified(t, "fnd-1", "rel-1", "fl-1", "CVE-2024-1"))
		repo.setBandErr = errors.New("db down")
		if err := writeSvc(repo).ReactToEnrichment(context.Background(), app.EnrichmentSignal{
			FaultlineID: "fl-1", Band: "high",
		}); err == nil {
			t.Fatal("a band/fixes write failure must surface")
		}
	})
}
