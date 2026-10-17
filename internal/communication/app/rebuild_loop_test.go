package app_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/themis-project/themis/internal/communication/app"
)

type cyclesMem struct {
	rows      map[string]*app.RebuildCycle // by release, open only
	all       []app.RebuildCycle
	next      int64
	openErr   error
	createErr error
	updateErr error
}

func newCyclesMem() *cyclesMem { return &cyclesMem{rows: map[string]*app.RebuildCycle{}} }

func (c *cyclesMem) OpenCycle(_ context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	if c.openErr != nil {
		return app.RebuildCycle{}, false, c.openErr
	}
	if r, ok := c.rows[releaseID]; ok && r.State == app.CycleOpen {
		return *r, true, nil
	}
	return app.RebuildCycle{}, false, nil
}
func (c *cyclesMem) CreateCycle(_ context.Context, cy app.RebuildCycle) (app.RebuildCycle, error) {
	if c.createErr != nil {
		return app.RebuildCycle{}, c.createErr
	}
	c.next++
	cy.ID = c.next
	c.rows[cy.ReleaseID] = &cy
	c.all = append(c.all, cy)
	return cy, nil
}
func (c *cyclesMem) UpdateCycle(_ context.Context, cy app.RebuildCycle) error {
	if c.updateErr != nil {
		return c.updateErr
	}
	c.rows[cy.ReleaseID] = &cy
	return nil
}

type postureMem struct {
	rows []app.ReleaseSeverityRow
	err  error
}

func (p *postureMem) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	return p.rows, p.err
}

func loopFixture(max int) (*app.RebuildLoop, *cyclesMem, *postureMem, *intentStore) {
	store := newIntentStore()
	cycles := newCyclesMem()
	posture := &postureMem{}
	svc := intentSvc(store, app.DeliveryIntentConfig{RebuildDestination: "team/build-image"})
	return app.NewRebuildLoop(cycles, posture, svc, intentClock{}, max), cycles, posture, store
}

func rows(scores map[string]int) []app.ReleaseSeverityRow {
	var out []app.ReleaseSeverityRow
	for cve, s := range scores {
		out = append(out, app.ReleaseSeverityRow{CVE: cve, BaseScore: s})
	}
	return out
}

// M2-8 end to end at the app level: clean → no cycle; Critical/High → a cycle opens and attempt 1
// is asked for; the next evaluation compares against the set captured at the start (a new Critical
// mid-loop is not targeted), continues with attempt 2; the evaluation after that is the limit —
// still open ⇒ EXHAUSTED, nothing raised; a later new SBOM may open a fresh cycle; and a cycle
// whose targets all close SUCCEEDS with nothing raised.
func TestRebuildLoop_OpensContinuesStops(t *testing.T) {
	ctx := context.Background()
	loop, cycles, posture, store := loopFixture(2)
	lineage := lineage()

	// Clean: nothing.
	posture.rows = rows(map[string]int{"CVE-2026-9": 55})
	out, err := loop.Evaluate(ctx, "rel-1", "ev-1", "env-1")
	if err != nil || out.State != app.OutcomeClean || out.Snapshot(2) != nil {
		t.Fatalf("clean = %+v (err %v)", out, err)
	}
	if _, raised, err := loop.Raise(ctx, lineage, "env-1", out, "prod-1", "prj-1"); err != nil || raised {
		t.Fatalf("clean must raise nothing: %v / %v", raised, err)
	}

	// Opens on Critical/High; the attempt is asked for with the whole set.
	posture.rows = rows(map[string]int{"CVE-2026-1": 95, "CVE-2026-2": 72, "CVE-2026-3": 40})
	out, err = loop.Evaluate(ctx, "rel-1", "ev-1", "env-1")
	if err != nil || out.State != app.OutcomeOpened || out.NextAttempt != 1 || !reflect.DeepEqual(out.Targeted, []string{"CVE-2026-1", "CVE-2026-2"}) {
		t.Fatalf("opened = %+v (err %v)", out, err)
	}
	snap := out.Snapshot(2)
	if snap[app.SnapshotRebuildState] != "opened" || snap[app.SnapshotRebuildAttempt] != "1" || snap[app.SnapshotRebuildMaxAttempts] != "2" ||
		snap[app.SnapshotRebuildTargeted] != "CVE-2026-1,CVE-2026-2" || snap[app.SnapshotRebuildOpen] != "CVE-2026-1,CVE-2026-2" || snap[app.SnapshotRebuildBaseline] != "ev-1" {
		t.Errorf("snapshot = %v", snap)
	}
	in, raised, err := loop.Raise(ctx, lineage, "env-1", out, "prod-1", "prj-1")
	if err != nil || !raised || in.Type != app.IntentCIRebuild || in.Destination != "team/build-image" || in.Snapshot[app.SnapshotAttempt] != "1" ||
		in.Snapshot[app.SnapshotTargetedCVEs] != "CVE-2026-1,CVE-2026-2" || in.Snapshot[app.SnapshotPriorSBOMID] != "ev-1" || in.Snapshot[app.SnapshotRebuildState] != "opened" {
		t.Fatalf("raised = %+v / %v / %v", in, raised, err)
	}
	if c := cycles.rows["rel-1"]; c.Attempts != 1 || c.State != app.CycleOpen || c.BaselineSBOMID != "ev-1" || c.OriginEventID != "env-1" {
		t.Errorf("cycle = %+v", c)
	}

	// The rebuild's SBOM: one closed, one open, a NEW Critical — continue with attempt 2 on the
	// still-open target only.
	posture.rows = rows(map[string]int{"CVE-2026-2": 60, "CVE-2026-7": 99})
	out, err = loop.Evaluate(ctx, "rel-1", "ev-2", "env-2")
	if err != nil || out.State != app.OutcomeContinuing || out.NextAttempt != 2 || !reflect.DeepEqual(out.Closed, []string{"CVE-2026-1"}) || !reflect.DeepEqual(out.Open, []string{"CVE-2026-2"}) {
		t.Fatalf("continuing = %+v (err %v)", out, err)
	}
	in, raised, err = loop.Raise(ctx, lineage, "env-2", out, "prod-1", "prj-1")
	if err != nil || !raised || in.Snapshot[app.SnapshotAttempt] != "2" || in.Snapshot[app.SnapshotTargetedCVEs] != "CVE-2026-2" || in.Snapshot[app.SnapshotPriorSBOMID] != "ev-2" {
		t.Fatalf("second raise = %+v / %v", in, err)
	}
	if c := cycles.rows["rel-1"]; c.Attempts != 2 || c.LastSBOMID != "ev-2" || len(c.Targeted) != 2 {
		t.Errorf("cycle after attempt 2 = %+v (the set must not grow)", c)
	}

	// Still open after the second rebuild: exhausted, nothing raised, the cycle is closed.
	out, err = loop.Evaluate(ctx, "rel-1", "ev-3", "env-3")
	if err != nil || out.State != app.OutcomeExhausted || out.NextAttempt != 0 || out.Attempt != 2 || !reflect.DeepEqual(out.Open, []string{"CVE-2026-2"}) {
		t.Fatalf("exhausted = %+v (err %v)", out, err)
	}
	if out.Snapshot(2)[app.SnapshotRebuildState] != "exhausted" || out.Snapshot(2)[app.SnapshotRebuildAttempt] != "2" {
		t.Errorf("exhausted snapshot = %v", out.Snapshot(2))
	}
	if _, raised, err := loop.Raise(ctx, lineage, "env-3", out, "prod-1", "prj-1"); err != nil || raised {
		t.Fatalf("exhaustion must raise nothing: %v / %v", raised, err)
	}
	if c := cycles.rows["rel-1"]; c.State != app.CycleExhausted || c.Attempts != 2 {
		t.Errorf("cycle after exhaustion = %+v", c)
	}
	if n := len(store.created); n != 2 {
		t.Errorf("rebuild intents = %d, want exactly the two attempts", n)
	}

	// A later new SBOM opens a NEW cycle (the old one is closed), and when its targets all close
	// the cycle succeeds with nothing raised.
	out, err = loop.Evaluate(ctx, "rel-1", "ev-4", "env-4")
	if err != nil || out.State != app.OutcomeOpened || len(cycles.all) != 2 {
		t.Fatalf("new cycle = %+v (err %v, cycles %d)", out, err, len(cycles.all))
	}
	posture.rows = rows(map[string]int{"CVE-2026-3": 40})
	out, err = loop.Evaluate(ctx, "rel-1", "ev-5", "env-5")
	// The new cycle targeted only CVE-2026-7: CVE-2026-2 had dropped to Medium by then.
	if err != nil || out.State != app.OutcomeSucceeded || out.NextAttempt != 0 || len(out.Open) != 0 || !reflect.DeepEqual(out.Closed, []string{"CVE-2026-7"}) {
		t.Fatalf("succeeded = %+v (err %v)", out, err)
	}
	if _, raised, _ := loop.Raise(ctx, lineage, "env-5", out, "", ""); raised {
		t.Error("success must raise nothing")
	}
	if c := cycles.rows["rel-1"]; c.State != app.CycleSucceeded {
		t.Errorf("cycle after success = %+v", c)
	}
}

// Failure shapes: no posture reader, a failed read, and each cycle-store failure surface — the
// inbox transaction then rolls the evaluation back and retries it, which is the one safe answer.
func TestRebuildLoop_Failures(t *testing.T) {
	ctx := context.Background()
	if _, err := app.NewRebuildLoop(newCyclesMem(), nil, nil, intentClock{}, 0).Evaluate(ctx, "rel-1", "ev-1", "env-1"); !errors.Is(err, app.ErrLoopUnavailable) {
		t.Errorf("no posture: %v", err)
	}
	loop, cycles, posture, store := loopFixture(0)
	if loop.MaxAttempts() != 2 {
		t.Errorf("max attempts below 1 must take the default 2, got %d", loop.MaxAttempts())
	}
	posture.err = errors.New("governance down")
	if _, err := loop.Evaluate(ctx, "rel-1", "ev-1", "env-1"); err == nil {
		t.Error("a failed posture read must surface")
	}
	posture.err = nil
	posture.rows = rows(map[string]int{"CVE-2026-1": 95})
	cycles.openErr = errors.New("db down")
	if _, err := loop.Evaluate(ctx, "rel-1", "ev-1", "env-1"); err == nil {
		t.Error("a failed open-cycle read must surface")
	}
	cycles.openErr = nil
	cycles.createErr = errors.New("db down")
	if _, err := loop.Evaluate(ctx, "rel-1", "ev-1", "env-1"); err == nil {
		t.Error("a failed create must surface")
	}
	cycles.createErr = nil
	out, err := loop.Evaluate(ctx, "rel-1", "ev-1", "env-1")
	if err != nil || out.State != app.OutcomeOpened {
		t.Fatalf("open: %+v %v", out, err)
	}
	cycles.updateErr = errors.New("db down")
	if _, err := loop.Evaluate(ctx, "rel-1", "ev-2", "env-2"); err == nil {
		t.Error("a failed update must surface")
	}
	cycles.updateErr = nil
	// A raise whose intent cannot be created surfaces too.
	store.err = errors.New("db down")
	if _, _, err := loop.Raise(ctx, lineage(), "env-1", out, "", ""); err == nil {
		t.Error("a failed enqueue must surface")
	}
}
