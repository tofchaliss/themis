package app

// Δ4b autonomous sweep: the walking-skeleton behaviors, all without a model — the analyst is
// pure orchestration over reads + the precedent seam + the push.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// --- fakes -----------------------------------------------------------------------------

type fakeReleases struct{ ids []string }

func (f fakeReleases) ListReleaseIDs(context.Context) ([]string, error) { return f.ids, nil }

type fakePostureReader struct {
	byRelease map[string]domain.ReleasePosture
	err       error
}

func (f fakePostureReader) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	return domain.FindingAssessment{}, nil
}
func (f fakePostureReader) GetReleasePosture(_ context.Context, rel string) (domain.ReleasePosture, error) {
	if f.err != nil {
		return domain.ReleasePosture{}, f.err
	}
	return f.byRelease[rel], nil
}
func (f fakePostureReader) GetReleaseComparison(context.Context, string, string) (domain.ReleaseComparison, error) {
	return domain.ReleaseComparison{}, nil
}

// fakeIndex is a VectorIndex that returns canned precedents regardless of query — enough for the
// PrecedentService's semantic path to fire in the analyst.
type fakeIndex struct{ out []domain.PrecedentPosition }

func (f fakeIndex) Search([]float32, int, string) []domain.PrecedentPosition { return f.out }

type fakeEmbed struct{}

func (fakeEmbed) Embed(context.Context, string) ([]float32, error) { return []float32{1, 0}, nil }
func (fakeEmbed) Model() string                                    { return "fake" }

type recordingRaiser struct {
	calls []string // finding ids pushed
	err   error
}

func (r *recordingRaiser) RaiseAIProposal(_ context.Context, findingID, _, _ string) error {
	if r.err != nil {
		return r.err
	}
	r.calls = append(r.calls, findingID)
	return nil
}

type memRecorder struct{ seen map[string]bool }

func newMemRecorder() *memRecorder { return &memRecorder{seen: map[string]bool{}} }
func (m *memRecorder) HasProposed(_ context.Context, f, k string) (bool, error) {
	return m.seen[f+"|"+k], nil
}
func (m *memRecorder) RecordProposed(_ context.Context, f, k string) error {
	m.seen[f+"|"+k] = true
	return nil
}

// --- helpers ---------------------------------------------------------------------------

func undecided(findingID string, prio int) domain.PostureEntry {
	return domain.PostureEntry{FindingID: findingID, Stance: "", ResidualPriority: prio,
		Components: []domain.PostureComponent{{PURL: "pkg:golang/x@1"}}}
}

func precedent(release, cve, stance string, score float64) domain.PrecedentPosition {
	return domain.PrecedentPosition{ReleaseID: release, SourceCVE: cve, Stance: stance, Score: score}
}

func sweepWith(t *testing.T, posture map[string]domain.ReleasePosture, precs []domain.PrecedentPosition,
	raiser ProposalRaiser, rec ProposedRecorder, pool *Budget) *AutonomousSweep {
	t.Helper()
	ps := NewPrecedentService(fakeEmbed{}, fakeIndex{out: precs}, nil, 5)
	releases := make([]string, 0, len(posture))
	for r := range posture {
		releases = append(releases, r)
	}
	fixed := time.Unix(1_700_000_000, 0)
	return NewAutonomousSweep(fakeReleases{ids: releases}, fakePostureReader{byRelease: posture}, ps, raiser, rec, pool).
		WithClock(func() time.Time { return fixed })
}

// --- tests -----------------------------------------------------------------------------

func TestSweepDisabledWithoutAPool(t *testing.T) {
	raiser := &recordingRaiser{}
	s := sweepWith(t,
		map[string]domain.ReleasePosture{"rel-1": {ReleaseID: "rel-1", Entries: []domain.PostureEntry{undecided("f1", 90)}}},
		[]domain.PrecedentPosition{precedent("rel-2", "CVE-1", "not_affected", 0.9)},
		raiser, newMemRecorder(), nil)
	if s.Enabled() {
		t.Fatal("no pool must read disabled")
	}
	res, err := s.Run(context.Background())
	if err != nil || res.Proposed != 0 || len(raiser.calls) != 0 {
		t.Errorf("disabled sweep did work: res=%+v err=%v", res, err)
	}
}

func TestSweepProposesForUndecidedWithDecidedPrecedent(t *testing.T) {
	raiser := &recordingRaiser{}
	rec := newMemRecorder()
	pool := NewBudget(100, time.Hour)
	s := sweepWith(t,
		map[string]domain.ReleasePosture{"rel-1": {ReleaseID: "rel-1", Entries: []domain.PostureEntry{
			undecided("f1", 90),
			{FindingID: "f2", Stance: "affected", ResidualPriority: 80}, // decided — skipped
		}}},
		[]domain.PrecedentPosition{precedent("rel-2", "CVE-1", "not_affected", 0.9)},
		raiser, rec, pool)

	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Proposed != 1 || len(raiser.calls) != 1 || raiser.calls[0] != "f1" {
		t.Fatalf("res=%+v calls=%v — want one proposal for the undecided f1", res, raiser.calls)
	}

	// Second sweep: the pair is recorded → SKIP (quiet-by-default).
	res2, _ := s.Run(context.Background())
	if res2.Proposed != 0 || res2.Skipped == 0 {
		t.Errorf("second sweep must skip already-proposed: %+v", res2)
	}
}

func TestSweepReproposesWhenPrecedentChanges(t *testing.T) {
	raiser := &recordingRaiser{}
	rec := newMemRecorder()
	posture := map[string]domain.ReleasePosture{"rel-1": {ReleaseID: "rel-1", Entries: []domain.PostureEntry{undecided("f1", 90)}}}

	s1 := sweepWith(t, posture, []domain.PrecedentPosition{precedent("rel-2", "CVE-1", "not_affected", 0.9)}, raiser, rec, NewBudget(100, time.Hour))
	_, _ = s1.Run(context.Background())

	// The precedent changed (different stance → different key) → re-propose.
	s2 := sweepWith(t, posture, []domain.PrecedentPosition{precedent("rel-2", "CVE-1", "mitigated", 0.9)}, raiser, rec, NewBudget(100, time.Hour))
	res, _ := s2.Run(context.Background())
	if res.Proposed != 1 {
		t.Errorf("a changed precedent must re-propose: %+v (calls=%v)", res, raiser.calls)
	}
}

func TestSweepSkipsUndecidedWithNoPrecedent(t *testing.T) {
	raiser := &recordingRaiser{}
	s := sweepWith(t,
		map[string]domain.ReleasePosture{"rel-1": {ReleaseID: "rel-1", Entries: []domain.PostureEntry{undecided("f1", 90)}}},
		nil, // no precedents
		raiser, newMemRecorder(), NewBudget(100, time.Hour))
	res, _ := s.Run(context.Background())
	if res.Proposed != 0 || res.Skipped != 1 || res.Examined != 1 {
		t.Errorf("no-precedent undecided must be examined + skipped: %+v", res)
	}
}

func TestSweepDrainThenStopMidPass(t *testing.T) {
	raiser := &recordingRaiser{}
	// A pool that admits exactly one push (cost 1, limit 1).
	pool := NewBudget(1, time.Hour)
	s := sweepWith(t,
		map[string]domain.ReleasePosture{"rel-1": {ReleaseID: "rel-1", Entries: []domain.PostureEntry{
			undecided("f-hi", 95), undecided("f-lo", 40),
		}}},
		[]domain.PrecedentPosition{precedent("rel-2", "CVE-1", "not_affected", 0.9)},
		raiser, newMemRecorder(), pool)
	res, _ := s.Run(context.Background())
	if res.Proposed != 1 || !res.Paused {
		t.Fatalf("res=%+v — want exactly one proposal then paused", res)
	}
	// Worst-first: the high-priority Finding got the single slot.
	if len(raiser.calls) != 1 || raiser.calls[0] != "f-hi" {
		t.Errorf("worst-first violated: %v", raiser.calls)
	}
}

func TestSweepPushFailureIsPerFindingNotFatal(t *testing.T) {
	raiser := &recordingRaiser{err: errors.New("governance down")}
	s := sweepWith(t,
		map[string]domain.ReleasePosture{"rel-1": {ReleaseID: "rel-1", Entries: []domain.PostureEntry{
			undecided("f1", 90), undecided("f2", 80),
		}}},
		[]domain.PrecedentPosition{precedent("rel-2", "CVE-1", "not_affected", 0.9)},
		raiser, newMemRecorder(), NewBudget(100, time.Hour))
	res, err := s.Run(context.Background())
	if err != nil {
		t.Fatalf("a push failure must not fail the sweep: %v", err)
	}
	if res.PushErrs != 2 || res.Proposed != 0 {
		t.Errorf("both pushes should fail per-Finding: %+v", res)
	}
}

func TestSweepPostureReadErrorSkipsRelease(t *testing.T) {
	pool := NewBudget(100, time.Hour)
	ps := NewPrecedentService(fakeEmbed{}, fakeIndex{}, nil, 5)
	s := NewAutonomousSweep(fakeReleases{ids: []string{"rel-1"}},
		fakePostureReader{err: errors.New("db down")}, ps, &recordingRaiser{}, newMemRecorder(), pool).
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	res, err := s.Run(context.Background())
	if err != nil || res.Examined != 0 {
		t.Errorf("an unreadable release must be skipped, not fatal: res=%+v err=%v", res, err)
	}
}

type errReleases struct{}

func (errReleases) ListReleaseIDs(context.Context) ([]string, error) {
	return nil, errors.New("registry down")
}

// A release-list read failure IS fatal to the sweep (there is no work without releases) — the
// one error the sweep propagates, unlike per-release / per-Finding failures which it skips.
func TestSweepReleaseListErrorIsFatal(t *testing.T) {
	ps := NewPrecedentService(fakeEmbed{}, fakeIndex{}, nil, 5)
	s := NewAutonomousSweep(errReleases{}, fakePostureReader{}, ps, &recordingRaiser{}, newMemRecorder(), NewBudget(100, time.Hour)).
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0) })
	if _, err := s.Run(context.Background()); err == nil {
		t.Error("a release-list failure must be fatal — no releases, no work")
	}
}
