package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The retry policy as itself: 1s, doubling, saturating at 1m — and a cap that holds rather than
// overshooting, because the step before the cap doubles past it.
func TestNextEvaluationBackoff(t *testing.T) {
	for _, tc := range []struct{ prev, want time.Duration }{
		{0, app.EvaluationBackoffStart},
		{-time.Second, app.EvaluationBackoffStart},
		{time.Second, 2 * time.Second},
		{2 * time.Second, 4 * time.Second},
		{16 * time.Second, 32 * time.Second},
		{32 * time.Second, app.EvaluationBackoffMax},
		{app.EvaluationBackoffMax, app.EvaluationBackoffMax},
		{5 * time.Minute, app.EvaluationBackoffMax},
	} {
		if got := app.NextEvaluationBackoff(tc.prev); got != tc.want {
			t.Errorf("NextEvaluationBackoff(%s) = %s, want %s", tc.prev, got, tc.want)
		}
	}
}

// The schedule as the worker applies it: the wait doubles with each failed pass and never
// exceeds the cap, so a dependency that is down for an hour is retried ~1m apart, not 5s apart.
func TestWorker_BackoffDoublesPerRowAndSaturates(t *testing.T) {
	ctx := context.Background()
	q, worker, identity, _ := evaluationWorker(t, "prod-1", "prj-1")
	identity.failUntil = 1_000 // down for the whole test
	record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

	wait := app.EvaluationBackoffStart
	for attempt := 1; attempt <= 8; attempt++ {
		worker.Tick(ctx)
		if identity.calls != attempt {
			t.Fatalf("attempt %d: Registry calls = %d, want %d", attempt, identity.calls, attempt)
		}
		// One tick short of the wait changes nothing...
		worker.clock.advance(wait - time.Millisecond)
		worker.Tick(ctx)
		if identity.calls != attempt {
			t.Fatalf("attempt %d: retried %s early", attempt, wait)
		}
		// ...and the wait expiring lets the row through again.
		worker.clock.advance(time.Millisecond)
		wait = app.NextEvaluationBackoff(wait)
	}
	if wait != app.EvaluationBackoffMax {
		t.Errorf("after 8 failures the wait is %s, want the %s cap", wait, app.EvaluationBackoffMax)
	}
	if len(q.pending()) != 1 {
		t.Error("eight failures must still leave the row pending — nothing is ever dropped")
	}
}

// A successful publish clears the row's schedule, so a LATER failure on a different row (or the
// same release's next SBOM) starts again at 1s rather than inheriting a punished delay.
func TestWorker_SuccessClearsTheSchedule(t *testing.T) {
	ctx := context.Background()
	q, worker, identity, _ := evaluationWorker(t, "prod-1", "prj-1")
	identity.failUntil = 1
	record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

	worker.Tick(ctx) // fails → 1s wait
	worker.clock.advance(app.EvaluationBackoffStart)
	worker.Tick(ctx) // succeeds
	if n := len(q.publishedEvents()); n != 1 {
		t.Fatalf("published %d event(s), want 1", n)
	}

	// The next SBOM of the same release fails once and waits 1s — not 2s.
	identity.failUntil = 3
	record2(t, q, "rel-1", "ev-2", domain.CauseRediscovery)
	worker.Tick(ctx)
	before := identity.calls
	worker.clock.advance(app.EvaluationBackoffStart - time.Millisecond)
	worker.Tick(ctx)
	if identity.calls != before {
		t.Error("retried before the 1s wait elapsed")
	}
	worker.clock.advance(time.Millisecond)
	worker.Tick(ctx)
	if identity.calls != before+1 {
		t.Error("a fresh failure must wait 1s, not inherit the previous row's delay")
	}
}

// A store that cannot be read is reported and changes nothing: no identity lookup, no
// publication. The pass is simply a no-op the next one repeats.
func TestWorker_QueueReadFailureIsReportedAndInert(t *testing.T) {
	q, worker, identity, log := evaluationWorker(t, "prod-1", "prj-1")
	q.listErr = errors.New("db down")

	worker.Tick(context.Background())

	if identity.calls != 0 {
		t.Error("a failed queue read must not reach Registry")
	}
	if log.count() != 1 || !errors.Is(log.problems[0].err, q.listErr) {
		t.Errorf("problems = %+v, want the store error", log.problems)
	}
	if log.problems[0].releaseID != "" {
		t.Error("a queue-wide failure names no release")
	}
}

// The two per-row store failures after identity resolves: counting, and publish-and-mark. Both
// leave the row pending, which is the only acceptable outcome — the event is the rebuild loop's
// only trigger, so a lost row is a Release that is never evaluated again.
func TestWorker_CountAndPublishFailuresLeaveTheRowPending(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		set  func(q *evalQueue, err error)
	}{
		{"counting fails", func(q *evalQueue, err error) { q.countErr = err }},
		{"publish-and-mark fails", func(q *evalQueue, err error) { q.publishErr = err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, worker, _, log := evaluationWorker(t, "prod-1", "prj-1")
			boom := errors.New("boom")
			record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)
			tc.set(q, boom)

			worker.Tick(ctx)

			if n := len(q.publishedEvents()); n != 0 {
				t.Errorf("published %d event(s) despite the failure", n)
			}
			if len(q.pending()) != 1 {
				t.Error("the row must stay pending")
			}
			if log.count() != 1 || !errors.Is(log.problems[0].err, boom) {
				t.Errorf("problems = %+v, want the store error", log.problems)
			}

			// The failure clears and the next pass publishes the SAME row — nothing was lost.
			tc.set(q, nil)
			worker.clock.advance(app.EvaluationBackoffStart)
			worker.Tick(ctx)
			if n := len(q.publishedEvents()); n != 1 {
				t.Errorf("published %d event(s) after recovery, want 1", n)
			}
		})
	}
}

// A nil log is silent, not a panic: the reporting seam is optional (a composition root without a
// logger must still get a working worker).
func TestWorker_NilLogIsSilent(t *testing.T) {
	q := newEvalQueue()
	identity := &stubIdentity{failUntil: 1}
	worker := app.NewReleaseEvaluationWorker(q, identity, newStepClock(), nil)
	record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

	worker.Tick(context.Background()) // the failure path, with nowhere to report it
	if len(q.pending()) != 1 {
		t.Error("the row must still be pending")
	}
}

// The loop: it drains on its cadence and stops when the context is cancelled. Run uses the
// 5s default; RunEvery is the same loop at a cadence a test can wait for.
func TestWorker_RunEveryDrainsAndStops(t *testing.T) {
	q, worker, _, _ := evaluationWorker(t, "prod-1", "prj-1")
	record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.w.RunEvery(ctx, time.Millisecond)
		close(done)
	}()

	deadline := time.After(2 * time.Second)
	for len(q.publishedEvents()) == 0 {
		select {
		case <-deadline:
			t.Fatal("the loop never published the pending row")
		case <-time.After(time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop did not stop on cancellation")
	}

	// Run is the same loop on the fixed default cadence: an already-cancelled context returns
	// immediately, without a pass.
	stopped, stop := context.WithCancel(context.Background())
	stop()
	worker.w.Run(stopped)
}

// record2 enqueues a second fact for a release that already has one (record asserts exactly one
// pending row, which is the right assertion for the first).
func record2(t *testing.T, q *evalQueue, releaseID, sbomID, cause string) {
	t.Helper()
	coord := app.NewCoordinator(writeSvc(&fakeRepo{})).WithEvaluations(q)
	if err := coord.OnReleaseCorrelationCompleted(context.Background(), app.InboundReleaseCorrelationCompleted{
		ReleaseID: releaseID, SBOMID: sbomID, Cause: cause,
	}); err != nil {
		t.Fatalf("record %s/%s: %v", releaseID, sbomID, err)
	}
}

// A Coordinator with no queue wired ignores the fact rather than failing: the seam is optional,
// and an un-wired notification must not halt the Knowledge stream.
func TestCoordinator_ReleaseCorrelationCompleted_WithoutQueueIsInert(t *testing.T) {
	coord := app.NewCoordinator(writeSvc(&fakeRepo{}))
	if err := coord.OnReleaseCorrelationCompleted(context.Background(), app.InboundReleaseCorrelationCompleted{
		ReleaseID: "rel-1", SBOMID: "ev-1", Cause: domain.CauseNewSBOM,
	}); err != nil {
		t.Errorf("err = %v, want nil (no queue wired ⇒ inert)", err)
	}
}

// A store write that fails IS returned to the caller, so the bus retries the envelope: the row
// is the only record that the Release needs evaluating, and losing it loses the trigger.
func TestCoordinator_ReleaseCorrelationCompleted_StoreErrorPropagates(t *testing.T) {
	q := newEvalQueue()
	boom := errors.New("insert failed")
	coord := app.NewCoordinator(writeSvc(&fakeRepo{})).WithEvaluations(failingQueue{err: boom})
	if err := coord.OnReleaseCorrelationCompleted(context.Background(), app.InboundReleaseCorrelationCompleted{
		ReleaseID: "rel-1", SBOMID: "ev-1", Cause: domain.CauseNewSBOM,
	}); !errors.Is(err, boom) {
		t.Errorf("err = %v, want the store error", err)
	}
	if len(q.pending()) != 0 {
		t.Error("nothing recorded")
	}
}

type failingQueue struct{ err error }

func (f failingQueue) EnqueuePendingReleaseEvaluation(context.Context, string, string, string) error {
	return f.err
}
