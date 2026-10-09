package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// TestReleaseEvaluatedEvent_ZeroCounts_AndCauseMapping is N-M2b's acceptance test
// (EDR-DELIVERY-01 M2-2 / M2-3): what Governance publishes when Knowledge says it has finished
// correlating an SBOM.
//
// It drives the REAL path end to end inside the app ring — the inbound use case records a
// pending row, the worker resolves identity, counts and publishes — because the split between
// the two is the point of the step, and a test of either half alone would not notice if the
// halves stopped meeting.
func TestReleaseEvaluatedEvent_ZeroCounts_AndCauseMapping(t *testing.T) {
	ctx := context.Background()

	// (a) ZERO COUNTS ARE THE SUCCESS CASE. An SBOM that matched nothing still publishes, with
	// all four counts zero: a subscriber cannot otherwise tell "evaluated, clean" from "not
	// evaluated yet" or from "the pipeline is broken" (M2-2).
	t.Run("zero counts publish, snake_case with integer counts", func(t *testing.T) {
		q, worker, _, _ := evaluationWorker(t, "prod-1", "prj-1")
		record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

		worker.Tick(ctx)

		ev := onlyPublished(t, q)
		if ev.event.SeverityCounts != (domain.SeverityCounts{}) {
			t.Errorf("counts = %+v, want all zero", ev.event.SeverityCounts)
		}
		// The wire shape is asserted as BYTES, because snake_case and integer counts are the
		// contract — a Go-field-name body or a float count would satisfy every struct comparison
		// above and still break every consumer.
		raw, err := json.Marshal(ev.event)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		const want = `{"product_id":"prod-1","project_id":"prj-1","release_id":"rel-1","sbom_id":"ev-1",` +
			`"severity_counts":{"critical":0,"high":0,"medium":0,"low":0},"cause":"new_sbom"}`
		if string(raw) != want {
			t.Errorf("body =\n  %s\nwant\n  %s", raw, want)
		}
		if len(q.pending()) != 0 {
			t.Error("a published row must be marked published, not re-offered")
		}
	})

	// (b) BOTH CAUSES ARE MAPPED VERBATIM. Governance never re-derives the cause: the producer
	// knows why correlation ran, and a consumer inferring it would be guessing (M2-3).
	t.Run("both causes map verbatim", func(t *testing.T) {
		for _, cause := range []string{domain.CauseNewSBOM, domain.CauseRediscovery} {
			q, worker, _, _ := evaluationWorker(t, "prod-1", "prj-1")
			record(t, q, "rel-1", "ev-1", cause)

			worker.Tick(ctx)

			if got := onlyPublished(t, q).event.Cause; got != cause {
				t.Errorf("cause = %q, want %q", got, cause)
			}
		}
	})

	// (c) A THIRD CAUSE IS REFUSED, and refused means NOTHING RECORDED: `cause` is a closed enum
	// on the published event, so admitting a third value would open it for every consumer
	// downstream. No row ⇒ no publication attempt.
	t.Run("a third cause is refused and records nothing", func(t *testing.T) {
		q, worker, identity, _ := evaluationWorker(t, "prod-1", "prj-1")
		coord := app.NewCoordinator(writeSvc(&fakeRepo{})).WithEvaluations(q)

		for _, bad := range []string{"other", "", "NEW_SBOM", "rebuild"} {
			err := coord.OnReleaseCorrelationCompleted(ctx, app.InboundReleaseCorrelationCompleted{
				ReleaseID: "rel-1", SBOMID: "ev-1", Cause: bad,
			})
			if !errors.Is(err, app.ErrUnknownDiscoveryCause) {
				t.Errorf("cause %q: err = %v, want ErrUnknownDiscoveryCause", bad, err)
			}
		}
		if len(q.pending()) != 0 {
			t.Errorf("a refused cause must enqueue nothing, got %d row(s)", len(q.pending()))
		}

		// A valid cause with no subject is refused the same way — a row keyed on a blank id could
		// never resolve to anything.
		for _, m := range []app.InboundReleaseCorrelationCompleted{
			{ReleaseID: "", SBOMID: "ev-1", Cause: domain.CauseNewSBOM},
			{ReleaseID: "rel-1", SBOMID: "", Cause: domain.CauseNewSBOM},
		} {
			if err := coord.OnReleaseCorrelationCompleted(ctx, m); !errors.Is(err, app.ErrInvalidEvaluationSubject) {
				t.Errorf("%+v: err = %v, want ErrInvalidEvaluationSubject", m, err)
			}
		}

		worker.Tick(ctx)
		if n := len(q.publishedEvents()); n != 0 {
			t.Errorf("published %d event(s) with nothing recorded", n)
		}
		if identity.calls != 0 {
			t.Errorf("Registry was asked %d time(s) for a refused event", identity.calls)
		}
	})

	// (d) THE LADDER AT ITS EDGES (M1b-5): each floor belongs to its own bucket, and a
	// `base_score` of 0 is Unknown — counted nowhere, least of all as `low`.
	t.Run("ladder edges 90/70/40/1/0", func(t *testing.T) {
		q, worker, _, _ := evaluationWorker(t, "prod-1", "prj-1")
		// Five Findings on the release, one per edge. The 0 is a card with no severity evidence;
		// one of the others stands for a SUPPRESSED Finding, which is counted all the same (M1b-4).
		q.scores["rel-1"] = []int{90, 70, 40, 1, 0}
		record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

		worker.Tick(ctx)

		got := onlyPublished(t, q).event.SeverityCounts
		want := domain.SeverityCounts{Critical: 1, High: 1, Medium: 1, Low: 1}
		if got != want {
			t.Errorf("counts = %+v, want %+v (the 0 is counted nowhere)", got, want)
		}
	})

	// (e) A REGISTRY OUTAGE DELAYS, it does not lose. The row stays pending, the failure is
	// reported, the backoff spaces the retries, and the publication happens EXACTLY ONCE when
	// Registry answers again. Nothing is ever published with a blank product or project.
	t.Run("a registry outage delays but loses nothing", func(t *testing.T) {
		q, worker, identity, log := evaluationWorker(t, "prod-1", "prj-1")
		clock := worker.clock
		identity.failUntil = 2
		q.scores["rel-1"] = []int{95}
		record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

		worker.w.Tick(ctx) // outage 1
		if n := len(q.publishedEvents()); n != 0 {
			t.Fatalf("published %d event(s) while Registry was down", n)
		}
		if len(q.pending()) != 1 {
			t.Fatal("the row must stay pending while Registry is down — nothing is dropped")
		}

		// Still inside the 1s backoff: the pass skips the row rather than hammering Registry.
		worker.w.Tick(ctx)
		if identity.calls != 1 {
			t.Errorf("Registry calls = %d, want 1 — the row is backing off", identity.calls)
		}

		clock.advance(app.EvaluationBackoffStart)
		worker.w.Tick(ctx) // outage 2 → the next wait doubles
		if identity.calls != 2 {
			t.Errorf("Registry calls = %d, want 2", identity.calls)
		}
		clock.advance(app.EvaluationBackoffStart)
		worker.w.Tick(ctx)
		if identity.calls != 2 {
			t.Errorf("Registry calls = %d, want 2 — the second wait is 2s, not 1s", identity.calls)
		}

		clock.advance(2 * app.EvaluationBackoffStart)
		worker.w.Tick(ctx) // Registry is back
		ev := onlyPublished(t, q)
		if ev.event.ProductID != "prod-1" || ev.event.ProjectID != "prj-1" {
			t.Errorf("ids = %q/%q, want prod-1/prj-1", ev.event.ProductID, ev.event.ProjectID)
		}
		if ev.event.SeverityCounts != (domain.SeverityCounts{Critical: 1}) {
			t.Errorf("counts = %+v, want one critical", ev.event.SeverityCounts)
		}
		if len(q.pending()) != 0 {
			t.Error("the row must be marked published once it has been published")
		}

		// A further pass publishes nothing a second time (the row is marked, and the store's
		// publish-and-mark is one guarded transaction).
		worker.w.Tick(ctx)
		if n := len(q.publishedEvents()); n != 1 {
			t.Errorf("published %d event(s), want exactly 1", n)
		}
		if log.count() != 2 {
			t.Errorf("reported %d problem(s), want one per outage pass", log.count())
		}
		for _, p := range log.problems {
			if !errors.Is(p.err, errRegistryDown) || p.releaseID != "rel-1" {
				t.Errorf("problem = %+v, want the Registry error against rel-1", p)
			}
		}
	})

	// (e′) The same rule for the quieter failure: Registry answers 200 with a blank hop. It is
	// NOT a publishable identity — a blank product id would state that the Release belongs to
	// nothing, and a subscriber would route its ticket nowhere.
	t.Run("a blank product or project is never published", func(t *testing.T) {
		for _, tc := range []struct{ name, product, project string }{
			{"blank product", "", "prj-1"},
			{"blank project", "prod-1", ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				q, worker, _, log := evaluationWorker(t, tc.product, tc.project)
				record(t, q, "rel-1", "ev-1", domain.CauseNewSBOM)

				worker.Tick(ctx)

				if n := len(q.publishedEvents()); n != 0 {
					t.Errorf("published %d event(s) with a blank id", n)
				}
				if len(q.pending()) != 1 {
					t.Error("the row must stay pending — a blank id is a deferral, not a drop")
				}
				if log.count() != 1 || !errors.Is(log.problems[0].err, app.ErrUnresolvedReleaseIdentity) {
					t.Errorf("problems = %+v, want ErrUnresolvedReleaseIdentity", log.problems)
				}
			})
		}
	})
}

// --- helpers --------------------------------------------------------------------------

// tickWorker bundles the worker with the clock a test moves, so a backoff assertion reads as
// "advance time, tick" rather than as plumbing.
type tickWorker struct {
	w     *app.ReleaseEvaluationWorker
	clock *stepClock
}

func (t tickWorker) Tick(ctx context.Context) { t.w.Tick(ctx) }

func evaluationWorker(t *testing.T, product, project string) (*evalQueue, tickWorker, *stubIdentity, *evalLog) {
	t.Helper()
	q := newEvalQueue()
	identity := &stubIdentity{product: product, project: project}
	clock := newStepClock()
	log := &evalLog{}
	return q, tickWorker{w: app.NewReleaseEvaluationWorker(q, identity, clock, log), clock: clock}, identity, log
}

// record drives the INBOUND use case, not the queue directly: the pending row must be the one
// the handler would have written, including its refusals.
func record(t *testing.T, q *evalQueue, releaseID, sbomID, cause string) {
	t.Helper()
	coord := app.NewCoordinator(writeSvc(&fakeRepo{})).WithEvaluations(q)
	if err := coord.OnReleaseCorrelationCompleted(context.Background(), app.InboundReleaseCorrelationCompleted{
		ReleaseID: releaseID, SBOMID: sbomID, Cause: cause,
	}); err != nil {
		t.Fatalf("record %s/%s/%s: %v", releaseID, sbomID, cause, err)
	}
	// Recording the same fact twice adds no second row (the ON CONFLICT DO NOTHING contract), so
	// a redelivered envelope cannot double-publish.
	if err := coord.OnReleaseCorrelationCompleted(context.Background(), app.InboundReleaseCorrelationCompleted{
		ReleaseID: releaseID, SBOMID: sbomID, Cause: cause,
	}); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	if n := len(q.pending()); n != 1 {
		t.Fatalf("pending rows = %d, want 1 (the enqueue is idempotent on release+sbom+cause)", n)
	}
}

func onlyPublished(t *testing.T, q *evalQueue) publishedEvaluation {
	t.Helper()
	events := q.publishedEvents()
	if len(events) != 1 {
		t.Fatalf("published %d event(s), want exactly 1", len(events))
	}
	ev := events[0]
	if ev.event.ProductID == "" || ev.event.ProjectID == "" {
		t.Errorf("published blank ids: %+v", ev.event)
	}
	if ev.occurredAt.IsZero() {
		t.Error("the published event must carry a publication time")
	}
	if ev.event.ReleaseID != ev.row.ReleaseID || ev.event.SBOMID != ev.row.SBOMID {
		t.Errorf("event %+v does not match its row %+v", ev.event, ev.row)
	}
	return ev
}
