package app

import (
	"context"
	"errors"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

// The release-evaluation worker (EDR-DELIVERY-01 N-M2b) is the second half of a deliberately
// split path. The inbound handler only RECORDS that a Release is due for evaluation, inside the
// bus reader's inbox transaction; everything that can fail against another service happens
// here, on a background loop where a failure costs a retry instead of the pipeline. The reason
// is EDR-EVENTBUS-01 D8: a handler error halts the whole Knowledge stream into Governance after
// five attempts, so resolving identity on the reader path would let a Registry outage stop
// Findings from opening.
//
// The worker's three guarantees, in the order they matter:
//   - it never publishes a blank product or project id (an unresolved identity is a deferral),
//   - it never drops a pending row (a failure re-reads the row on the next pass), and
//   - it never publishes twice (publish-and-mark is ONE store transaction).

const (
	// DefaultReleaseEvaluationPoll is how often the worker looks for pending rows. Fixed, not
	// configurable: it is the latency of a notification nobody is waiting on synchronously, and a
	// knob here would be a knob with no right answer to tune it against.
	DefaultReleaseEvaluationPoll = 5 * time.Second
	// The per-row retry schedule while a dependency is down: 1s, doubling, capped at 1m. In
	// memory and process-local, so a restart resets it — the rows stay pending either way, which
	// is why losing the schedule costs a retry burst and never a publication.
	EvaluationBackoffStart = time.Second
	EvaluationBackoffMax   = time.Minute
	// evaluationBatch bounds one pass. A backlog drains over several passes rather than holding
	// one long unit of work open.
	evaluationBatch = 100
)

// ErrUnresolvedReleaseIdentity is returned when Registry answers without an error but without a
// product or a project either. Treated exactly like an outage: the event's ids are what let a
// subscriber route a ticket to the right product, and a blank one would be published as fact.
var ErrUnresolvedReleaseIdentity = errors.New("governance: release identity resolved to a blank product or project")

// PendingEvaluation is one recorded, not-yet-published release evaluation.
type PendingEvaluation struct {
	// ID is the queue row's own identity — the key the publish-and-mark transaction and the
	// retry schedule both use. It is store-assigned and means nothing outside the queue.
	ID         int64
	ReleaseID  string
	SBOMID     string
	Cause      string
	ReceivedAt time.Time
}

// PendingEvaluations is the write half of the queue, used by the inbound seam. It is its own
// port because the inbound handler must be able to do EXACTLY this and nothing else.
type PendingEvaluations interface {
	// EnqueuePendingReleaseEvaluation records that (release, sbom, cause) is due for evaluation,
	// idempotently on that triple: a redelivered or repeated completion fact adds no second row.
	// It joins the caller's transaction when one is ambient (the inbox unit of work).
	EnqueuePendingReleaseEvaluation(ctx context.Context, releaseID, sbomID, cause string) error
}

// ReleaseEvaluations is the queue as the worker sees it: read the backlog, count the Release's
// Findings, publish-and-mark atomically.
type ReleaseEvaluations interface {
	PendingEvaluations
	// ListPendingReleaseEvaluations returns up to limit unpublished rows, oldest first.
	ListPendingReleaseEvaluations(ctx context.Context, limit int) ([]PendingEvaluation, error)
	// CountFindingsByBaseScoreBuckets buckets EVERY Finding of the Release by the M1b-5 ladder,
	// including the ones a Position has suppressed (M1b-4).
	CountFindingsByBaseScoreBuckets(ctx context.Context, releaseID string) (domain.SeverityCounts, error)
	// PublishEvaluatedAndMark appends the event to the outbox and marks the row published in ONE
	// transaction. The two must not be separable: an append without the mark publishes twice, and
	// a mark without the append loses the only signal the rebuild loop runs on.
	PublishEvaluatedAndMark(ctx context.Context, row PendingEvaluation, ev domain.ReleaseEvaluated, occurredAt time.Time) error
}

// ReleaseIdentityResolver resolves a Release to the project and product that own it, over
// Registry's read API. It fails CLOSED — a transport failure or a blank hop is an error, never a
// blank id (the same rule the product-scope confinement follows, EDR-DELIVERY-01 N-M0).
type ReleaseIdentityResolver interface {
	ProductAndProjectOfRelease(ctx context.Context, releaseID string) (productID, projectID string, err error)
}

// EvaluationLog is the one thing this worker needs to say out loud: a row it could not publish
// yet. A narrow port rather than the shared logger, because the app ring may not import the
// observability package (R1 — the adapter supplies the implementation); a nil log is silent.
type EvaluationLog interface {
	Error(msg, releaseID string, err error)
}

// ReleaseEvaluationWorker drains the pending-evaluation queue: resolve identity, count, publish.
type ReleaseEvaluationWorker struct {
	store    ReleaseEvaluations
	identity ReleaseIdentityResolver
	clock    Clock
	log      EvaluationLog
	// retry is the per-row backoff schedule, keyed by queue row id. Entries are dropped on a
	// successful publish; a row in backoff is skipped, never removed from the queue.
	retry map[int64]retrySchedule
}

type retrySchedule struct {
	at    time.Time
	delay time.Duration
}

// NewReleaseEvaluationWorker builds the worker. log may be nil (no reporting).
func NewReleaseEvaluationWorker(st ReleaseEvaluations, identity ReleaseIdentityResolver, clock Clock, log EvaluationLog) *ReleaseEvaluationWorker {
	return &ReleaseEvaluationWorker{store: st, identity: identity, clock: clock, log: log, retry: map[int64]retrySchedule{}}
}

// Run drains the queue on the default cadence until ctx is cancelled.
func (w *ReleaseEvaluationWorker) Run(ctx context.Context) {
	w.RunEvery(ctx, DefaultReleaseEvaluationPoll)
}

// RunEvery is Run with an explicit cadence (the seam the tests drive).
func (w *ReleaseEvaluationWorker) RunEvery(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Tick(ctx)
		}
	}
}

// Tick runs one pass over the backlog. It reports failures and returns normally: a pass that
// could not publish has changed nothing, and the rows are still there for the next one.
func (w *ReleaseEvaluationWorker) Tick(ctx context.Context) {
	rows, err := w.store.ListPendingReleaseEvaluations(ctx, evaluationBatch)
	if err != nil {
		w.report("reading the pending release-evaluation queue failed", "", err)
		return
	}
	for _, row := range rows {
		now := w.clock.Now()
		if sched, ok := w.retry[row.ID]; ok && now.Before(sched.at) {
			continue // still backing off from an earlier failure — the row stays pending
		}
		if err := w.publish(ctx, row); err != nil {
			delay := w.nextDelay(row.ID)
			w.retry[row.ID] = retrySchedule{at: now.Add(delay), delay: delay}
			w.report("release evaluation deferred — the row stays pending and will be retried", row.ReleaseID, err)
			continue
		}
		delete(w.retry, row.ID)
	}
}

// publish resolves, counts and publishes one row. Order matters: identity is resolved FIRST,
// because it is the step that fails, and counting before it would be work thrown away.
func (w *ReleaseEvaluationWorker) publish(ctx context.Context, row PendingEvaluation) error {
	productID, projectID, err := w.identity.ProductAndProjectOfRelease(ctx, row.ReleaseID)
	if err != nil {
		return err
	}
	if productID == "" || projectID == "" {
		return ErrUnresolvedReleaseIdentity
	}
	counts, err := w.store.CountFindingsByBaseScoreBuckets(ctx, row.ReleaseID)
	if err != nil {
		return err
	}
	ev := domain.NewReleaseEvaluated(productID, projectID, row.ReleaseID, row.SBOMID, row.Cause, counts)
	return w.store.PublishEvaluatedAndMark(ctx, row, ev, w.clock.Now())
}

// nextDelay is the row's next backoff step: the first failure waits EvaluationBackoffStart,
// each further one doubles, and the wait saturates at EvaluationBackoffMax.
func (w *ReleaseEvaluationWorker) nextDelay(id int64) time.Duration {
	sched, ok := w.retry[id]
	if !ok {
		return EvaluationBackoffStart
	}
	return NextEvaluationBackoff(sched.delay)
}

// NextEvaluationBackoff doubles a backoff delay up to the cap. Exported because it is the whole
// retry policy and is worth testing as itself.
func NextEvaluationBackoff(prev time.Duration) time.Duration {
	if prev <= 0 {
		return EvaluationBackoffStart
	}
	if next := prev * 2; next < EvaluationBackoffMax {
		return next
	}
	return EvaluationBackoffMax
}

func (w *ReleaseEvaluationWorker) report(msg, releaseID string, err error) {
	if w.log == nil {
		return
	}
	w.log.Error(msg, releaseID, err)
}
