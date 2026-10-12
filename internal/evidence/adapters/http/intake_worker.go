package http

import (
	"context"
	"sync"

	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// intakeQueueCapacity is how deep the overflow backlog goes before the door refuses
// to take more.
//
// ONE worker drains it, and that is the decision rather than an accident. The
// fast path does not run here — it runs on the request's own goroutine, so ordinary
// uploads stay as concurrent as the HTTP server is. What reaches this queue is the
// work that already blew the inline budget: a 50k-finding report, a large CSV. Those
// are expensive in memory as well as time, and running sixty of them at once is how
// a node dies instead of degrading. Serialized, a backlog gets slower; parallelized,
// it falls over.
//
// The honest cost of the queue, recorded rather than discovered later: each job holds
// its submitted body, so a full backlog of maximum-sized submissions is
// capacity × THEMIS_INTAKE_MAX_BYTES of retained memory.
//
// Exported so a test can fill the backlog by its real size: a queue-full test that
// hard-codes 64 passes for the wrong reason the day the capacity changes.
const IntakeQueueCapacity = 64

// intakeJob is one overflowed submission: the receipt already reserved for it, and
// the command to run from the start.
//
// From the start, not from where the inline attempt stopped. An intake is not
// resumable — stages 1-6 are pure and step 7 is one transaction — so the only two
// honest options are "redo it" and "lose it". Redoing is safe because filing the same
// content twice resolves to the one document already held (D8).
type intakeJob struct {
	receipt store.IntakeReceipt
	cmd     app.IntakeCommand
}

// intakeWorker is the bounded overflow executor: one goroutine draining a queue of
// [IntakeQueueCapacity].
type intakeWorker struct {
	mu     sync.Mutex
	closed bool
	jobs   chan intakeJob
	done   chan struct{}
}

func startIntakeWorker(process func(context.Context, intakeJob)) *intakeWorker {
	w := &intakeWorker{
		jobs: make(chan intakeJob, IntakeQueueCapacity),
		done: make(chan struct{}),
	}
	go func() {
		defer close(w.done)
		for job := range w.jobs {
			// A detached context, because the work must outlive the request that
			// handed it over — that is the whole of what `202` promises.
			process(context.Background(), job)
		}
	}()
	return w
}

// enqueue takes a job if the backlog has room, and reports whether it did. It never
// blocks: a door that blocks when the backlog is full has turned a refusal the client
// could act on into a hang it cannot.
func (w *intakeWorker) enqueue(job intakeJob) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return false
	}
	select {
	case w.jobs <- job:
		return true
	default:
		return false
	}
}

// close stops accepting work and waits for the backlog to drain. Taking the lock
// before closing the channel is what makes a submission arriving mid-shutdown a
// `503` rather than a panic on a closed channel.
func (w *intakeWorker) close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	close(w.jobs)
	w.mu.Unlock()
	<-w.done
}

// process runs one overflowed intake to its terminal state and records the outcome
// on the receipt the client is holding a URL to.
func (i *Intake) process(ctx context.Context, job intakeJob) {
	receipt, err := i.run.Intake(ctx, job.cmd)
	if receipt == nil {
		i.log.Error("overflowed intake returned no receipt",
			observability.String("intake_id", job.receipt.IntakeID), observability.Err(err))
		return
	}
	if err != nil {
		i.log.Error("overflowed intake failed",
			observability.String("intake_id", job.receipt.IntakeID), observability.Err(err))
	}
	if _, perr := i.persist(ctx, i.merge(ctx, job.receipt, receipt, err)); perr != nil {
		// The work landed (or was refused) but the receipt could not be advanced.
		// Nothing can be told to the client — it is holding a status URL — so the
		// log is the only honest record, and a receipt stuck non-terminal is closed
		// out by the next startup's recovery sweep.
		i.log.Error("overflowed intake could not advance its receipt",
			observability.String("intake_id", job.receipt.IntakeID), observability.Err(perr))
	}
}
