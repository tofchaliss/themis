package delivery

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// defaultWorkerBatch is how many due intents one pass takes. Small on purpose: a pass is a
// burst of outbound calls, and a large batch turns a recovered channel into a thundering
// herd against the system that just came back.
const defaultWorkerBatch = 20

// An IntentWorker drains ONE delivery kind. One worker per kind is the isolation that makes
// N-M1a's promise true in both directions:
//
//   - from the bus: the worker runs on its own goroutine and its own ticker, reading rows
//     the governance reader already committed. A refusing Jira produces a dead-lettered row
//     and nothing else — no envelope is failed, no stream halts, no event is retried.
//   - between channels: a worker's queue is scoped by kind, so a Jira outage cannot starve
//     or block the mail worker. They share a pool and nothing else.
//
// It decides nothing about retry or dead-lettering itself; the intent's own state machine
// does (domain.DeliveryIntent), and the worker only reports the outcome. That is what keeps
// "how many tries, how long a wait" one answer rather than one per channel.
type IntentWorker struct {
	svc      *app.DeliveryIntentService
	sender   Sender
	kind     domain.DeliveryKind
	batch    int
	interval time.Duration
	logger   *observability.Logger
}

// WorkerConfig configures one per-kind worker. Zero values take sane defaults.
type WorkerConfig struct {
	Kind     domain.DeliveryKind
	Batch    int
	Interval time.Duration
}

// NewIntentWorker builds a worker for one kind over the intent use case and a sender.
func NewIntentWorker(svc *app.DeliveryIntentService, sender Sender, cfg WorkerConfig, logger *observability.Logger) *IntentWorker {
	if cfg.Batch <= 0 {
		cfg.Batch = defaultWorkerBatch
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 500 * time.Millisecond
	}
	if logger == nil {
		logger = observability.Nop()
	}
	return &IntentWorker{
		svc: svc, sender: sender, kind: cfg.Kind,
		batch: cfg.Batch, interval: cfg.Interval,
		logger: logger.Component("delivery-" + string(cfg.Kind)),
	}
}

// Kind reports which delivery channel this worker drains.
func (w *IntentWorker) Kind() domain.DeliveryKind { return w.kind }

// Interval reports this worker's poll cadence.
func (w *IntentWorker) Interval() time.Duration { return w.interval }

// Drain makes ONE pass: take the due intents of this kind and try each one. It returns how
// many were delivered. A send failure is not this method's error — it is the intent's
// outcome, recorded and returned to the queue or dead-lettered. Only a STORE failure stops
// the pass, because at that point the outcome cannot be recorded and trying the next intent
// would risk sending without a record of having done so.
//
// There are deliberately no sleeps here. When an intent is next due is state on the row
// (next_attempt_at, set from the backoff policy when the failure was recorded), so a test
// steps a clock instead of waiting, and a restarted node resumes the same schedule.
func (w *IntentWorker) Drain(ctx context.Context) (int, error) {
	intents, err := w.svc.DueIntents(ctx, w.kind, w.batch)
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, intent := range intents {
		sendErr := w.sender.Send(ctx, intent)
		// The RECORDED intent, not the one the queue handed us: after a failure the two
		// differ, and it is the recorded one that knows whether this was the last try.
		recorded, rerr := w.svc.RecordOutcome(ctx, intent, sendErr)
		if rerr != nil {
			return delivered, rerr
		}
		if sendErr != nil {
			w.logOutcome(recorded, sendErr)
			continue
		}
		delivered++
	}
	return delivered, nil
}

// logOutcome states a failed send at the severity its consequence deserves: a dead letter is
// an error a person has to act on, an intermediate failure is a warning the worker will
// handle itself. Both name the intent so the operator API can be pointed at it directly.
func (w *IntentWorker) logOutcome(intent domain.DeliveryIntent, sendErr error) {
	fields := []observability.Field{
		observability.String("intent_id", intent.ID()),
		observability.String("kind", string(intent.Kind())),
		observability.String("destination", intent.Destination()),
		observability.Int("attempts", intent.Attempts()),
		observability.Int("max_attempts", intent.MaxAttempts()),
		observability.Err(sendErr),
	}
	if intent.Status() == domain.IntentDeadLetter {
		w.logger.Error("delivery intent DEAD-LETTERED — it will not be retried until an operator retries it", fields...)
		return
	}
	w.logger.Warn("delivery attempt failed; the intent stays pending and is due again after backoff", fields...)
}

// Run drains on the configured cadence until the context is cancelled. A store error is
// logged and the loop continues: the queue is durable, so the next tick retries whatever
// this one could not read.
func (w *IntentWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := w.Drain(ctx); err != nil {
				w.logger.Error("delivery drain failed", observability.Err(err))
			} else if n > 0 {
				w.logger.Info("delivered intents", observability.Int("count", n))
			}
		}
	}
}

// Workers is the set a composition root starts — one per ENABLED kind. A kind switched off
// has no worker at all rather than a worker that refuses: its intents keep accumulating as
// PENDING, visible in the operator list, and start moving the moment it is switched on.
type Workers []*IntentWorker

// Run starts every worker on its own goroutine and returns immediately.
func (ws Workers) Run(ctx context.Context) {
	for _, w := range ws {
		go w.Run(ctx)
	}
}
