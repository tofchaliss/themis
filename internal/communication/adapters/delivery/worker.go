package delivery

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Worker drains the delivery-intent queue: it claims due pending intents, hands each to the
// deliverer for its type, and records the outcome. It is the ONLY half of the outward path
// that talks to an external system — the event reader never does — so an unreachable Jira or
// mail relay costs retries here and nothing at all on the bus reader path (EDR-DELIVERY-01
// RC-7: external availability never blocks or changes Themis truth).
//
// A failed attempt is an OUTCOME, not an error: it is recorded, backed off and retried, and
// RunOnce reports an error only when the STORE fails (the one failure that means the record of
// what happened is itself unreliable).
//
// Honest limit: the claim is a plain read ordered by due time, so two Communication NODES
// draining the same database can both pick up the same intent. In-process concurrency is
// safe — one fetcher feeds the worker goroutines — and a send is required to be idempotent
// per intent id, which is what makes the cross-node case a duplicate-suppression question for
// the real senders in N-M1b rather than a correctness hole here.
type Worker struct {
	cfg        Config
	intents    app.DeliveryIntents
	svc        *app.DeliveryIntentService
	deliverers map[app.IntentType]IntentDeliverer
	logger     *observability.Logger
	now        func() time.Time
}

// NewWorker wires the worker over the intent store, the intent service (which it needs to
// enqueue the dead-letter notification) and one deliverer per intent type. Out-of-range config
// values fall back to their documented defaults; a nil logger becomes a no-op logger.
func NewWorker(cfg Config, intents app.DeliveryIntents, svc *app.DeliveryIntentService, deliverers map[app.IntentType]IntentDeliverer, logger *observability.Logger) *Worker {
	if logger == nil {
		logger = observability.Nop()
	}
	return &Worker{
		cfg:        cfg.withDefaults(),
		intents:    intents,
		svc:        svc,
		deliverers: deliverers,
		logger:     logger,
		now:        func() time.Time { return time.Now().UTC() },
	}
}

// WithClock overrides the worker's clock (tests drive backoff without waiting for it).
func (w *Worker) WithClock(now func() time.Time) *Worker {
	w.now = now
	return w
}

// Run drains the queue on the configured cadence until ctx is done. It returns immediately
// when delivery is disabled, so a composition root can call it unconditionally.
func (w *Worker) Run(ctx context.Context) {
	if !w.cfg.Enabled {
		w.logger.Info("outward delivery disabled (THEMIS_COMMUNICATION_DELIVERY_ENABLED != 1)")
		return
	}
	w.logger.Info("outward delivery worker started", observability.String("config", w.cfg.String()))
	ticker := time.NewTicker(w.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := w.RunOnce(ctx); err != nil {
				w.logger.Error("delivery pass failed", observability.Err(err))
			}
		}
	}
}

// RunOnce claims one batch of due intents, sends them over cfg.Workers goroutines, and
// returns how many were delivered. One fetcher plus N senders is what keeps two goroutines in
// this process from claiming the same intent.
func (w *Worker) RunOnce(ctx context.Context) (int, error) {
	batch, err := w.intents.GetPendingForWork(ctx, w.now(), w.cfg.Batch)
	if err != nil {
		return 0, err
	}
	if len(batch) == 0 {
		return 0, nil
	}

	jobs := make(chan app.Intent)
	var (
		mu        sync.Mutex
		delivered int
		firstErr  error
		wg        sync.WaitGroup
	)
	for i := 0; i < w.cfg.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for in := range jobs {
				ok, err := w.process(ctx, in)
				mu.Lock()
				if ok {
					delivered++
				}
				if err != nil && firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}()
	}
	for _, in := range batch {
		jobs <- in
	}
	close(jobs)
	wg.Wait()
	return delivered, firstErr
}

// process attempts one intent. It returns (true, nil) when the intent was delivered, and a
// non-nil error only when the STORE failed.
func (w *Worker) process(ctx context.Context, in app.Intent) (bool, error) {
	// Already exhausted before this pass — the attempt that spent the last try landed but the
	// dead-letter transition did not (a crash between the two writes). Finish it rather than
	// sending again: the attempt was already made.
	if in.Attempts >= w.cfg.MaxAttempts {
		return false, w.deadLetter(ctx, in, in.LastError)
	}

	deliverer, ok := w.deliverers[in.Type]
	if !ok {
		return false, w.failed(ctx, in, Result{}, fmt.Errorf("no deliverer wired for intent type %q", in.Type))
	}

	res, err := deliverer.DeliverIntent(ctx, in)
	if err != nil {
		return false, w.failed(ctx, in, res, err)
	}

	at := w.now()
	if rerr := w.intents.RecordAttempt(ctx, app.Attempt{
		IntentID: in.ID, AttemptNo: in.Attempts + 1, Outcome: app.AttemptSuccess,
		StatusCode: res.StatusCode, ResponseExcerpt: res.Excerpt, At: at, NextAttemptAt: at,
	}); rerr != nil {
		return false, rerr
	}
	if merr := w.intents.MarkDelivered(ctx, in.ID, res.Metadata); merr != nil {
		return false, merr
	}
	w.logger.Info("delivery intent delivered", w.fields(in, in.Attempts+1)...)
	return true, nil
}

// failed records the failed attempt, schedules the backoff, and dead-letters the intent when
// the attempt budget is spent.
func (w *Worker) failed(ctx context.Context, in app.Intent, res Result, cause error) error {
	attemptNo := in.Attempts + 1
	at := w.now()
	next := at.Add(backoffFor(attemptNo, w.cfg.BackoffInitial, w.cfg.BackoffMax))
	if rerr := w.intents.RecordAttempt(ctx, app.Attempt{
		IntentID: in.ID, AttemptNo: attemptNo, Outcome: app.AttemptFailure,
		StatusCode: res.StatusCode, ResponseExcerpt: res.Excerpt, Error: cause.Error(),
		At: at, NextAttemptAt: next,
	}); rerr != nil {
		return rerr
	}
	w.logger.Warn("delivery attempt failed",
		append(w.fields(in, attemptNo), observability.Err(cause), observability.Duration("retry_in", next.Sub(at)))...)

	if attemptNo >= w.cfg.MaxAttempts {
		in.Attempts = attemptNo
		return w.deadLetter(ctx, in, cause.Error())
	}
	return nil
}

// deadLetter gives up on the intent and tells a person — by enqueuing an operations mail
// INTENT, never by sending one inline (the worker's own failure path must not depend on the
// channel that just failed).
//
// An intent that IS a dead-letter notification does not get another one: one unreachable mail
// relay would otherwise fill the table with notifications about notifications. It is logged at
// error instead, which is the alert that matters when the telling-a-person channel is the
// broken one.
func (w *Worker) deadLetter(ctx context.Context, in app.Intent, lastError string) error {
	if err := w.intents.MarkDeadLetter(ctx, in.ID, lastError); err != nil {
		return err
	}
	w.logger.Error("delivery intent dead-lettered", append(w.fields(in, in.Attempts),
		observability.String("last_error", lastError))...)

	if in.IsDeadLetterNotification() {
		w.logger.Error("the dead-letter NOTIFICATION itself could not be delivered — no further notification is enqueued",
			w.fields(in, in.Attempts)...)
		return nil
	}
	if _, err := w.svc.EnqueueDeadLetterMail(ctx, in.Lineage, in.ID, w.cfg.DeadLetterAudience, map[string]string{
		"dead_letter_type":        string(in.Type),
		"dead_letter_destination": in.Destination,
		"dead_letter_error":       lastError,
	}); err != nil {
		return err
	}
	return nil
}

// fields are the correlation fields every delivery log line carries. The payload bytes and
// the snapshot are deliberately absent: a delivery body is outward content, and telemetry is
// not an outward channel.
func (w *Worker) fields(in app.Intent, attempt int) []observability.Field {
	return []observability.Field{
		observability.String("intent_id", in.ID),
		observability.String("intent_type", string(in.Type)),
		observability.String("destination", in.Destination),
		observability.String("origin_event_id", in.OriginEventID),
		observability.String("correlation_id", in.Lineage.CorrelationID),
		observability.Int("attempt", attempt),
	}
}

// backoffFor is the exponential schedule: initial, doubling per attempt, capped at max.
// attempt is 1-based, so the first failure waits `initial`.
func backoffFor(attempt int, initial, max time.Duration) time.Duration {
	delay := initial
	for i := 1; i < attempt; i++ {
		if delay >= max {
			return max
		}
		delay *= 2
	}
	if delay > max {
		return max
	}
	return delay
}
