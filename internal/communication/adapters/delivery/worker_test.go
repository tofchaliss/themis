package delivery_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

var workerEpoch = time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)

// intentStore is an in-memory DeliveryIntentRepository. It keeps the attempt history so the
// tests can assert what the worker actually recorded, not just where the row ended up.
type intentStore struct {
	byID      map[string]domain.DeliveryIntent
	order     []string
	attempts  map[string][]domain.DeliveryAttempt
	dueErr    error
	recordErr error
}

func newIntentStore() *intentStore {
	return &intentStore{byID: map[string]domain.DeliveryIntent{}, attempts: map[string][]domain.DeliveryAttempt{}}
}

func (s *intentStore) SaveIntent(_ context.Context, in domain.DeliveryIntent) (bool, error) {
	if _, dup := s.byID[in.ID()]; dup {
		return false, nil
	}
	s.byID[in.ID()] = in
	s.order = append(s.order, in.ID())
	return true, nil
}

func (s *intentStore) DueIntents(_ context.Context, kind domain.DeliveryKind, now time.Time, limit int) ([]domain.DeliveryIntent, error) {
	if s.dueErr != nil {
		return nil, s.dueErr
	}
	var out []domain.DeliveryIntent
	for _, id := range s.order {
		in := s.byID[id]
		if in.Kind() != kind || in.Status() != domain.IntentPending || in.NextAttemptAt().After(now) {
			continue
		}
		if len(out) >= limit {
			break
		}
		out = append(out, in)
	}
	return out, nil
}

func (s *intentStore) RecordAttempt(_ context.Context, in domain.DeliveryIntent, att domain.DeliveryAttempt) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	s.byID[in.ID()] = in
	s.attempts[in.ID()] = append(s.attempts[in.ID()], att)
	return nil
}

func (s *intentStore) SaveIntentState(_ context.Context, in domain.DeliveryIntent) error {
	s.byID[in.ID()] = in
	return nil
}

func (s *intentStore) GetIntent(_ context.Context, id string) (domain.DeliveryIntent, error) {
	in, ok := s.byID[id]
	if !ok {
		return domain.DeliveryIntent{}, app.ErrIntentNotFound
	}
	return in, nil
}

func (s *intentStore) IntentAttempts(_ context.Context, id string) ([]domain.DeliveryAttempt, error) {
	return s.attempts[id], nil
}

func (s *intentStore) ListIntents(context.Context, app.IntentFilter) ([]domain.DeliveryIntent, error) {
	return nil, nil
}

func (s *intentStore) CountIntentsByStatus(context.Context) (map[domain.IntentStatus]int, error) {
	return nil, nil
}

type seqIDs struct{ n int }

func (g *seqIDs) NewID() string { g.n++; return fmt.Sprintf("int-%d", g.n) }

// stepClock is the injected scheduler seam: a backoff is crossed by stepping the clock, so
// no test ever sleeps and none of them is timing-dependent.
type stepClock struct{ t time.Time }

func (c *stepClock) Now() time.Time       { return c.t }
func (c *stepClock) step(d time.Duration) { c.t = c.t.Add(d) }

// fixture wires a service + store over one clock, seeded with one PENDING intent per kind.
type fixture struct {
	store *intentStore
	svc   *app.DeliveryIntentService
	clock *stepClock
}

func newFixture(t *testing.T, maxAttempts int, kinds ...domain.DeliveryKind) *fixture {
	t.Helper()
	clock := &stepClock{t: workerEpoch}
	store := newIntentStore()
	svc := app.NewDeliveryIntentService(store, &seqIDs{}, clock, app.DeliveryIntentConfig{
		MaxAttempts: maxAttempts,
		Backoff:     domain.BackoffPolicy{Base: time.Minute, Cap: 10 * time.Minute},
	})
	for i, kind := range kinds {
		origin := domain.DeliveryOrigin{
			EventID:   fmt.Sprintf("env-%d", i+1),
			EventType: "governance.finding_opened", EventTime: workerEpoch,
			FindingID: fmt.Sprintf("fnd-%d", i+1), ReleaseID: "rel-1", CVE: "CVE-2026-1",
		}
		in, err := domain.NewDeliveryIntent(fmt.Sprintf("int-%d", i+1), kind, "default", origin, maxAttempts, workerEpoch)
		if err != nil {
			t.Fatalf("seed %s: %v", kind, err)
		}
		if _, err := store.SaveIntent(context.Background(), in); err != nil {
			t.Fatalf("save %s: %v", kind, err)
		}
	}
	return &fixture{store: store, svc: svc, clock: clock}
}

func (f *fixture) worker(kind domain.DeliveryKind, sender delivery.Sender) *delivery.IntentWorker {
	return delivery.NewIntentWorker(f.svc, sender, delivery.WorkerConfig{Kind: kind}, nil)
}

// drainPast runs one pass and then steps the clock far enough that any backoff the pass just
// scheduled has elapsed, so the next pass sees the intent again.
func (f *fixture) drainPast(t *testing.T, w *delivery.IntentWorker) int {
	t.Helper()
	n, err := w.Drain(context.Background())
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	f.clock.step(time.Hour)
	return n
}

// A refusing channel must burn exactly its attempt budget, stop, keep the cause, and leave a
// complete history — that history is the whole of what an operator has to go on.
func TestWorker_FailingSenderDeadLettersAfterMaxAttempts(t *testing.T) {
	f := newFixture(t, 3, domain.DeliveryJiraIssue)
	sender := delivery.NewFakeSender(domain.DeliveryJiraIssue, delivery.FakeFail, nil)
	w := f.worker(domain.DeliveryJiraIssue, sender)

	for i := 0; i < 3; i++ {
		if n := f.drainPast(t, w); n != 0 {
			t.Fatalf("pass %d delivered %d", i, n)
		}
	}

	in := f.store.byID["int-1"]
	if in.Status() != domain.IntentDeadLetter || in.Attempts() != 3 {
		t.Errorf("state = %s attempts=%d, want DEAD_LETTER/3", in.Status(), in.Attempts())
	}
	if in.LastError() == "" {
		t.Error("dead letter with no stated cause")
	}
	if got := len(f.store.attempts["int-1"]); got != 3 {
		t.Errorf("history = %d rows, want 3", got)
	}
	for i, att := range f.store.attempts["int-1"] {
		if att.OK || att.AttemptNo != i+1 || att.Error == "" {
			t.Errorf("history[%d] = %+v", i, att)
		}
	}

	// A dead letter is OFF the queue: further passes do not touch it.
	if n := f.drainPast(t, w); n != 0 || sender.Calls("int-1") != 3 {
		t.Errorf("after dead-letter: delivered=%d calls=%d, want 0/3", n, sender.Calls("int-1"))
	}
}

func TestWorker_SucceedingSenderDelivers(t *testing.T) {
	f := newFixture(t, 3, domain.DeliveryEmail)
	sender := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil)
	w := f.worker(domain.DeliveryEmail, sender)

	if n := f.drainPast(t, w); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	if in := f.store.byID["int-1"]; in.Status() != domain.IntentDelivered || in.Attempts() != 1 {
		t.Errorf("state = %s attempts=%d, want DELIVERED/1", in.Status(), in.Attempts())
	}
	if got := len(f.store.attempts["int-1"]); got != 1 {
		t.Errorf("history = %d rows, want 1", got)
	}
	if !f.store.attempts["int-1"][0].OK {
		t.Error("the recorded attempt does not say it succeeded")
	}
	// Delivered is terminal: a later pass must not send it again.
	if n := f.drainPast(t, w); n != 0 || sender.Calls("int-1") != 1 {
		t.Errorf("after delivery: delivered=%d calls=%d, want 0/1", n, sender.Calls("int-1"))
	}
}

// The case retry exists for: a channel that is down and then comes back. The intent must
// survive its outage and deliver, with the failures still on the record.
func TestWorker_FlakySenderRecoversAndKeepsTheFailedAttempts(t *testing.T) {
	f := newFixture(t, 5, domain.DeliveryCIBuild)
	sender := delivery.NewFakeSender(domain.DeliveryCIBuild, delivery.FakeFlaky, nil)
	w := f.worker(domain.DeliveryCIBuild, sender)

	for i := 0; i < 3; i++ {
		f.drainPast(t, w)
	}
	if in := f.store.byID["int-1"]; in.Status() != domain.IntentDelivered || in.Attempts() != 3 {
		t.Errorf("state = %s attempts=%d, want DELIVERED/3", in.Status(), in.Attempts())
	}
	history := f.store.attempts["int-1"]
	if len(history) != 3 || history[0].OK || history[1].OK || !history[2].OK {
		t.Errorf("history = %+v, want fail/fail/success", history)
	}
	if got := sender.Sent(); len(got) != 1 || got[0] != "int-1" {
		t.Errorf("sent = %v", got)
	}
}

// Backoff, asserted without a single sleep: after a failure the intent is not due, and the
// worker takes it again only once the scheduled wait has elapsed.
func TestWorker_BackoffHoldsTheIntentBackUntilItIsDue(t *testing.T) {
	f := newFixture(t, 5, domain.DeliveryEmail)
	sender := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeFail, nil)
	w := f.worker(domain.DeliveryEmail, sender)

	if _, err := w.Drain(context.Background()); err != nil {
		t.Fatalf("first drain: %v", err)
	}
	if _, err := w.Drain(context.Background()); err != nil { // no time has passed
		t.Fatalf("second drain: %v", err)
	}
	if sender.Calls("int-1") != 1 {
		t.Errorf("calls = %d with no time passed, want 1 — the backoff was not honoured", sender.Calls("int-1"))
	}
	f.clock.step(time.Minute) // exactly the first backoff step
	if _, err := w.Drain(context.Background()); err != nil {
		t.Fatalf("third drain: %v", err)
	}
	if sender.Calls("int-1") != 2 {
		t.Errorf("calls = %d after the backoff elapsed, want 2", sender.Calls("int-1"))
	}
	// Each wait is longer than the last, so a persistently broken channel is not hammered.
	if got := f.store.byID["int-1"].NextAttemptAt().Sub(f.clock.Now()); got != 2*time.Minute {
		t.Errorf("second wait = %v, want the doubled 2m", got)
	}
}

// Channel isolation, which is what makes one worker per kind worth the goroutine: a Jira
// outage must not touch the mail queue.
func TestWorker_OneKindsOutageDoesNotTouchAnother(t *testing.T) {
	f := newFixture(t, 2, domain.DeliveryJiraIssue, domain.DeliveryEmail)
	jira := f.worker(domain.DeliveryJiraIssue, delivery.NewFakeSender(domain.DeliveryJiraIssue, delivery.FakeFail, nil))
	mail := f.worker(domain.DeliveryEmail, delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil))

	for i := 0; i < 2; i++ {
		f.drainPast(t, jira)
	}
	if got := f.store.byID["int-1"].Status(); got != domain.IntentDeadLetter {
		t.Fatalf("jira intent = %s, want DEAD_LETTER", got)
	}
	if got := f.store.byID["int-2"].Status(); got != domain.IntentPending {
		t.Errorf("mail intent = %s after the jira outage, want untouched PENDING", got)
	}
	if n := f.drainPast(t, mail); n != 1 {
		t.Errorf("mail delivered %d, want 1", n)
	}
	if got := f.store.byID["int-2"].Status(); got != domain.IntentDelivered {
		t.Errorf("mail intent = %s, want DELIVERED", got)
	}
}

// An operator retry puts a dead letter back in front of the worker — and the worker then
// delivers it against a recovered channel.
func TestWorker_RetriedDeadLetterIsPickedUpAgain(t *testing.T) {
	f := newFixture(t, 1, domain.DeliveryJiraIssue)
	failing := f.worker(domain.DeliveryJiraIssue, delivery.NewFakeSender(domain.DeliveryJiraIssue, delivery.FakeFail, nil))
	f.drainPast(t, failing)
	if f.store.byID["int-1"].Status() != domain.IntentDeadLetter {
		t.Fatalf("setup: %s", f.store.byID["int-1"].Status())
	}

	if _, err := f.svc.RetryIntent(context.Background(), "int-1"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	recovered := f.worker(domain.DeliveryJiraIssue, delivery.NewFakeSender(domain.DeliveryJiraIssue, delivery.FakeSuccess, nil))
	if n := f.drainPast(t, recovered); n != 1 {
		t.Fatalf("after retry delivered %d, want 1", n)
	}
	if got := len(f.store.attempts["int-1"]); got != 2 {
		t.Errorf("history = %d rows, want 2 — the retry must add to it, not erase it", got)
	}
}

// A store failure stops the pass rather than sending without being able to record it.
func TestWorker_StoreFailureStopsThePass(t *testing.T) {
	f := newFixture(t, 3, domain.DeliveryEmail)
	f.store.dueErr = errors.New("db down")
	w := f.worker(domain.DeliveryEmail, delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil))
	if n, err := w.Drain(context.Background()); err == nil || n != 0 {
		t.Errorf("drain = %d, %v; want a surfaced store error", n, err)
	}
}

// If the outcome cannot be RECORDED the pass must stop, not move on: continuing would send
// the next intent while the previous one's send is unaccounted for, and the retry after a
// restart would then double-send.
func TestWorker_UnrecordableOutcomeStopsThePass(t *testing.T) {
	f := newFixture(t, 3, domain.DeliveryEmail, domain.DeliveryEmail)
	f.store.recordErr = errors.New("db down")
	sender := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil)
	w := f.worker(domain.DeliveryEmail, sender)

	if n, err := w.Drain(context.Background()); err == nil || n != 0 {
		t.Errorf("drain = %d, %v; want a surfaced record error", n, err)
	}
	if got := len(sender.Sent()); got != 1 {
		t.Errorf("sent %d intents past an unrecordable outcome, want 1", got)
	}
}

func TestNewIntentWorker_Defaults(t *testing.T) {
	f := newFixture(t, 3)
	w := delivery.NewIntentWorker(f.svc, delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil),
		delivery.WorkerConfig{Kind: domain.DeliveryEmail}, nil)
	if w.Kind() != domain.DeliveryEmail || w.Interval() <= 0 {
		t.Errorf("worker = %s interval=%v", w.Kind(), w.Interval())
	}
}

// Run is the goroutine wrapper: it drains on its ticker and stops when the context is
// cancelled. Asserted through the observable outcome (the intent gets delivered), with a
// short interval rather than a sleep in the test body.
func TestWorkers_RunDrainsAndStopsOnCancel(t *testing.T) {
	f := newFixture(t, 3, domain.DeliveryEmail)
	sender := delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil)
	w := delivery.NewIntentWorker(f.svc, sender,
		delivery.WorkerConfig{Kind: domain.DeliveryEmail, Batch: 5, Interval: time.Millisecond}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	delivery.Workers{w}.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for f.store.byID["int-1"].Status() != domain.IntentDelivered {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("worker did not deliver: status = %s", f.store.byID["int-1"].Status())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
}

// A drain error inside Run is logged and the loop continues — the queue is durable, so the
// next tick retries whatever this one could not read.
func TestWorker_RunSurvivesAStoreFailure(t *testing.T) {
	f := newFixture(t, 3, domain.DeliveryEmail)
	f.store.dueErr = errors.New("db down")
	w := delivery.NewIntentWorker(f.svc, delivery.NewFakeSender(domain.DeliveryEmail, delivery.FakeSuccess, nil),
		delivery.WorkerConfig{Kind: domain.DeliveryEmail, Interval: time.Millisecond}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	w.Run(ctx) // returns on the context deadline, not on the store error
	if f.store.byID["int-1"].Status() != domain.IntentPending {
		t.Errorf("intent = %s, want untouched PENDING", f.store.byID["int-1"].Status())
	}
}
