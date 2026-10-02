package delivery_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

func TestLogDelivererAndRedactor(t *testing.T) {
	art, err := domain.Materialize(domain.PositionSnapshot{
		FindingID: "fnd-1", Stance: domain.StanceNotAffected,
		Lineage: domain.Lineage{ReleaseID: "rel-1", CVE: "CVE-1"},
	}, domain.ArtifactVEX)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	pub, err := domain.NewPublication("pub-1", art, "openvex", "tooling", "export", []byte(`{"vex":true}`), "", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("NewPublication: %v", err)
	}

	payload := delivery.PassThroughRedactor{}.Redact([]byte("secret"))
	if string(payload) != "secret" {
		t.Errorf("redactor changed payload: %q", payload)
	}
	if err := delivery.NewLogDeliverer(nil).Deliver(context.Background(), pub, payload); err != nil {
		t.Errorf("deliver: %v", err)
	}
}

// --- N-M1a: the outward-delivery worker ----------------------------------------------------

var epoch = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

// memIntents is an in-memory DeliveryIntents: enough of the store's real behaviour (due-time
// filtering, counter advance, guarded transitions) that the worker's retry/dead-letter
// mechanics are tested against the contract rather than against a mock's expectations.
type memIntents struct {
	mu       sync.Mutex
	intents  map[string]*app.Intent
	order    []string
	attempts []app.Attempt

	failPending   error
	failAttempt   error
	failDelivered error
	failDeadLtr   error
	failCreate    error
}

func newMemIntents() *memIntents {
	return &memIntents{intents: map[string]*app.Intent{}}
}

func (m *memIntents) CreateIntent(_ context.Context, in app.Intent) (app.Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failCreate != nil {
		return app.Intent{}, m.failCreate
	}
	if in.OriginEventID != "" {
		for _, id := range m.order {
			if m.intents[id].OriginEventID == in.OriginEventID {
				return *m.intents[id], nil
			}
		}
	}
	stored := in
	m.intents[in.ID] = &stored
	m.order = append(m.order, in.ID)
	return stored, nil
}

func (m *memIntents) GetIntent(_ context.Context, id string) (app.Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok {
		return app.Intent{}, app.ErrIntentNotFound
	}
	return *in, nil
}

func (m *memIntents) GetPendingForWork(_ context.Context, now time.Time, limit int) ([]app.Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failPending != nil {
		return nil, m.failPending
	}
	var out []app.Intent
	for _, id := range m.order {
		in := m.intents[id]
		if in.State == app.IntentPending && !in.NextAttemptAt.After(now) {
			out = append(out, *in)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].NextAttemptAt.Before(out[j].NextAttemptAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memIntents) RecordAttempt(_ context.Context, a app.Attempt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failAttempt != nil {
		return m.failAttempt
	}
	in, ok := m.intents[a.IntentID]
	if !ok {
		return app.ErrIntentNotFound
	}
	m.attempts = append(m.attempts, a)
	in.Attempts = a.AttemptNo
	in.LastAttemptAt = a.At
	in.LastError = a.Error
	in.NextAttemptAt = a.NextAttemptAt
	return nil
}

func (m *memIntents) MarkDelivered(_ context.Context, id string, result map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failDelivered != nil {
		return m.failDelivered
	}
	in, ok := m.intents[id]
	if !ok {
		return app.ErrIntentNotFound
	}
	in.State, in.Result = app.IntentDelivered, result
	return nil
}

func (m *memIntents) MarkDeadLetter(_ context.Context, id, lastError string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failDeadLtr != nil {
		return m.failDeadLtr
	}
	in, ok := m.intents[id]
	if !ok {
		return app.ErrIntentNotFound
	}
	in.State, in.LastError = app.IntentDeadLetter, lastError
	return nil
}

func (m *memIntents) CancelIntent(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok {
		return app.ErrIntentNotFound
	}
	in.State = app.IntentCancelled
	return nil
}

func (m *memIntents) ListDeadLetters(_ context.Context, _ time.Time, limit int) ([]app.Intent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []app.Intent
	for _, id := range m.order {
		if in := m.intents[id]; in.State == app.IntentDeadLetter && len(out) < limit {
			out = append(out, *in)
		}
	}
	return out, nil
}

func (m *memIntents) RetryIntent(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.intents[id]
	if !ok {
		return app.ErrIntentNotFound
	}
	in.State, in.Attempts, in.LastError = app.IntentPending, 0, ""
	return nil
}

// get returns one stored intent for assertions.
func (m *memIntents) get(t *testing.T, id string) app.Intent {
	t.Helper()
	in, err := m.GetIntent(context.Background(), id)
	if err != nil {
		t.Fatalf("intent %s: %v", id, err)
	}
	return in
}

// attemptsFor returns the ledger rows for one intent, in order.
func (m *memIntents) attemptsFor(id string) []app.Attempt {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []app.Attempt
	for _, a := range m.attempts {
		if a.IntentID == id {
			out = append(out, a)
		}
	}
	return out
}

func (m *memIntents) countByType(typ app.IntentType) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, id := range m.order {
		if m.intents[id].Type == typ {
			n++
		}
	}
	return n
}

type seqIDs struct {
	mu sync.Mutex
	n  int
}

func (g *seqIDs) NewID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return fmt.Sprintf("int-gen-%d", g.n)
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return epoch }

// harness wires a worker over the in-memory store with a controllable clock.
type harness struct {
	intents *memIntents
	svc     *app.DeliveryIntentService
	worker  *delivery.Worker
	jira    *delivery.FakeJiraDeliverer
	mail    *delivery.FakeMailDeliverer
	logs    *observer.ObservedLogs
	now     time.Time
}

func newHarness(t *testing.T, cfg delivery.Config) *harness {
	t.Helper()
	core, logs := observer.New(zapcore.DebugLevel)
	logger := observability.New(zap.New(core))

	h := &harness{
		intents: newMemIntents(),
		jira:    delivery.NewFakeJiraDeliverer(logger),
		mail:    delivery.NewFakeMailDeliverer(logger),
		logs:    logs,
		now:     epoch,
	}
	h.svc = app.NewDeliveryIntentService(h.intents, &seqIDs{}, fixedClock{}, app.DeliveryIntentConfig{
		DeadLetterAudience: cfg.DeadLetterAudience,
	})
	h.worker = delivery.NewWorker(cfg, h.intents, h.svc, map[app.IntentType]delivery.IntentDeliverer{
		app.IntentJiraIssue: h.jira,
		app.IntentEmail:     h.mail,
	}, logger).WithClock(func() time.Time { return h.now })
	return h
}

// seed stores one pending intent of the given type and returns its id.
func (h *harness) seed(t *testing.T, typ app.IntentType) string {
	t.Helper()
	in, err := h.intents.CreateIntent(context.Background(), app.Intent{
		ID: "int-" + string(typ), Type: typ, Destination: "dest", State: app.IntentPending,
		NextAttemptAt: epoch, OriginEventID: "env-1", Snapshot: map[string]string{},
		Lineage:   app.IntentLineage{SourceContext: "governance", EventType: "governance.finding_opened", EventID: "env-1", CorrelationID: "corr-1"},
		ReleaseID: "rel-1",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return in.ID
}

func (h *harness) runOnce(t *testing.T) int {
	t.Helper()
	n, err := h.worker.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	return n
}

// advance moves the fake clock past the scheduled backoff so the next pass sees the intent.
func (h *harness) advance(d time.Duration) { h.now = h.now.Add(d) }

func testConfig() delivery.Config {
	return delivery.Config{
		Enabled: true, Workers: 1, Batch: 10, MaxAttempts: 3,
		BackoffInitial: time.Second, BackoffMax: 4 * time.Second,
		DeadLetterAudience: "operations", Interval: time.Millisecond,
	}
}

func TestWorkerDeliversOnTheFirstPass(t *testing.T) {
	h := newHarness(t, testConfig())
	id := h.seed(t, app.IntentJiraIssue)

	if n := h.runOnce(t); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	in := h.intents.get(t, id)
	if in.State != app.IntentDelivered {
		t.Errorf("state = %s, want delivered", in.State)
	}
	if in.Attempts != 1 || in.Result["transport"] != "fake" || in.Result["reference"] == "" {
		t.Errorf("intent = %+v", in)
	}
	ledger := h.intents.attemptsFor(id)
	if len(ledger) != 1 || ledger[0].Outcome != app.AttemptSuccess || ledger[0].StatusCode != 200 {
		t.Errorf("attempt ledger = %+v", ledger)
	}
	// A delivered intent is no longer work.
	if n := h.runOnce(t); n != 0 {
		t.Errorf("second pass delivered %d, want 0", n)
	}
}

// Two failures then a success: the attempts advance, the backoff grows (and honours the cap),
// and the final success marks the intent delivered.
func TestWorkerRetriesWithBackoffThenSucceeds(t *testing.T) {
	h := newHarness(t, testConfig())
	id := h.seed(t, app.IntentJiraIssue)
	h.jira.FailFirst(2, errors.New("jira refused"))

	if n := h.runOnce(t); n != 0 {
		t.Fatalf("first pass delivered %d, want 0", n)
	}
	in := h.intents.get(t, id)
	if in.Attempts != 1 || in.State != app.IntentPending {
		t.Fatalf("after one failure: %+v", in)
	}
	if got := in.NextAttemptAt.Sub(h.now); got != time.Second {
		t.Errorf("backoff after attempt 1 = %s, want 1s", got)
	}
	if in.LastError != "jira refused" {
		t.Errorf("last error = %q", in.LastError)
	}
	// Not yet due: the backoff is real, not decorative.
	if n := h.runOnce(t); n != 0 {
		t.Fatalf("pass before the backoff elapsed delivered %d", n)
	}
	if got := len(h.intents.attemptsFor(id)); got != 1 {
		t.Fatalf("attempts recorded = %d, want 1 (the intent was not yet due)", got)
	}

	h.advance(time.Second)
	if n := h.runOnce(t); n != 0 {
		t.Fatalf("second attempt delivered %d, want 0", n)
	}
	in = h.intents.get(t, id)
	if in.Attempts != 2 {
		t.Fatalf("attempts = %d, want 2", in.Attempts)
	}
	if got := in.NextAttemptAt.Sub(h.now); got != 2*time.Second {
		t.Errorf("backoff after attempt 2 = %s, want 2s (doubled)", got)
	}

	h.advance(2 * time.Second)
	if n := h.runOnce(t); n != 1 {
		t.Fatalf("third attempt delivered %d, want 1", n)
	}
	in = h.intents.get(t, id)
	if in.State != app.IntentDelivered || in.Attempts != 3 {
		t.Errorf("intent = %+v", in)
	}
	if in.LastError != "" {
		t.Errorf("a delivered intent keeps a last error: %q", in.LastError)
	}
	if got := h.jira.Calls(); got != 3 {
		t.Errorf("deliverer calls = %d, want 3", got)
	}
	ledger := h.intents.attemptsFor(id)
	if len(ledger) != 3 || ledger[0].Outcome != app.AttemptFailure || ledger[2].Outcome != app.AttemptSuccess {
		t.Errorf("attempt ledger = %+v", ledger)
	}
}

// The backoff cap holds: with max=4s the fourth attempt waits 4s, not 8s.
func TestWorkerBackoffHonoursTheCap(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 6
	h := newHarness(t, cfg)
	id := h.seed(t, app.IntentJiraIssue)
	h.jira.FailFirst(6, nil)

	wants := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	for i, want := range wants {
		h.runOnce(t)
		in := h.intents.get(t, id)
		if got := in.NextAttemptAt.Sub(h.now); got != want {
			t.Fatalf("backoff after attempt %d = %s, want %s", i+1, got, want)
		}
		h.advance(want)
	}
}

// Exhaustion: with maxAttempts=2 the second failure dead-letters the intent AND enqueues an
// operations mail intent — telling a person is itself an intent, never an inline send.
func TestWorkerDeadLettersAndNotifiesOperations(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 2
	h := newHarness(t, cfg)
	id := h.seed(t, app.IntentJiraIssue)
	h.jira.FailFirst(5, errors.New("jira down"))

	h.runOnce(t)
	h.advance(time.Second)
	h.runOnce(t)

	in := h.intents.get(t, id)
	if in.State != app.IntentDeadLetter {
		t.Fatalf("state = %s, want dead_letter", in.State)
	}
	if in.Attempts != 2 || in.LastError != "jira down" {
		t.Errorf("intent = %+v", in)
	}
	if got := h.jira.Calls(); got != 2 {
		t.Errorf("deliverer calls = %d, want 2 (no third try after exhaustion)", got)
	}

	notices, err := h.intents.ListDeadLetters(context.Background(), epoch, 10)
	if err != nil || len(notices) != 1 {
		t.Fatalf("dead letters = %v (%v)", notices, err)
	}
	if h.intents.countByType(app.IntentEmail) != 1 {
		t.Fatalf("want exactly one email intent enqueued for the dead letter")
	}
	mail := h.intents.get(t, "int-gen-1") // the notification the worker minted
	if mail.Type != app.IntentEmail || mail.Destination != "operations" {
		t.Errorf("notification intent = %+v", mail)
	}
	if mail.OriginEventID != "" {
		t.Errorf("a worker-sourced notification must carry no originating event: %q", mail.OriginEventID)
	}
	if !mail.IsDeadLetterNotification() || mail.Snapshot["dead_letter_intent_id"] != id {
		t.Errorf("notification snapshot = %v", mail.Snapshot)
	}
	if mail.Snapshot["dead_letter_error"] != "jira down" || mail.Snapshot["dead_letter_type"] != "jira_issue" {
		t.Errorf("notification snapshot = %v", mail.Snapshot)
	}
}

// The notification chain stops at one: a dead-lettered dead-letter mail does not enqueue
// another notification, or one unreachable relay fills the table.
func TestWorkerDoesNotNotifyAboutAFailedNotification(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 1
	h := newHarness(t, cfg)
	notice, err := h.svc.EnqueueDeadLetterMail(context.Background(),
		app.IntentLineage{SourceContext: "communication"}, "int-dead", "operations", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	h.mail.FailFirst(5, errors.New("relay down"))

	h.runOnce(t)

	if got := h.intents.get(t, notice.ID).State; got != app.IntentDeadLetter {
		t.Fatalf("state = %s, want dead_letter", got)
	}
	if n := h.intents.countByType(app.IntentEmail); n != 1 {
		t.Errorf("email intents = %d, want 1 (no notification about the notification)", n)
	}
	if !hasMessage(h.logs, "no further notification is enqueued") {
		t.Error("the broken notification channel must be logged loudly")
	}
}

// A pending intent whose attempts already reached the maximum (a crash between the failed
// attempt and the dead-letter write) is finished WITHOUT another send.
func TestWorkerFinishesAnAlreadyExhaustedIntentWithoutSending(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 2
	h := newHarness(t, cfg)
	id := h.seed(t, app.IntentJiraIssue)
	// Spend the budget without the dead-letter transition — the state a crash leaves behind.
	if err := h.intents.RecordAttempt(context.Background(), app.Attempt{
		IntentID: id, AttemptNo: 2, Outcome: app.AttemptFailure, Error: "earlier failure",
		At: epoch, NextAttemptAt: epoch,
	}); err != nil {
		t.Fatalf("record: %v", err)
	}

	h.runOnce(t)

	if got := h.intents.get(t, id).State; got != app.IntentDeadLetter {
		t.Errorf("state = %s, want dead_letter", got)
	}
	if got := h.jira.Calls(); got != 0 {
		t.Errorf("deliverer calls = %d, want 0 — the attempt budget was already spent", got)
	}
}

// An intent type with no deliverer wired is a configuration fault, recorded as a failed
// attempt rather than crashing the pass.
func TestWorkerRecordsAFailureWhenNoDelivererIsWired(t *testing.T) {
	cfg := testConfig()
	cfg.MaxAttempts = 1
	h := newHarness(t, cfg)
	h.worker = delivery.NewWorker(cfg, h.intents, h.svc, map[app.IntentType]delivery.IntentDeliverer{}, nil).
		WithClock(func() time.Time { return h.now })
	id := h.seed(t, app.IntentJiraIssue)

	h.runOnce(t)

	in := h.intents.get(t, id)
	if in.State != app.IntentDeadLetter || !strings.Contains(in.LastError, "no deliverer wired") {
		t.Errorf("intent = %+v", in)
	}
}

func TestWorkerRunOnceOnAnEmptyQueue(t *testing.T) {
	h := newHarness(t, testConfig())
	if n := h.runOnce(t); n != 0 {
		t.Errorf("delivered %d on an empty queue", n)
	}
}

// Store failures are the ONE class the worker reports as an error: if the record of what
// happened is unreliable, the pass is not a success.
func TestWorkerReportsStoreFailures(t *testing.T) {
	boom := errors.New("db down")
	cases := []struct {
		name  string
		apply func(*harness)
	}{
		{"fetch", func(h *harness) { h.intents.failPending = boom }},
		{"record attempt", func(h *harness) { h.intents.failAttempt = boom }},
		{"mark delivered", func(h *harness) { h.intents.failDelivered = boom }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, testConfig())
			h.seed(t, app.IntentJiraIssue)
			tc.apply(h)
			if _, err := h.worker.RunOnce(context.Background()); !errors.Is(err, boom) {
				t.Errorf("err = %v, want the store error", err)
			}
		})
	}
}

func TestWorkerReportsDeadLetterStoreFailures(t *testing.T) {
	boom := errors.New("db down")
	for _, tc := range []struct {
		name  string
		apply func(*harness)
	}{
		{"mark dead letter", func(h *harness) { h.intents.failDeadLtr = boom }},
		{"enqueue notification", func(h *harness) { h.intents.failCreate = boom }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.MaxAttempts = 1
			h := newHarness(t, cfg)
			h.seed(t, app.IntentJiraIssue)
			h.jira.FailFirst(1, errors.New("refused"))
			tc.apply(h)
			if _, err := h.worker.RunOnce(context.Background()); !errors.Is(err, boom) {
				t.Errorf("err = %v, want the store error", err)
			}
		})
	}
}

// The toggle: with delivery disabled Run returns at once and no pass happens.
func TestWorkerRunIsANoOpWhenDisabled(t *testing.T) {
	cfg := testConfig()
	cfg.Enabled = false
	h := newHarness(t, cfg)
	h.seed(t, app.IntentJiraIssue)

	done := make(chan struct{})
	go func() { h.worker.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return with delivery disabled")
	}
	if h.jira.Calls() != 0 {
		t.Error("a disabled worker sent something")
	}
	if got := h.intents.get(t, "int-jira_issue").State; got != app.IntentPending {
		t.Errorf("state = %s, want the intent untouched", got)
	}
	if !hasMessage(h.logs, "outward delivery disabled") {
		t.Error("a disabled worker must say so")
	}
}

// The loop delivers on its cadence and stops when the context is cancelled.
func TestWorkerRunLoopDeliversThenStops(t *testing.T) {
	h := newHarness(t, testConfig())
	id := h.seed(t, app.IntentJiraIssue)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.worker.Run(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for h.intents.get(t, id).State != app.IntentDelivered {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("the worker loop did not deliver the pending intent")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the worker loop did not stop on context cancellation")
	}
}

// The loop reports a store failure and keeps running (one bad pass is not a reason to stop
// draining the queue).
func TestWorkerRunLoopLogsAPassFailure(t *testing.T) {
	h := newHarness(t, testConfig())
	h.intents.failPending = errors.New("db down")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.worker.Run(ctx)

	deadline := time.Now().Add(5 * time.Second)
	for !hasMessage(h.logs, "delivery pass failed") {
		if time.Now().After(deadline) {
			t.Fatal("a failed pass was not logged")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// Telemetry carries the correlation ids an operator needs — and NOT the delivery body.
func TestWorkerLogsCorrelationButNeverThePayload(t *testing.T) {
	h := newHarness(t, testConfig())
	id := h.seed(t, app.IntentJiraIssue)
	// A payload would be N-M1b's; prove even a present one never reaches the log.
	in := h.intents.get(t, id)
	in.PayloadBytes = []byte("TOP-SECRET-BODY")
	h.intents.intents[id] = &in

	h.runOnce(t)

	entry, ok := findMessage(h.logs, "delivery intent delivered")
	if !ok {
		t.Fatal("no delivered log line")
	}
	fields := entry.ContextMap()
	if fields["intent_id"] != id || fields["origin_event_id"] != "env-1" || fields["correlation_id"] != "corr-1" {
		t.Errorf("log fields = %v", fields)
	}
	for _, e := range h.logs.All() {
		if strings.Contains(fmt.Sprint(e.ContextMap()), "TOP-SECRET-BODY") || strings.Contains(e.Message, "TOP-SECRET-BODY") {
			t.Fatal("a delivery payload reached the logs")
		}
	}
}

func TestFakeDeliverersAreProgrammableAndCount(t *testing.T) {
	jira := delivery.NewFakeJiraDeliverer(nil) // nil logger must not panic
	mail := delivery.NewFakeMailDeliverer(nil)
	in := app.Intent{ID: "int-1", Type: app.IntentJiraIssue, Destination: "dest"}

	jira.FailFirst(1, nil) // nil error = the generic transport failure
	if _, err := jira.DeliverIntent(context.Background(), in); err == nil {
		t.Error("want the programmed failure")
	}
	res, err := jira.DeliverIntent(context.Background(), in)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if res.StatusCode != 200 || res.Metadata["channel"] != "jira" || !strings.Contains(res.Excerpt, "accepted") {
		t.Errorf("result = %+v", res)
	}
	if jira.Calls() != 2 {
		t.Errorf("calls = %d, want 2", jira.Calls())
	}
	if res, err := mail.DeliverIntent(context.Background(), in); err != nil || res.Metadata["channel"] != "mail" {
		t.Errorf("mail result = %+v (%v)", res, err)
	}
}

func TestConfigFromEnvDefaultsAndOverrides(t *testing.T) {
	cfg := delivery.ConfigFromEnv()
	if cfg.Enabled {
		t.Error("outward delivery must be OFF by default")
	}
	if cfg.Workers != 2 || cfg.Batch != 50 || cfg.MaxAttempts != 3 ||
		cfg.BackoffInitial != time.Second || cfg.BackoffMax != 30*time.Second || cfg.Interval != 5*time.Second {
		t.Errorf("defaults = %s", cfg)
	}

	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_ENABLED", "1")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_WORKERS", "4")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_BATCH", "7")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_MAX_ATTEMPTS", "5")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_BACKOFF_INITIAL", "2s")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_BACKOFF_MAX", "1m")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_INTERVAL", "3s")
	t.Setenv("THEMIS_COMMUNICATION_DEADLETTER_AUDIENCE", "oncall")
	cfg = delivery.ConfigFromEnv()
	if !cfg.Enabled || cfg.Workers != 4 || cfg.Batch != 7 || cfg.MaxAttempts != 5 ||
		cfg.BackoffInitial != 2*time.Second || cfg.BackoffMax != time.Minute || cfg.Interval != 3*time.Second ||
		cfg.DeadLetterAudience != "oncall" {
		t.Errorf("configured = %s", cfg)
	}
	if !strings.Contains(cfg.String(), "deadletter_audience=\"oncall\"") {
		t.Errorf("String() = %s", cfg.String())
	}

	// A misconfigured knob falls back to its default rather than disabling the mechanism.
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_WORKERS", "zero")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_BATCH", "-1")
	t.Setenv("THEMIS_COMMUNICATION_DELIVERY_BACKOFF_MAX", "nonsense")
	cfg = delivery.ConfigFromEnv()
	if cfg.Workers != 2 || cfg.Batch != 50 || cfg.BackoffMax != 30*time.Second {
		t.Errorf("fallbacks = %s", cfg)
	}
}

// A zero Config still produces a working worker: every knob falls back to its default, and a
// backoff maximum below the initial delay is raised rather than inverting the schedule.
func TestWorkerAppliesConfigDefaults(t *testing.T) {
	h := newHarness(t, delivery.Config{Enabled: true})
	id := h.seed(t, app.IntentEmail)
	if n := h.runOnce(t); n != 1 {
		t.Fatalf("delivered %d, want 1", n)
	}
	if got := h.intents.get(t, id).State; got != app.IntentDelivered {
		t.Errorf("state = %s", got)
	}

	h2 := newHarness(t, delivery.Config{Enabled: true, BackoffInitial: time.Minute, BackoffMax: time.Second})
	id2 := h2.seed(t, app.IntentEmail)
	h2.mail.FailFirst(1, errors.New("refused"))
	h2.runOnce(t)
	if got := h2.intents.get(t, id2).NextAttemptAt.Sub(epoch); got != time.Minute {
		t.Errorf("backoff = %s, want the initial delay (the cap was below it)", got)
	}
}

// Several intents in one pass, spread over more than one goroutine.
func TestWorkerDeliversABatchConcurrently(t *testing.T) {
	cfg := testConfig()
	cfg.Workers = 3
	h := newHarness(t, cfg)
	for i := 0; i < 6; i++ {
		if _, err := h.intents.CreateIntent(context.Background(), app.Intent{
			ID: fmt.Sprintf("int-%d", i), Type: app.IntentEmail, Destination: "ops",
			State: app.IntentPending, NextAttemptAt: epoch, Snapshot: map[string]string{},
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	if n := h.runOnce(t); n != 6 {
		t.Fatalf("delivered %d, want 6", n)
	}
	if got := h.mail.Calls(); got != 6 {
		t.Errorf("deliverer calls = %d, want 6", got)
	}
}

func hasMessage(logs *observer.ObservedLogs, substr string) bool {
	_, ok := findMessage(logs, substr)
	return ok
}

func findMessage(logs *observer.ObservedLogs, substr string) (observer.LoggedEntry, bool) {
	for _, e := range logs.All() {
		if strings.Contains(e.Message, substr) {
			return e, true
		}
	}
	return observer.LoggedEntry{}, false
}
