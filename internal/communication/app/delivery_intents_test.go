package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

var intentNow = time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)

// memIntents is an in-memory DeliveryIntentRepository with the one behaviour that matters
// for these tests: SaveIntent enforces the same (origin event, type, kind, destination)
// uniqueness the UNIQUE index does, so the dedup rule is exercised without a database.
type memIntents struct {
	byID     map[string]domain.DeliveryIntent
	order    []string
	dedup    map[string]bool
	attempts map[string][]domain.DeliveryAttempt
	failOn   string // method name that should return an error
}

func newMemIntents() *memIntents {
	return &memIntents{
		byID:     map[string]domain.DeliveryIntent{},
		dedup:    map[string]bool{},
		attempts: map[string][]domain.DeliveryAttempt{},
	}
}

func (m *memIntents) fail(method string) error {
	if m.failOn == method {
		return errors.New("store unavailable")
	}
	return nil
}

func (m *memIntents) SaveIntent(_ context.Context, in domain.DeliveryIntent) (bool, error) {
	if err := m.fail("SaveIntent"); err != nil {
		return false, err
	}
	o := in.Origin()
	key := fmt.Sprintf("%s|%s|%s|%s", o.EventID, o.EventType, in.Kind(), in.Destination())
	if m.dedup[key] {
		return false, nil
	}
	m.dedup[key] = true
	m.byID[in.ID()] = in
	m.order = append(m.order, in.ID())
	return true, nil
}

func (m *memIntents) DueIntents(_ context.Context, kind domain.DeliveryKind, now time.Time, limit int) ([]domain.DeliveryIntent, error) {
	if err := m.fail("DueIntents"); err != nil {
		return nil, err
	}
	var out []domain.DeliveryIntent
	for _, id := range m.order {
		in := m.byID[id]
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

func (m *memIntents) RecordAttempt(_ context.Context, in domain.DeliveryIntent, att domain.DeliveryAttempt) error {
	if err := m.fail("RecordAttempt"); err != nil {
		return err
	}
	m.byID[in.ID()] = in
	m.attempts[in.ID()] = append(m.attempts[in.ID()], att)
	return nil
}

func (m *memIntents) SaveIntentState(_ context.Context, in domain.DeliveryIntent) error {
	if err := m.fail("SaveIntentState"); err != nil {
		return err
	}
	m.byID[in.ID()] = in
	return nil
}

func (m *memIntents) GetIntent(_ context.Context, id string) (domain.DeliveryIntent, error) {
	if err := m.fail("GetIntent"); err != nil {
		return domain.DeliveryIntent{}, err
	}
	in, ok := m.byID[id]
	if !ok {
		return domain.DeliveryIntent{}, app.ErrIntentNotFound
	}
	return in, nil
}

func (m *memIntents) IntentAttempts(_ context.Context, id string) ([]domain.DeliveryAttempt, error) {
	if err := m.fail("IntentAttempts"); err != nil {
		return nil, err
	}
	return m.attempts[id], nil
}

func (m *memIntents) ListIntents(_ context.Context, f app.IntentFilter) ([]domain.DeliveryIntent, error) {
	if err := m.fail("ListIntents"); err != nil {
		return nil, err
	}
	var out []domain.DeliveryIntent
	for _, id := range m.order {
		in := m.byID[id]
		if f.Status != "" && in.Status() != f.Status {
			continue
		}
		if f.Kind != "" && in.Kind() != f.Kind {
			continue
		}
		out = append(out, in)
	}
	if f.Offset >= len(out) {
		return nil, nil
	}
	out = out[f.Offset:]
	if len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *memIntents) CountIntentsByStatus(_ context.Context) (map[domain.IntentStatus]int, error) {
	if err := m.fail("CountIntentsByStatus"); err != nil {
		return nil, err
	}
	out := map[domain.IntentStatus]int{}
	for _, in := range m.byID {
		out[in.Status()]++
	}
	return out, nil
}

type intentIDs struct{ n int }

func (g *intentIDs) NewID() string { g.n++; return fmt.Sprintf("int-%d", g.n) }

// stepClock is the deterministic scheduler seam: the worker and the service ask it what time
// it is, so a backoff can be asserted by stepping rather than by sleeping.
type stepClock struct{ t time.Time }

func (c *stepClock) Now() time.Time       { return c.t }
func (c *stepClock) step(d time.Duration) { c.t = c.t.Add(d) }

func newIntentSvc(repo app.DeliveryIntentRepository, clock app.Clock, maxAttempts int) *app.DeliveryIntentService {
	return app.NewDeliveryIntentService(repo, &intentIDs{}, clock, app.DeliveryIntentConfig{
		MaxAttempts: maxAttempts,
		Backoff:     domain.BackoffPolicy{Base: time.Minute, Cap: 10 * time.Minute},
	})
}

func findingOpenedOrigin(eventID string) domain.DeliveryOrigin {
	return domain.DeliveryOrigin{
		EventID: eventID, EventType: "governance.finding_opened", EventTime: intentNow,
		FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1",
	}
}

func TestRecordFindingOpened_RecordsOnePendingJiraIntent(t *testing.T) {
	repo := newMemIntents()
	svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)

	n, err := svc.RecordFindingOpened(context.Background(), findingOpenedOrigin("env-1"))
	if err != nil || n != 1 {
		t.Fatalf("record = %d, %v", n, err)
	}
	in := repo.byID["int-1"]
	if in.Kind() != domain.DeliveryJiraIssue || in.Status() != domain.IntentPending ||
		in.Destination() != app.DefaultIntentDestination || in.PayloadHash() == "" {
		t.Errorf("intent = %s/%s/%s hash=%q", in.Kind(), in.Status(), in.Destination(), in.PayloadHash())
	}
	if in.MaxAttempts() != 5 {
		t.Errorf("max attempts = %d, want the configured 5", in.MaxAttempts())
	}
}

// A replayed or redelivered envelope must not produce a second outward action — and the
// duplicate must not be an ERROR either, or the bus reader would retry a fact it has already
// fully applied.
func TestRecordFindingOpened_DedupsOnTheOriginEvent(t *testing.T) {
	repo := newMemIntents()
	svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)
	ctx := context.Background()

	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	n, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1"))
	if err != nil {
		t.Fatalf("replay errored: %v", err)
	}
	if n != 0 || len(repo.byID) != 1 {
		t.Errorf("replay created %d intents (total %d), want 0 (total 1)", n, len(repo.byID))
	}

	// A DIFFERENT envelope about the same Finding is a different fact and does record.
	if n, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-2")); err != nil || n != 1 {
		t.Errorf("distinct event = %d, %v", n, err)
	}
}

func TestRecordProposalAccepted_CIBuildOnlyWithHarnessEvidence(t *testing.T) {
	origin := domain.DeliveryOrigin{
		EventID: "env-9", EventType: "governance.proposal_accepted", EventTime: intentNow,
		FindingID: "fnd-2", ProposalID: "prop-2", PositionVersion: 4,
	}

	plain := newMemIntents()
	if n, err := newIntentSvc(plain, &stepClock{t: intentNow}, 5).
		RecordProposalAccepted(context.Background(), origin, false); err != nil || n != 1 {
		t.Fatalf("without harness evidence = %d, %v", n, err)
	}
	if got := kindsOf(plain); len(got) != 1 || got[0] != domain.DeliveryEmail {
		t.Errorf("without harness evidence kinds = %v, want [email]", got)
	}

	harness := newMemIntents()
	if n, err := newIntentSvc(harness, &stepClock{t: intentNow}, 5).
		RecordProposalAccepted(context.Background(), origin, true); err != nil || n != 2 {
		t.Fatalf("with harness evidence = %d, %v", n, err)
	}
	got := kindsOf(harness)
	if len(got) != 2 || got[0] != domain.DeliveryCIBuild || got[1] != domain.DeliveryEmail {
		t.Errorf("with harness evidence kinds = %v, want [ci_build email]", got)
	}
}

func kindsOf(repo *memIntents) []domain.DeliveryKind {
	out := make([]domain.DeliveryKind, 0, len(repo.order))
	for _, id := range repo.order {
		out = append(out, repo.byID[id].Kind())
	}
	return out
}

func TestRecordOutcome_SuccessAndBackoffThenDeadLetter(t *testing.T) {
	repo := newMemIntents()
	clock := &stepClock{t: intentNow}
	svc := newIntentSvc(repo, clock, 2)
	ctx := context.Background()

	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("record: %v", err)
	}

	due, err := svc.DueIntents(ctx, domain.DeliveryJiraIssue, 0)
	if err != nil || len(due) != 1 {
		t.Fatalf("due = %d, %v", len(due), err)
	}

	// First failure: still PENDING, but no longer due — the backoff pushed it forward, which
	// is what a second Drain at the same instant must observe.
	if _, err := svc.RecordOutcome(ctx, due[0], errors.New("jira 503")); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	if got := repo.byID["int-1"]; got.Status() != domain.IntentPending || got.Attempts() != 1 {
		t.Fatalf("after failure = %s attempts=%d", got.Status(), got.Attempts())
	}
	if again, _ := svc.DueIntents(ctx, domain.DeliveryJiraIssue, 0); len(again) != 0 {
		t.Errorf("intent is due again with no time passed: %d", len(again))
	}

	clock.step(2 * time.Minute)
	due, _ = svc.DueIntents(ctx, domain.DeliveryJiraIssue, 0)
	if len(due) != 1 {
		t.Fatalf("not due after the backoff elapsed: %d", len(due))
	}
	if _, err := svc.RecordOutcome(ctx, due[0], errors.New("jira 503")); err != nil {
		t.Fatalf("record second failure: %v", err)
	}
	final := repo.byID["int-1"]
	if final.Status() != domain.IntentDeadLetter || final.LastError() != "jira 503" {
		t.Errorf("final = %s err=%q", final.Status(), final.LastError())
	}
	if len(repo.attempts["int-1"]) != 2 {
		t.Errorf("history = %d rows, want 2", len(repo.attempts["int-1"]))
	}

	// A success on a fresh intent delivers it with exactly one history row.
	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-2")); err != nil {
		t.Fatalf("record second: %v", err)
	}
	ok, _ := svc.DueIntents(ctx, domain.DeliveryJiraIssue, 0)
	if len(ok) != 1 {
		t.Fatalf("second intent not due: %d", len(ok))
	}
	if _, err := svc.RecordOutcome(ctx, ok[0], nil); err != nil {
		t.Fatalf("record success: %v", err)
	}
	if got := repo.byID["int-2"]; got.Status() != domain.IntentDelivered {
		t.Errorf("second intent = %s, want DELIVERED", got.Status())
	}
	if len(repo.attempts["int-2"]) != 1 {
		t.Errorf("second history = %d rows, want 1", len(repo.attempts["int-2"]))
	}
}

// An outcome arriving for an already-delivered intent is not a second attempt, and must not
// append a history row that claims it was.
func TestRecordOutcome_IgnoredOnceDelivered(t *testing.T) {
	repo := newMemIntents()
	svc := newIntentSvc(repo, &stepClock{t: intentNow}, 3)
	ctx := context.Background()
	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("record: %v", err)
	}
	due, _ := svc.DueIntents(ctx, domain.DeliveryJiraIssue, 0)
	if _, err := svc.RecordOutcome(ctx, due[0], nil); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	delivered := repo.byID["int-1"]
	if _, err := svc.RecordOutcome(ctx, delivered, errors.New("late failure")); err != nil {
		t.Fatalf("duplicate outcome: %v", err)
	}
	if len(repo.attempts["int-1"]) != 1 {
		t.Errorf("history = %d rows, want 1", len(repo.attempts["int-1"]))
	}
}

func TestRetryAndCancelIntent(t *testing.T) {
	repo := newMemIntents()
	clock := &stepClock{t: intentNow}
	svc := newIntentSvc(repo, clock, 1)
	ctx := context.Background()

	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("record: %v", err)
	}
	due, _ := svc.DueIntents(ctx, domain.DeliveryJiraIssue, 0)
	if _, err := svc.RecordOutcome(ctx, due[0], errors.New("jira gone")); err != nil {
		t.Fatalf("fail it: %v", err)
	}
	if repo.byID["int-1"].Status() != domain.IntentDeadLetter {
		t.Fatalf("setup: %s", repo.byID["int-1"].Status())
	}

	clock.step(time.Hour)
	back, err := svc.RetryIntent(ctx, "int-1")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if back.Status() != domain.IntentPending || back.Attempts() != 0 {
		t.Errorf("retried = %s attempts=%d", back.Status(), back.Attempts())
	}
	// The history survives the retry — it is the record of what was tried, not of what is
	// currently queued.
	if len(repo.attempts["int-1"]) != 1 {
		t.Errorf("history lost on retry: %d rows", len(repo.attempts["int-1"]))
	}

	cancelled, err := svc.CancelIntent(ctx, "int-1")
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if cancelled.Status() != domain.IntentCancelled {
		t.Errorf("cancelled = %s", cancelled.Status())
	}

	// Refusals surface the domain sentinels so the HTTP edge can map them to a 409.
	if _, err := svc.CancelIntent(ctx, "nope"); !errors.Is(err, app.ErrIntentNotFound) {
		t.Errorf("cancel unknown = %v", err)
	}
	if _, err := svc.RetryIntent(ctx, "nope"); !errors.Is(err, app.ErrIntentNotFound) {
		t.Errorf("retry unknown = %v", err)
	}
	if _, err := svc.RetryIntent(ctx, "int-1"); err != nil {
		t.Fatalf("retry cancelled: %v", err)
	}
	if _, err := svc.RetryIntent(ctx, "int-1"); !errors.Is(err, domain.ErrIntentNotRetryable) {
		t.Errorf("retry pending = %v, want ErrIntentNotRetryable", err)
	}
	if _, err := svc.CancelIntent(ctx, "int-1"); err != nil {
		t.Fatalf("cancel pending: %v", err)
	}
}

func TestGetListAndCountIntents(t *testing.T) {
	repo := newMemIntents()
	svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)
	ctx := context.Background()

	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("record: %v", err)
	}
	if _, err := svc.RecordProposalAccepted(ctx, domain.DeliveryOrigin{
		EventID: "env-2", EventType: "governance.proposal_accepted", EventTime: intentNow, FindingID: "fnd-2",
	}, false); err != nil {
		t.Fatalf("record accepted: %v", err)
	}

	in, attempts, err := svc.GetIntent(ctx, "int-1")
	if err != nil || in.ID() != "int-1" || len(attempts) != 0 {
		t.Fatalf("get = %s %d %v", in.ID(), len(attempts), err)
	}
	if _, _, err := svc.GetIntent(ctx, "missing"); !errors.Is(err, app.ErrIntentNotFound) {
		t.Errorf("get missing = %v", err)
	}

	all, err := svc.ListIntents(ctx, app.IntentFilter{})
	if err != nil || len(all) != 2 {
		t.Fatalf("list all = %d, %v", len(all), err)
	}
	mail, err := svc.ListIntents(ctx, app.IntentFilter{Kind: domain.DeliveryEmail})
	if err != nil || len(mail) != 1 || mail[0].Kind() != domain.DeliveryEmail {
		t.Errorf("list by kind = %v, %v", mail, err)
	}
	pending, err := svc.ListIntents(ctx, app.IntentFilter{Status: domain.IntentPending})
	if err != nil || len(pending) != 2 {
		t.Errorf("list by status = %d, %v", len(pending), err)
	}

	// The page size is clamped at both ends so one operator query cannot pull the table.
	if _, err := svc.ListIntents(ctx, app.IntentFilter{Limit: 100000, Offset: -5}); err != nil {
		t.Errorf("clamped list: %v", err)
	}
	if one, err := svc.ListIntents(ctx, app.IntentFilter{Limit: 1}); err != nil || len(one) != 1 {
		t.Errorf("limit 1 = %d, %v", len(one), err)
	}

	counts, err := svc.IntentCounts(ctx)
	if err != nil || counts[domain.IntentPending] != 2 {
		t.Errorf("counts = %v, %v", counts, err)
	}
}

// A partially configured node must still behave predictably rather than recording intents
// nobody may try, or addressed nowhere.
func TestNewDeliveryIntentService_Defaults(t *testing.T) {
	repo := newMemIntents()
	svc := app.NewDeliveryIntentService(repo, &intentIDs{}, &stepClock{t: intentNow}, app.DeliveryIntentConfig{})
	if _, err := svc.RecordFindingOpened(context.Background(), findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("record: %v", err)
	}
	in := repo.byID["int-1"]
	if in.MaxAttempts() != 5 || in.Destination() != app.DefaultIntentDestination {
		t.Errorf("defaults = max %d dest %q", in.MaxAttempts(), in.Destination())
	}
}

// Every store failure has to reach the caller: the bus reader's transaction rolls back on a
// recording error, and the worker stops its pass rather than sending without a record.
func TestDeliveryIntentService_StoreErrorsSurface(t *testing.T) {
	ctx := context.Background()
	for _, method := range []string{"SaveIntent", "DueIntents", "GetIntent", "IntentAttempts",
		"ListIntents", "CountIntentsByStatus"} {
		repo := newMemIntents()
		repo.failOn = method
		svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)
		var err error
		switch method {
		case "SaveIntent":
			_, err = svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1"))
		case "DueIntents":
			_, err = svc.DueIntents(ctx, domain.DeliveryEmail, 5)
		case "GetIntent":
			_, _, err = svc.GetIntent(ctx, "int-1")
		case "IntentAttempts":
			_, _, err = svc.GetIntent(ctx, "int-1")
		case "ListIntents":
			_, err = svc.ListIntents(ctx, app.IntentFilter{})
		case "CountIntentsByStatus":
			_, err = svc.IntentCounts(ctx)
		}
		if err == nil {
			t.Errorf("%s: store failure was swallowed", method)
		}
	}

	// The two write paths need a real intent in place before the failing call.
	for _, method := range []string{"RecordAttempt", "SaveIntentState"} {
		repo := newMemIntents()
		svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)
		if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
			t.Fatalf("%s setup: %v", method, err)
		}
		repo.failOn = method
		var err error
		if method == "RecordAttempt" {
			_, err = svc.RecordOutcome(ctx, repo.byID["int-1"], nil)
		} else {
			_, err = svc.CancelIntent(ctx, "int-1")
		}
		if err == nil {
			t.Errorf("%s: store failure was swallowed", method)
		}
	}
}

// An origin with no causing event has no dedup identity, so recording it would let a replay
// create a second outward action. It is refused before anything is written.
func TestRecordFindingOpened_RefusesAnOriginWithNoEvent(t *testing.T) {
	repo := newMemIntents()
	svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)
	n, err := svc.RecordFindingOpened(context.Background(), domain.DeliveryOrigin{FindingID: "fnd-1"})
	if err == nil {
		t.Error("an origin with no event id was recorded")
	}
	if n != 0 || len(repo.byID) != 0 {
		t.Errorf("created %d intents on refusal", n)
	}
}

// A refused transition must surface as itself, and a store failure DURING a transition must
// not be reported as success — the operator would believe an intent was re-queued when it
// was not.
func TestRetryAndCancel_TransitionAndStoreRefusals(t *testing.T) {
	ctx := context.Background()

	cancelled := newMemIntents()
	csvc := newIntentSvc(cancelled, &stepClock{t: intentNow}, 5)
	if _, err := csvc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	delivered := cancelled.byID["int-1"]
	if _, err := csvc.RecordOutcome(ctx, delivered, nil); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if _, err := csvc.CancelIntent(ctx, "int-1"); !errors.Is(err, domain.ErrIntentNotCancellable) {
		t.Errorf("cancel delivered = %v, want ErrIntentNotCancellable", err)
	}

	stored := newMemIntents()
	ssvc := newIntentSvc(stored, &stepClock{t: intentNow}, 1)
	if _, err := ssvc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := ssvc.RecordOutcome(ctx, stored.byID["int-1"], errors.New("boom")); err != nil {
		t.Fatalf("dead-letter it: %v", err)
	}
	stored.failOn = "SaveIntentState"
	if _, err := ssvc.RetryIntent(ctx, "int-1"); err == nil {
		t.Error("retry reported success while the store refused to persist it")
	}
}

// IntentAttempts failing must not be reported as "found nothing": GetIntent has two reads
// and only one of them was the lookup.
func TestGetIntent_AttemptsReadFailureSurfaces(t *testing.T) {
	repo := newMemIntents()
	svc := newIntentSvc(repo, &stepClock{t: intentNow}, 5)
	ctx := context.Background()
	if _, err := svc.RecordFindingOpened(ctx, findingOpenedOrigin("env-1")); err != nil {
		t.Fatalf("setup: %v", err)
	}
	repo.failOn = "IntentAttempts"
	if _, _, err := svc.GetIntent(ctx, "int-1"); err == nil || errors.Is(err, app.ErrIntentNotFound) {
		t.Errorf("attempts read failure = %v", err)
	}
}
