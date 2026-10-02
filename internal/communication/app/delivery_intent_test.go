package app_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

// intentStore is an in-memory DeliveryIntents double. CreateIntent reproduces the store's one
// behaviour the service depends on — idempotence on the originating event id — so the
// service's guarantees are tested against the contract, not against SQL.
type intentStore struct {
	created []app.Intent
	byEvent map[string]app.Intent
	err     error
}

func newIntentStore() *intentStore {
	return &intentStore{byEvent: map[string]app.Intent{}}
}

func (s *intentStore) CreateIntent(_ context.Context, in app.Intent) (app.Intent, error) {
	if s.err != nil {
		return app.Intent{}, s.err
	}
	if in.OriginEventID != "" {
		if existing, ok := s.byEvent[in.OriginEventID]; ok {
			return existing, nil
		}
		s.byEvent[in.OriginEventID] = in
	}
	s.created = append(s.created, in)
	return in, nil
}

func (s *intentStore) GetIntent(context.Context, string) (app.Intent, error) {
	return app.Intent{}, app.ErrIntentNotFound
}
func (s *intentStore) GetPendingForWork(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (s *intentStore) RecordAttempt(context.Context, app.Attempt) error               { return nil }
func (s *intentStore) MarkDelivered(context.Context, string, map[string]string) error { return nil }
func (s *intentStore) MarkDeadLetter(context.Context, string, string) error           { return nil }
func (s *intentStore) CancelIntent(context.Context, string) error                     { return nil }
func (s *intentStore) ListDeadLetters(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (s *intentStore) RetryIntent(context.Context, string) error { return nil }

type intentIDs struct{ n int }

func (g *intentIDs) NewID() string { g.n++; return fmt.Sprintf("int-%d", g.n) }

var intentEpoch = time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC)

type intentClock struct{}

func (intentClock) Now() time.Time { return intentEpoch }

func intentSvc(store *intentStore, cfg app.DeliveryIntentConfig) *app.DeliveryIntentService {
	return app.NewDeliveryIntentService(store, &intentIDs{}, intentClock{}, cfg)
}

func lineage() app.IntentLineage {
	return app.IntentLineage{
		SourceContext: "governance",
		EventType:     "governance.finding_opened",
		EventID:       "env-1",
		EventTime:     intentEpoch.Add(-time.Minute),
		CorrelationID: "corr-1",
	}
}

func TestEnqueueJiraForRelease(t *testing.T) {
	store := newIntentStore()
	in, err := intentSvc(store, app.DeliveryIntentConfig{}).EnqueueJiraForRelease(
		context.Background(), lineage(), "env-1", "rel-1", "prod-1", "proj-1",
		map[string]string{"finding_id": "fnd-1", "cve": "CVE-2026-1"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.Type != app.IntentJiraIssue || in.State != app.IntentPending {
		t.Errorf("type/state = %s/%s", in.Type, in.State)
	}
	if in.Destination != "themis-remediation" {
		t.Errorf("destination = %q, want the default jira alias", in.Destination)
	}
	if in.ReleaseID != "rel-1" || in.ProductID != "prod-1" || in.ProjectID != "proj-1" {
		t.Errorf("pointers = %+v", in)
	}
	if in.OriginEventID != "env-1" {
		t.Errorf("origin event = %q", in.OriginEventID)
	}
	if in.Attempts != 0 || !in.NextAttemptAt.Equal(intentEpoch) || in.LastError != "" {
		t.Errorf("work columns = %+v", in)
	}
	// The payload is N-M1b's: an intent carries facts, not a rendered body.
	if len(in.PayloadBytes) != 0 || in.PayloadSHA256 != "" {
		t.Errorf("payload must stay empty in N-M1a: %q / %q", in.PayloadSHA256, in.PayloadBytes)
	}
	want := map[string]string{
		"finding_id": "fnd-1", "cve": "CVE-2026-1",
		"release_id": "rel-1", "product_id": "prod-1", "project_id": "proj-1",
		"event_type": "governance.finding_opened", "event_id": "env-1",
		"event_time": intentEpoch.Add(-time.Minute).Format(time.RFC3339Nano),
	}
	for k, v := range want {
		if in.Snapshot[k] != v {
			t.Errorf("snapshot[%q] = %q, want %q", k, in.Snapshot[k], v)
		}
	}
	if in.Lineage != lineage() {
		t.Errorf("lineage = %+v", in.Lineage)
	}
}

func TestEnqueueJiraRefusesWithoutRelease(t *testing.T) {
	store := newIntentStore()
	if _, err := intentSvc(store, app.DeliveryIntentConfig{}).EnqueueJiraForRelease(
		context.Background(), lineage(), "env-1", "  ", "", "", nil); !errors.Is(err, app.ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
	if len(store.created) != 0 {
		t.Error("nothing may be enqueued for an indeterminate subject")
	}
}

func TestEnqueueJiraIsIdempotentOnTheEventID(t *testing.T) {
	store := newIntentStore()
	svc := intentSvc(store, app.DeliveryIntentConfig{})
	first, err := svc.EnqueueJiraForRelease(context.Background(), lineage(), "env-1", "rel-1", "", "", nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.EnqueueJiraForRelease(context.Background(), lineage(), "env-1", "rel-1", "", "", nil)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID != second.ID {
		t.Errorf("redelivery created a second intent: %s vs %s", first.ID, second.ID)
	}
	if len(store.created) != 1 {
		t.Errorf("created %d intents, want 1", len(store.created))
	}
}

func TestEnqueueDecisionMail(t *testing.T) {
	store := newIntentStore()
	in, err := intentSvc(store, app.DeliveryIntentConfig{}).EnqueueDecisionMail(
		context.Background(), lineage(), "env-2", "prop-1", "fnd-1", "rel-1", "",
		map[string]string{"position_version": "2"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.Type != app.IntentEmail || in.Destination != "security-decisions" {
		t.Errorf("type/destination = %s/%s", in.Type, in.Destination)
	}
	if in.ProposalID != "prop-1" || in.FindingID != "fnd-1" || in.ReleaseID != "rel-1" {
		t.Errorf("pointers = %+v", in)
	}
	if in.Snapshot["proposal_id"] != "prop-1" || in.Snapshot["position_version"] != "2" {
		t.Errorf("snapshot = %v", in.Snapshot)
	}
	if in.IsDeadLetterNotification() {
		t.Error("a decision mail is not a dead-letter notification")
	}
}

func TestEnqueueDecisionMailHonoursAnExplicitAudience(t *testing.T) {
	store := newIntentStore()
	in, err := intentSvc(store, app.DeliveryIntentConfig{DecisionAudience: "configured"}).EnqueueDecisionMail(
		context.Background(), lineage(), "env-2", "prop-1", "", "", "per-call", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.Destination != "per-call" {
		t.Errorf("destination = %q, want the per-call audience", in.Destination)
	}
}

func TestEnqueueDecisionMailRefusesWithoutASubject(t *testing.T) {
	store := newIntentStore()
	if _, err := intentSvc(store, app.DeliveryIntentConfig{}).EnqueueDecisionMail(
		context.Background(), lineage(), "env-2", "", "", "rel-1", "", nil); !errors.Is(err, app.ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
	if len(store.created) != 0 {
		t.Error("a decision mail with neither proposal nor finding must not be enqueued")
	}
}

func TestEnqueueDeadLetterMail(t *testing.T) {
	store := newIntentStore()
	svc := intentSvc(store, app.DeliveryIntentConfig{})
	if got := svc.DeadLetterAudience(); got != "operations" {
		t.Errorf("dead-letter audience = %q, want the default", got)
	}
	in, err := svc.EnqueueDeadLetterMail(context.Background(), lineage(), "int-dead", "",
		map[string]string{"dead_letter_error": "boom"})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.Destination != "operations" {
		t.Errorf("destination = %q", in.Destination)
	}
	// Worker-sourced: no originating event, so it takes part in no deduplication.
	if in.OriginEventID != "" {
		t.Errorf("origin event = %q, want empty for a worker-sourced intent", in.OriginEventID)
	}
	if !in.IsDeadLetterNotification() {
		t.Error("the dead-letter mail must be marked as a notification (it stops the chain)")
	}
	if in.Snapshot["dead_letter_intent_id"] != "int-dead" || in.Snapshot["dead_letter_error"] != "boom" {
		t.Errorf("snapshot = %v", in.Snapshot)
	}
}

func TestEnqueueDeadLetterMailRefusesWithoutAnIntent(t *testing.T) {
	if _, err := intentSvc(newIntentStore(), app.DeliveryIntentConfig{}).EnqueueDeadLetterMail(
		context.Background(), lineage(), "", "ops", nil); !errors.Is(err, app.ErrNoSubject) {
		t.Fatalf("err = %v, want ErrNoSubject", err)
	}
}

func TestEnqueueDeadLetterMailUsesTheConfiguredAudience(t *testing.T) {
	svc := intentSvc(newIntentStore(), app.DeliveryIntentConfig{DeadLetterAudience: "oncall"})
	if got := svc.DeadLetterAudience(); got != "oncall" {
		t.Errorf("audience = %q", got)
	}
	in, err := svc.EnqueueDeadLetterMail(context.Background(), lineage(), "int-dead", "", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if in.Destination != "oncall" {
		t.Errorf("destination = %q", in.Destination)
	}
}

// A store failure is returned, not swallowed: if the intent cannot be recorded, the caller
// (the inbound reader, inside the inbox transaction) must roll back rather than lose the
// outward obligation.
func TestEnqueuePropagatesStoreFailure(t *testing.T) {
	store := newIntentStore()
	store.err = errors.New("db down")
	svc := intentSvc(store, app.DeliveryIntentConfig{})
	if _, err := svc.EnqueueJiraForRelease(context.Background(), lineage(), "env-1", "rel-1", "", "", nil); err == nil {
		t.Error("jira: want the store error")
	}
	if _, err := svc.EnqueueDecisionMail(context.Background(), lineage(), "env-2", "prop-1", "", "", "", nil); err == nil {
		t.Error("mail: want the store error")
	}
	if _, err := svc.EnqueueDeadLetterMail(context.Background(), lineage(), "int-1", "", nil); err == nil {
		t.Error("dead-letter: want the store error")
	}
}

// A lineage with no event facts (the worker path, or a transport that carried none) must not
// invent snapshot keys — an empty value is absence, not a fact.
func TestSnapshotOmitsAbsentLineageFacts(t *testing.T) {
	store := newIntentStore()
	in, err := intentSvc(store, app.DeliveryIntentConfig{}).EnqueueDeadLetterMail(
		context.Background(), app.IntentLineage{}, "int-dead", "ops", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	for _, k := range []string{"event_type", "event_id", "event_time"} {
		if _, ok := in.Snapshot[k]; ok {
			t.Errorf("snapshot carries %q for an empty lineage", k)
		}
	}
}
