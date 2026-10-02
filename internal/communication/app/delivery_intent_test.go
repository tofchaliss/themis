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

// stubRenderer is an IntentPayloadRenderer double. It renders a recognizable envelope per intent
// type (and can fail), which is all the service needs to be held to: materialize at enqueue,
// store the digest, and fail CLOSED when the render fails.
type stubRenderer struct {
	err   error
	empty bool
	calls int
}

func (r *stubRenderer) RenderIntentPayload(_ context.Context, in app.Intent) ([]byte, error) {
	r.calls++
	if r.err != nil {
		return nil, r.err
	}
	if r.empty {
		return nil, nil
	}
	return app.BuildPayload("subject for "+string(in.Type), []byte("body for "+in.ID)), nil
}

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
	// Without a renderer the service records facts only — the N-M1a behaviour, which a real
	// sender refuses rather than improvising a body for.
	if len(in.PayloadBytes) != 0 || in.PayloadSHA256 != "" {
		t.Errorf("no renderer wired, so no payload: %q / %q", in.PayloadSHA256, in.PayloadBytes)
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

// --- N-M1b: payload materialization at enqueue (D-N-3) --------------------------------------

// Every enqueue path materializes: the bytes that will be sent are stored with their content
// address, so a retry re-sends a snapshot instead of re-deriving one from an estate that moved.
func TestEnqueueMaterializesThePayload(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		enqueue func(*app.DeliveryIntentService) (app.Intent, error)
		subject string
	}{
		{"jira", func(s *app.DeliveryIntentService) (app.Intent, error) {
			return s.EnqueueJiraForRelease(ctx, lineage(), "env-1", "rel-1", "", "", nil)
		}, "subject for jira_issue"},
		{"decision mail", func(s *app.DeliveryIntentService) (app.Intent, error) {
			return s.EnqueueDecisionMail(ctx, lineage(), "env-2", "prop-1", "fnd-1", "rel-1", "", nil)
		}, "subject for email"},
		{"dead-letter mail", func(s *app.DeliveryIntentService) (app.Intent, error) {
			return s.EnqueueDeadLetterMail(ctx, lineage(), "int-dead", "", nil)
		}, "subject for email"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newIntentStore()
			renderer := &stubRenderer{}
			in, err := tc.enqueue(intentSvc(store, app.DeliveryIntentConfig{}).WithPayloadRenderer(renderer))
			if err != nil {
				t.Fatalf("enqueue: %v", err)
			}
			if len(in.PayloadBytes) == 0 || in.PayloadSHA256 == "" {
				t.Fatalf("payload not materialized: %q / %q", in.PayloadSHA256, in.PayloadBytes)
			}
			if got := app.PayloadDigest(in.PayloadBytes); got != in.PayloadSHA256 {
				t.Errorf("digest = %q, does not address the stored bytes (%q)", in.PayloadSHA256, got)
			}
			subject, body := app.SplitPayload(in.PayloadBytes)
			if subject != tc.subject || len(body) == 0 {
				t.Errorf("envelope = %q / %q", subject, body)
			}
			// The payload reached the STORE, not just the returned value.
			if len(store.created) != 1 || store.created[0].PayloadSHA256 != in.PayloadSHA256 {
				t.Errorf("stored intent = %+v", store.created)
			}
		})
	}
}

// A render that fails enqueues NOTHING. An intent whose content could not be determined is the
// intent that must not exist: the alternative is a sender rendering it later, which is exactly the
// render-at-send D-N-3 forbids. The originating event is retried by the bus, so nothing is lost.
func TestEnqueueFailsClosedWhenTheRenderFails(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("governance unreachable")
	for _, tc := range []struct {
		name     string
		renderer *stubRenderer
		want     error
	}{
		{"render error", &stubRenderer{err: boom}, boom},
		{"empty payload", &stubRenderer{empty: true}, app.ErrEmptyPayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newIntentStore()
			svc := intentSvc(store, app.DeliveryIntentConfig{}).WithPayloadRenderer(tc.renderer)
			if _, err := svc.EnqueueJiraForRelease(ctx, lineage(), "env-1", "rel-1", "", "", nil); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if len(store.created) != 0 {
				t.Error("an intent was recorded despite having no determinable payload")
			}
		})
	}
}

// A replay re-renders and then DISCARDS the result: CreateIntent returns the row already there,
// payload included. Determinism is a property of the record, not of the renderer.
func TestReplayKeepsTheFirstMaterializedPayload(t *testing.T) {
	ctx := context.Background()
	store := newIntentStore()
	renderer := &stubRenderer{}
	svc := intentSvc(store, app.DeliveryIntentConfig{}).WithPayloadRenderer(renderer)

	first, err := svc.EnqueueJiraForRelease(ctx, lineage(), "env-1", "rel-1", "", "", nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.EnqueueJiraForRelease(ctx, lineage(), "env-1", "rel-1", "", "", nil)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if second.ID != first.ID || second.PayloadSHA256 != first.PayloadSHA256 {
		t.Errorf("replay returned a different intent/payload: %+v vs %+v", second, first)
	}
	if len(store.created) != 1 {
		t.Errorf("created %d intents, want 1", len(store.created))
	}
}

// The payload envelope: one Subject line, a blank line, the body — and the round trip.
func TestPayloadEnvelope(t *testing.T) {
	payload := app.BuildPayload("  one\nline  ", []byte("first\n\nsecond\n"))
	if want := "Subject: one line\n\nfirst\n\nsecond\n"; string(payload) != want {
		t.Errorf("payload = %q, want %q", payload, want)
	}
	subject, body := app.SplitPayload(payload)
	if subject != "one line" || string(body) != "first\n\nsecond\n" {
		t.Errorf("split = %q / %q", subject, body)
	}
	// An N-M1a row (no envelope) yields no subject and the bytes whole — a real sender refuses it
	// rather than guessing a summary.
	if subject, body := app.SplitPayload([]byte("legacy body")); subject != "" || string(body) != "legacy body" {
		t.Errorf("legacy split = %q / %q", subject, body)
	}
	// A header with no blank line after it is a subject and no body — refused downstream, never
	// sent as a bodyless mail.
	if subject, body := app.SplitPayload([]byte("Subject: alone\n")); subject != "alone" || body != nil {
		t.Errorf("headers-only split = %q / %q", subject, body)
	}
	if app.PayloadDigest(nil) == app.PayloadDigest([]byte("x")) {
		t.Error("the digest does not distinguish payloads")
	}
	if got := len(app.PayloadDigest([]byte("x"))); got != 64 {
		t.Errorf("digest length = %d, want a hex SHA-256", got)
	}
}
