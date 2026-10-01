package domain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

var intentEpoch = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func testOrigin() domain.DeliveryOrigin {
	return domain.DeliveryOrigin{
		EventID: "env-1", EventType: "governance.finding_opened", EventTime: intentEpoch,
		FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1",
		ProductID: "prod-1", ProposalID: "prop-1", PositionVersion: 3,
	}
}

func newTestIntent(t *testing.T, kind domain.DeliveryKind, maxAttempts int) domain.DeliveryIntent {
	t.Helper()
	in, err := domain.NewDeliveryIntent("int-1", kind, "default", testOrigin(), maxAttempts, intentEpoch)
	if err != nil {
		t.Fatalf("new intent: %v", err)
	}
	return in
}

func TestNewDeliveryIntent_RecordsAPendingSnapshot(t *testing.T) {
	in := newTestIntent(t, domain.DeliveryJiraIssue, 3)

	if in.ID() != "int-1" || in.Kind() != domain.DeliveryJiraIssue || in.Destination() != "default" {
		t.Errorf("identity = %s/%s/%s", in.ID(), in.Kind(), in.Destination())
	}
	if in.Status() != domain.IntentPending || in.Attempts() != 0 || in.MaxAttempts() != 3 || in.LastError() != "" {
		t.Errorf("state = %s attempts=%d max=%d err=%q", in.Status(), in.Attempts(), in.MaxAttempts(), in.LastError())
	}
	// Due immediately, and every stamp is the record time.
	if !in.NextAttemptAt().Equal(intentEpoch) || !in.CreatedAt().Equal(intentEpoch) || !in.UpdatedAt().Equal(intentEpoch) {
		t.Errorf("stamps = %v/%v/%v", in.NextAttemptAt(), in.CreatedAt(), in.UpdatedAt())
	}
	// The hash pins the recorded bytes: that is what makes the payload a snapshot rather
	// than a hint about how to regenerate one.
	sum := sha256.Sum256(in.Payload())
	if in.PayloadHash() != hex.EncodeToString(sum[:]) || in.PayloadHash() == "" {
		t.Errorf("payload hash = %q", in.PayloadHash())
	}
	if in.Origin().FindingID != "fnd-1" || len(in.Snapshot()) == 0 {
		t.Errorf("origin/snapshot = %+v / %q", in.Origin(), in.Snapshot())
	}
}

func TestNewDeliveryIntent_Refusals(t *testing.T) {
	o := testOrigin()
	cases := []struct {
		name        string
		id          string
		kind        domain.DeliveryKind
		destination string
		origin      domain.DeliveryOrigin
	}{
		{"empty id", "", domain.DeliveryEmail, "default", o},
		{"unknown kind", "i", domain.DeliveryKind("slack"), "default", o},
		{"empty destination", "i", domain.DeliveryEmail, "", o},
		{"no origin event id", "i", domain.DeliveryEmail, "default", domain.DeliveryOrigin{EventType: "t"}},
		{"no origin event type", "i", domain.DeliveryEmail, "default", domain.DeliveryOrigin{EventID: "e"}},
	}
	for _, c := range cases {
		if _, err := domain.NewDeliveryIntent(c.id, c.kind, c.destination, c.origin, 3, intentEpoch); err == nil {
			t.Errorf("%s: want refusal, got nil", c.name)
		}
	}
}

// A max-attempts budget below one would record an intent nobody may ever try — a silent
// drop wearing the clothes of a queued action.
func TestNewDeliveryIntent_MaxAttemptsFloorsAtOne(t *testing.T) {
	in, err := domain.NewDeliveryIntent("i", domain.DeliveryEmail, "default", testOrigin(), 0, intentEpoch)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if in.MaxAttempts() != 1 {
		t.Errorf("max attempts = %d, want 1", in.MaxAttempts())
	}
}

func TestDeliveryIntent_SuccessDelivers(t *testing.T) {
	in := newTestIntent(t, domain.DeliveryEmail, 3)
	at := intentEpoch.Add(time.Minute)

	att, ok := in.RecordSuccess(at)
	if !ok || att.AttemptNo != 1 || !att.OK || !att.At.Equal(at) {
		t.Fatalf("attempt = %+v ok=%v", att, ok)
	}
	if in.Status() != domain.IntentDelivered || in.Attempts() != 1 || in.LastError() != "" {
		t.Errorf("state = %s attempts=%d", in.Status(), in.Attempts())
	}
	// A second outcome for a delivered intent is not a second attempt.
	if _, ok := in.RecordSuccess(at); ok {
		t.Error("delivered intent recorded a second success")
	}
	if _, ok := in.RecordFailure("late", at, domain.BackoffPolicy{}); ok {
		t.Error("delivered intent recorded a failure")
	}
	if in.Attempts() != 1 {
		t.Errorf("attempts = %d after duplicate outcomes, want 1", in.Attempts())
	}
}

// The whole dead-letter rule in one test: the intent stays PENDING and becomes due later
// while the budget lasts, and stops with its cause stated when it runs out.
func TestDeliveryIntent_FailuresDeadLetterAfterMaxAttempts(t *testing.T) {
	in := newTestIntent(t, domain.DeliveryJiraIssue, 3)
	policy := domain.BackoffPolicy{Base: 100 * time.Millisecond, Cap: time.Second}

	for attempt := 1; attempt <= 2; attempt++ {
		at := intentEpoch.Add(time.Duration(attempt) * time.Minute)
		att, ok := in.RecordFailure("jira refused", at, policy)
		if !ok || att.AttemptNo != attempt || att.OK || att.Error != "jira refused" {
			t.Fatalf("attempt %d = %+v ok=%v", attempt, att, ok)
		}
		if in.Status() != domain.IntentPending {
			t.Fatalf("attempt %d: status = %s, want PENDING", attempt, in.Status())
		}
		want := at.Add(policy.Delay(attempt))
		if !in.NextAttemptAt().Equal(want) {
			t.Errorf("attempt %d: next attempt = %v, want %v", attempt, in.NextAttemptAt(), want)
		}
	}

	at := intentEpoch.Add(3 * time.Minute)
	if _, ok := in.RecordFailure("jira refused", at, policy); !ok {
		t.Fatal("third failure not recorded")
	}
	if in.Status() != domain.IntentDeadLetter || in.Attempts() != 3 || in.LastError() != "jira refused" {
		t.Errorf("final state = %s attempts=%d err=%q", in.Status(), in.Attempts(), in.LastError())
	}
}

func TestDeliveryIntent_RetryReopensTerminalStates(t *testing.T) {
	policy := domain.BackoffPolicy{Base: time.Millisecond, Cap: time.Second}
	at := intentEpoch.Add(time.Hour)

	dead := newTestIntent(t, domain.DeliveryEmail, 1)
	dead.RecordFailure("relay down", intentEpoch, policy)
	if dead.Status() != domain.IntentDeadLetter {
		t.Fatalf("setup: status = %s", dead.Status())
	}
	if err := dead.Retry(at); err != nil {
		t.Fatalf("retry dead letter: %v", err)
	}
	if dead.Status() != domain.IntentPending || dead.Attempts() != 0 || dead.LastError() != "" ||
		!dead.NextAttemptAt().Equal(at) {
		t.Errorf("after retry = %s attempts=%d err=%q due=%v",
			dead.Status(), dead.Attempts(), dead.LastError(), dead.NextAttemptAt())
	}

	cancelled := newTestIntent(t, domain.DeliveryEmail, 3)
	if err := cancelled.Cancel(at); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if err := cancelled.Retry(at); err != nil {
		t.Errorf("retry cancelled: %v", err)
	}

	// Refused where there is nothing to re-open.
	pending := newTestIntent(t, domain.DeliveryEmail, 3)
	if err := pending.Retry(at); !errors.Is(err, domain.ErrIntentNotRetryable) {
		t.Errorf("retry pending = %v, want ErrIntentNotRetryable", err)
	}
	delivered := newTestIntent(t, domain.DeliveryEmail, 3)
	delivered.RecordSuccess(at)
	if err := delivered.Retry(at); !errors.Is(err, domain.ErrIntentNotRetryable) {
		t.Errorf("retry delivered = %v, want ErrIntentNotRetryable", err)
	}
}

func TestDeliveryIntent_CancelOnlyFromPending(t *testing.T) {
	at := intentEpoch.Add(time.Hour)

	in := newTestIntent(t, domain.DeliveryCIBuild, 3)
	if err := in.Cancel(at); err != nil {
		t.Fatalf("cancel pending: %v", err)
	}
	if in.Status() != domain.IntentCancelled || !in.UpdatedAt().Equal(at) {
		t.Errorf("state = %s updated=%v", in.Status(), in.UpdatedAt())
	}
	// Idempotent: the caller asked for a state that already holds.
	if err := in.Cancel(at.Add(time.Minute)); err != nil {
		t.Errorf("second cancel = %v, want nil", err)
	}

	delivered := newTestIntent(t, domain.DeliveryCIBuild, 3)
	delivered.RecordSuccess(at)
	if err := delivered.Cancel(at); !errors.Is(err, domain.ErrIntentNotCancellable) {
		t.Errorf("cancel delivered = %v, want ErrIntentNotCancellable", err)
	}
	dead := newTestIntent(t, domain.DeliveryCIBuild, 1)
	dead.RecordFailure("boom", at, domain.BackoffPolicy{})
	if err := dead.Cancel(at); !errors.Is(err, domain.ErrIntentNotCancellable) {
		t.Errorf("cancel dead letter = %v, want ErrIntentNotCancellable", err)
	}
}

func TestBackoffPolicy_Delay(t *testing.T) {
	p := domain.BackoffPolicy{Base: 100 * time.Millisecond, Cap: 800 * time.Millisecond}
	for _, c := range []struct {
		attempt int
		want    time.Duration
	}{
		{0, 0},
		{1, 100 * time.Millisecond},
		{2, 200 * time.Millisecond},
		{3, 400 * time.Millisecond},
		{4, 800 * time.Millisecond},
		{40, 800 * time.Millisecond}, // capped, and the doubling never overflows
	} {
		if got := p.Delay(c.attempt); got != c.want {
			t.Errorf("Delay(%d) = %v, want %v", c.attempt, got, c.want)
		}
	}
	if got := (domain.BackoffPolicy{}).Delay(3); got != 0 {
		t.Errorf("zero policy Delay = %v, want 0", got)
	}
	// A base already past the cap is clamped rather than honoured.
	if got := (domain.BackoffPolicy{Base: time.Minute, Cap: time.Second}).Delay(1); got != time.Second {
		t.Errorf("clamped base Delay = %v, want 1s", got)
	}
	// No cap stated falls back to the built-in ceiling rather than doubling into overflow.
	if got := (domain.BackoffPolicy{Base: time.Second}).Delay(30); got != 30*time.Second {
		t.Errorf("uncapped Delay = %v, want the 30s default ceiling", got)
	}
}

func TestDeliveryKindAndStatusVocabularies(t *testing.T) {
	for _, k := range []domain.DeliveryKind{domain.DeliveryJiraIssue, domain.DeliveryEmail, domain.DeliveryCIBuild} {
		if !k.Valid() {
			t.Errorf("kind %s should be valid", k)
		}
	}
	if domain.DeliveryKind("slack").Valid() {
		t.Error("unknown kind accepted")
	}
	for _, s := range []domain.IntentStatus{domain.IntentPending, domain.IntentDelivered,
		domain.IntentDeadLetter, domain.IntentCancelled} {
		if !s.Valid() {
			t.Errorf("status %s should be valid", s)
		}
	}
	if domain.IntentStatus("RETRYING").Valid() {
		t.Error("unknown status accepted")
	}
}

// The payload is what a sender hands to the outside world, so it must be a pure function of
// the frozen lineage: same origin in, identical bytes out, whatever else has changed since.
func TestMaterializeDeliveryPayload_IsDeterministicAndPerKind(t *testing.T) {
	o := testOrigin()
	seen := map[string]bool{}
	for _, kind := range []domain.DeliveryKind{domain.DeliveryJiraIssue, domain.DeliveryEmail, domain.DeliveryCIBuild} {
		first, err := domain.MaterializeDeliveryPayload(kind, o)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		second, err := domain.MaterializeDeliveryPayload(kind, o)
		if err != nil {
			t.Fatalf("%s (again): %v", kind, err)
		}
		if string(first) != string(second) {
			t.Errorf("%s: payload is not deterministic:\n%s\n%s", kind, first, second)
		}
		if seen[string(first)] {
			t.Errorf("%s: payload collides with another kind's", kind)
		}
		seen[string(first)] = true

		var doc map[string]any
		if err := json.Unmarshal(first, &doc); err != nil {
			t.Fatalf("%s: payload is not JSON: %v", kind, err)
		}
		if doc["kind"] != string(kind) || doc["finding_id"] != "fnd-1" || doc["subject"] == "" {
			t.Errorf("%s: payload = %s", kind, first)
		}
	}
	if _, err := domain.MaterializeDeliveryPayload(domain.DeliveryKind("slack"), o); err == nil {
		t.Error("unknown kind materialized a payload")
	}

	// A proposal_accepted event names a Finding and nothing else, so the release and the CVE
	// really are absent — the subject line has to stay readable rather than trailing off into
	// blanks a person cannot tell from a truncated message.
	thin, err := domain.MaterializeDeliveryPayload(domain.DeliveryJiraIssue,
		domain.DeliveryOrigin{EventID: "e", EventType: "t"})
	if err != nil {
		t.Fatalf("thin origin: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(thin, &doc); err != nil {
		t.Fatalf("thin payload is not JSON: %v", err)
	}
	if doc["subject"] != "Finding opened: - on release -" {
		t.Errorf("thin subject = %v", doc["subject"])
	}
}

// A lineage field that survives writing but not reading would be a silently narrowed audit
// trail, so the snapshot has to round-trip whole.
func TestDeliverySnapshot_RoundTrips(t *testing.T) {
	o := testOrigin()
	raw := domain.MarshalDeliverySnapshot(o)
	back, err := domain.UnmarshalDeliverySnapshot(raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back != o {
		t.Errorf("round trip:\n got %+v\nwant %+v", back, o)
	}
	if _, err := domain.UnmarshalDeliverySnapshot([]byte("{not json")); err == nil {
		t.Error("malformed snapshot decoded without error")
	}
}

func TestReconstituteDeliveryIntent_AppliesNoRules(t *testing.T) {
	o := testOrigin()
	in := domain.ReconstituteDeliveryIntent("i", domain.DeliveryEmail, "default", o,
		[]byte(`{}`), []byte(`{}`), "hash", domain.IntentDeadLetter, 9, 3, "boom",
		intentEpoch, intentEpoch, intentEpoch)
	// Nine attempts against a budget of three is a state the rules would never produce;
	// history is loaded verbatim, not re-judged.
	if in.Attempts() != 9 || in.MaxAttempts() != 3 || in.Status() != domain.IntentDeadLetter ||
		in.LastError() != "boom" || in.PayloadHash() != "hash" {
		t.Errorf("reconstituted = %+v", in)
	}
}
