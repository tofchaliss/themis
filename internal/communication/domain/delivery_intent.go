package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// A DeliveryIntent is Themis's RECORD OF A DECISION TO ACT OUTWARD (outward-actions N-M1a):
// a Governance fact happened, and because of it a Jira issue / an e-mail / a CI build ought
// to exist somewhere outside the estate. Recording the intent is the whole of what the event
// path does — it never talks to Jira, a mail relay or a CI system, so no outward system's
// availability can stall, fail or retry the governance bus. Separate per-channel workers
// pick the intent up afterwards and try to send it.
//
// Three properties make that separation safe, and all three live here rather than in the
// worker:
//
//  1. The intent is a SNAPSHOT. Its lineage (which event, which Finding, which release) and
//     its materialized payload bytes are frozen at record time, so a send that happens
//     minutes or days later delivers what the fact said THEN — regenerating from current
//     state would silently deliver a different message than the one governance decided on.
//  2. It moves FORWARD ONLY. PENDING → DELIVERED / DEAD_LETTER / CANCELLED, and a retry
//     re-opens a terminal intent rather than erasing it. Nothing is ever deleted: the
//     attempt history is the audit of what Themis tried to do on the outside world.
//  3. It gives up LOUDLY. After max_attempts the intent is dead-lettered with the last
//     error kept, so a person can see it, retry it or cancel it — a silently dropped
//     outward action is indistinguishable from one that was never asked for.
type DeliveryIntent struct {
	id            string
	kind          DeliveryKind
	destination   string
	origin        DeliveryOrigin
	snapshot      []byte
	payload       []byte
	payloadHash   string
	status        IntentStatus
	attempts      int
	maxAttempts   int
	lastError     string
	nextAttemptAt time.Time
	createdAt     time.Time
	updatedAt     time.Time
}

// DeliveryKind names the outward channel an intent is destined for. The vocabulary is
// closed: an unknown kind has no worker and would sit PENDING forever.
type DeliveryKind string

// The three delivery kinds of N-M1a. jira_issue follows a newly opened Finding; email and
// ci_build follow an accepted proposal (ci_build only when that proposal rested on a
// commissioned harness execution).
const (
	DeliveryJiraIssue DeliveryKind = "jira_issue"
	DeliveryEmail     DeliveryKind = "email"
	DeliveryCIBuild   DeliveryKind = "ci_build"
)

// Valid reports whether the kind is one of the three known channels.
func (k DeliveryKind) Valid() bool {
	switch k {
	case DeliveryJiraIssue, DeliveryEmail, DeliveryCIBuild:
		return true
	default:
		return false
	}
}

// IntentStatus is the intent's forward-only lifecycle state.
type IntentStatus string

// The four intent states. PENDING is the only non-terminal one; DEAD_LETTER and CANCELLED
// are re-openable by an operator (Retry), DELIVERED is final.
const (
	IntentPending    IntentStatus = "PENDING"
	IntentDelivered  IntentStatus = "DELIVERED"
	IntentDeadLetter IntentStatus = "DEAD_LETTER"
	IntentCancelled  IntentStatus = "CANCELLED"
)

// Valid reports whether the status is one of the four known states.
func (s IntentStatus) Valid() bool {
	switch s {
	case IntentPending, IntentDelivered, IntentDeadLetter, IntentCancelled:
		return true
	default:
		return false
	}
}

// DeliveryOrigin is the immutable lineage the intent was born from (D-N-3): which bus event
// caused it, and which governance subjects that event named. These are reference HANDLES,
// never copies of upstream state — the same rule Lineage follows. Fields absent from a given
// event stay zero rather than being resolved from current state, because resolving later
// would put a fact into the snapshot that was not true when the decision was taken.
type DeliveryOrigin struct {
	// EventID identifies the causing bus envelope. It is the dedup identity: the same
	// envelope redelivered must not produce a second intent.
	EventID   string
	EventType string
	EventTime time.Time

	FindingID   string
	ReleaseID   string
	FaultlineID string
	CVE         string
	ProductID   string
	ProposalID  string

	PositionVersion int
}

// DeliveryAttempt is one append-only row of an intent's send history: when it was tried,
// whether it worked, and the error if it did not. The history is never pruned — it is how
// an operator answers "what did Themis actually try to do, and what did the other side say".
type DeliveryAttempt struct {
	AttemptNo int
	OK        bool
	Error     string
	At        time.Time
}

// BackoffPolicy is the retry schedule a failed intent waits out before the worker picks it
// up again: the base delay doubled per attempt, capped. It is a domain value rather than a
// worker detail because "when may this be tried again" is part of the intent's state — the
// worker reads the due time, it does not decide it.
type BackoffPolicy struct {
	Base time.Duration
	Cap  time.Duration
}

// defaultBackoffCap bounds the wait when a policy states no cap of its own. A doubling with
// no ceiling is not merely slow, it overflows into a negative duration and would make a
// failed intent due in the past forever.
const defaultBackoffCap = 30 * time.Second

// Delay returns how long to wait after the given (1-based) attempt number: Base doubled
// once per prior attempt, never past the cap. Doubling stops at the cap rather than after
// it, which is also what keeps the arithmetic from overflowing.
func (p BackoffPolicy) Delay(attempt int) time.Duration {
	if p.Base <= 0 || attempt <= 0 {
		return 0
	}
	ceiling := p.Cap
	if ceiling <= 0 {
		ceiling = defaultBackoffCap
	}
	d := p.Base
	for i := 1; i < attempt; i++ {
		if d >= ceiling/2 {
			return ceiling
		}
		d *= 2
	}
	if d > ceiling {
		return ceiling
	}
	return d
}

// Intent construction / transition errors.
var (
	errEmptyIntentID       = errors.New("communication: empty delivery intent id")
	errUnknownDeliveryKind = errors.New("communication: unknown delivery kind")
	errEmptyDestination    = errors.New("communication: empty delivery destination")
	errEmptyOriginEvent    = errors.New("communication: delivery intent missing origin event")

	// ErrIntentNotRetryable is returned when retrying an intent that is not in a terminal,
	// re-openable state. Only DEAD_LETTER and CANCELLED may be re-opened: re-opening a
	// PENDING intent would reset the attempt counter of a send that may be in flight, and a
	// DELIVERED one has already reached the outside world.
	ErrIntentNotRetryable = errors.New("communication: delivery intent is not retryable")

	// ErrIntentNotCancellable is returned when cancelling an intent that is not PENDING.
	// A DELIVERED intent cannot be un-sent, and a DEAD_LETTER one has already stopped —
	// cancelling it would only relabel a failure as a decision.
	ErrIntentNotCancellable = errors.New("communication: delivery intent is not cancellable")
)

// NewDeliveryIntent records a fresh PENDING intent, MATERIALIZING its snapshot and payload
// here rather than taking them from the caller. That is the freezing (D-N-3) and it belongs
// with the record: a caller that could supply its own bytes could supply bytes that do not
// match the lineage, and the hash would then certify a mismatch. maxAttempts below 1 is
// raised to 1 — an intent nobody may ever try is a silent drop.
func NewDeliveryIntent(id string, kind DeliveryKind, destination string, origin DeliveryOrigin,
	maxAttempts int, now time.Time) (DeliveryIntent, error) {
	switch {
	case id == "":
		return DeliveryIntent{}, errEmptyIntentID
	case destination == "":
		return DeliveryIntent{}, errEmptyDestination
	case origin.EventID == "" || origin.EventType == "":
		return DeliveryIntent{}, errEmptyOriginEvent
	}
	payload, err := MaterializeDeliveryPayload(kind, origin) // also refuses an unknown kind
	if err != nil {
		return DeliveryIntent{}, err
	}
	snapshot := MarshalDeliverySnapshot(origin)
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	sum := sha256.Sum256(payload)
	return DeliveryIntent{
		id: id, kind: kind, destination: destination, origin: origin,
		snapshot: snapshot, payload: payload, payloadHash: hex.EncodeToString(sum[:]),
		status: IntentPending, maxAttempts: maxAttempts,
		nextAttemptAt: now, createdAt: now, updatedAt: now,
	}, nil
}

// ReconstituteDeliveryIntent rebuilds a stored intent verbatim (the store's inverse of
// NewDeliveryIntent). It applies no rules: a persisted record is history, not a new decision.
func ReconstituteDeliveryIntent(id string, kind DeliveryKind, destination string, origin DeliveryOrigin,
	snapshot, payload []byte, payloadHash string, status IntentStatus,
	attempts, maxAttempts int, lastError string,
	nextAttemptAt, createdAt, updatedAt time.Time) DeliveryIntent {
	return DeliveryIntent{
		id: id, kind: kind, destination: destination, origin: origin,
		snapshot: snapshot, payload: payload, payloadHash: payloadHash,
		status: status, attempts: attempts, maxAttempts: maxAttempts, lastError: lastError,
		nextAttemptAt: nextAttemptAt, createdAt: createdAt, updatedAt: updatedAt,
	}
}

// Accessors — the intent is immutable from the outside; only the transition methods below
// change it, and they do so on a copy held by value.
func (i DeliveryIntent) ID() string               { return i.id }
func (i DeliveryIntent) Kind() DeliveryKind       { return i.kind }
func (i DeliveryIntent) Destination() string      { return i.destination }
func (i DeliveryIntent) Origin() DeliveryOrigin   { return i.origin }
func (i DeliveryIntent) Snapshot() []byte         { return i.snapshot }
func (i DeliveryIntent) Payload() []byte          { return i.payload }
func (i DeliveryIntent) PayloadHash() string      { return i.payloadHash }
func (i DeliveryIntent) Status() IntentStatus     { return i.status }
func (i DeliveryIntent) Attempts() int            { return i.attempts }
func (i DeliveryIntent) MaxAttempts() int         { return i.maxAttempts }
func (i DeliveryIntent) LastError() string        { return i.lastError }
func (i DeliveryIntent) NextAttemptAt() time.Time { return i.nextAttemptAt }
func (i DeliveryIntent) CreatedAt() time.Time     { return i.createdAt }
func (i DeliveryIntent) UpdatedAt() time.Time     { return i.updatedAt }

// RecordSuccess marks a delivered send and returns the history row to append. It is
// idempotent on an already-DELIVERED intent (ok=false), so a worker that raced with itself
// cannot double-count an attempt.
func (i *DeliveryIntent) RecordSuccess(at time.Time) (DeliveryAttempt, bool) {
	if i.status == IntentDelivered {
		return DeliveryAttempt{}, false
	}
	i.attempts++
	i.status = IntentDelivered
	i.lastError = ""
	i.updatedAt = at
	return DeliveryAttempt{AttemptNo: i.attempts, OK: true, At: at}, true
}

// RecordFailure records a failed send and returns the history row to append. The attempt
// counter rises; once it reaches maxAttempts the intent is DEAD_LETTER (it stops being
// picked up, and an operator has to decide), otherwise it stays PENDING and becomes due
// again after the policy's backoff. The last error is kept either way — a dead letter with
// no stated cause is just as opaque as a dropped one.
func (i *DeliveryIntent) RecordFailure(msg string, at time.Time, p BackoffPolicy) (DeliveryAttempt, bool) {
	if i.status == IntentDelivered {
		return DeliveryAttempt{}, false
	}
	i.attempts++
	i.lastError = msg
	i.updatedAt = at
	if i.attempts >= i.maxAttempts {
		i.status = IntentDeadLetter
		i.nextAttemptAt = at
	} else {
		i.status = IntentPending
		i.nextAttemptAt = at.Add(p.Delay(i.attempts))
	}
	return DeliveryAttempt{AttemptNo: i.attempts, OK: false, Error: msg, At: at}, true
}

// Retry re-opens a terminal intent for the workers: PENDING again, attempts back to zero,
// due immediately. The attempt HISTORY is untouched — a retry adds a new chapter, it does
// not erase the failed one. Refused on PENDING (nothing to re-open) and on DELIVERED
// (already sent) with ErrIntentNotRetryable.
func (i *DeliveryIntent) Retry(at time.Time) error {
	if i.status != IntentDeadLetter && i.status != IntentCancelled {
		return ErrIntentNotRetryable
	}
	i.status = IntentPending
	i.attempts = 0
	i.lastError = ""
	i.nextAttemptAt = at
	i.updatedAt = at
	return nil
}

// Cancel withdraws a PENDING intent: the workers stop picking it up and the record survives
// as the statement that a human decided this outward action should not happen. Cancelling an
// already-CANCELLED intent is a no-op success (the operator's request is already satisfied);
// anything else is ErrIntentNotCancellable.
func (i *DeliveryIntent) Cancel(at time.Time) error {
	if i.status == IntentCancelled {
		return nil // idempotent — the caller asked for a state that already holds
	}
	if i.status != IntentPending {
		return ErrIntentNotCancellable
	}
	i.status = IntentCancelled
	i.updatedAt = at
	return nil
}

// MaterializeDeliveryPayload renders the bytes a sender will hand to the outward channel
// (D-N-3). It is DETERMINISTIC — the same origin always renders the same bytes, which is
// what lets the payload hash mean anything — and it is computed ONCE, at record time, from
// the snapshot alone. Nothing here reads current state, and nothing here is channel-specific
// formatting: a real Jira client will map these fields onto its own issue schema when M2
// lands. At N-M1a the payload is deliberately minimal (the fuller artifact capture is N-M2);
// what matters now is that the structure and the freezing exist.
func MaterializeDeliveryPayload(kind DeliveryKind, origin DeliveryOrigin) ([]byte, error) {
	// The one human-readable line each channel needs — an issue summary, a mail subject, a
	// build label. It states the FACT, never a judgement: Communication materializes
	// decisions, it does not take them. An unknown kind has no line and no worker, so it is
	// refused here rather than recorded as an intent nobody will ever pick up.
	var subject string
	switch kind {
	case DeliveryJiraIssue:
		subject = "Finding opened: " + orDash(origin.CVE) + " on release " + orDash(origin.ReleaseID)
	case DeliveryEmail:
		subject = "Enterprise position accepted for finding " + orDash(origin.FindingID)
	case DeliveryCIBuild:
		subject = "Harness-backed position accepted for finding " + orDash(origin.FindingID)
	default:
		return nil, errUnknownDeliveryKind
	}
	// Field order is the struct's declaration order, so the JSON is byte-stable.
	doc := struct {
		Kind            string `json:"kind"`
		OriginEventType string `json:"origin_event_type"`
		OriginEventID   string `json:"origin_event_id"`
		OccurredAt      string `json:"occurred_at"`
		FindingID       string `json:"finding_id,omitempty"`
		ReleaseID       string `json:"release_id,omitempty"`
		FaultlineID     string `json:"faultline_id,omitempty"`
		CVE             string `json:"cve,omitempty"`
		ProductID       string `json:"product_id,omitempty"`
		ProposalID      string `json:"proposal_id,omitempty"`
		PositionVersion int    `json:"position_version,omitempty"`
		Subject         string `json:"subject"`
	}{
		Kind:            string(kind),
		OriginEventType: origin.EventType,
		OriginEventID:   origin.EventID,
		OccurredAt:      origin.EventTime.UTC().Format(time.RFC3339Nano),
		FindingID:       origin.FindingID,
		ReleaseID:       origin.ReleaseID,
		FaultlineID:     origin.FaultlineID,
		CVE:             origin.CVE,
		ProductID:       origin.ProductID,
		ProposalID:      origin.ProposalID,
		PositionVersion: origin.PositionVersion,
		Subject:         subject,
	}
	return json.Marshal(doc)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// deliverySnapshotDoc is the stored lineage snapshot's wire shape: DeliveryOrigin's fields
// with their JSON names. It is CONVERTIBLE to and from DeliveryOrigin, which is the point —
// the two cannot drift apart without a compile error, so no field can survive writing but
// not reading and leave a silently narrowed audit trail behind. Keep the fields in
// DeliveryOrigin's order; the conversions below stop compiling otherwise.
type deliverySnapshotDoc struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	EventTime       time.Time `json:"event_time"`
	FindingID       string    `json:"finding_id,omitempty"`
	ReleaseID       string    `json:"release_id,omitempty"`
	FaultlineID     string    `json:"faultline_id,omitempty"`
	CVE             string    `json:"cve,omitempty"`
	ProductID       string    `json:"product_id,omitempty"`
	ProposalID      string    `json:"proposal_id,omitempty"`
	PositionVersion int       `json:"position_version,omitempty"`
}

// MarshalDeliverySnapshot renders the immutable lineage snapshot stored beside the payload
// (D-N-3). It is the regeneration input: the payload can always be re-derived from it,
// whatever current state says. It returns no error because it cannot fail — the document is
// strings, an int and a time, none of which json.Marshal can refuse.
func MarshalDeliverySnapshot(origin DeliveryOrigin) []byte {
	origin.EventTime = origin.EventTime.UTC() // one stored form, whatever zone the event carried
	raw, _ := json.Marshal(deliverySnapshotDoc(origin))
	return raw
}

// UnmarshalDeliverySnapshot rebuilds the lineage from its stored JSON.
func UnmarshalDeliverySnapshot(raw []byte) (DeliveryOrigin, error) {
	var doc deliverySnapshotDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return DeliveryOrigin{}, err
	}
	return DeliveryOrigin(doc), nil
}
