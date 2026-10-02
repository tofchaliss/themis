package app

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrIntentNotFound is returned by the operator operations (retry / cancel / get) when no
// intent carries that id. The CLI turns it into a non-zero exit rather than a silent success.
var ErrIntentNotFound = errors.New("communication: delivery intent not found")

// ErrNoSubject is returned when an intent would have no subject to act about — a Jira ticket
// for no Release, a decision mail for no proposal. It fails CLOSED (nothing is enqueued):
// an outward action whose subject is indeterminate is exactly the action that must not go out
// (EDR-DELIVERY-01 RC-7).
var ErrNoSubject = errors.New("communication: delivery intent has no subject")

// IntentType is the outward channel an intent is destined for. The vocabulary is CLOSED and
// mirrored by a CHECK constraint in the store: `jira_issue` and `email`. N-M1a deliberately
// has no CI kind — the rebuild loop is a later milestone, and a type nothing can send would
// read as a capability.
type IntentType string

const (
	// IntentJiraIssue tracks remediation of a Release in the issue tracker (one ticket per
	// Release — EDR-DELIVERY-01 RC-2).
	IntentJiraIssue IntentType = "jira_issue"
	// IntentEmail notifies a governed audience by plain mail (RC-5).
	IntentEmail IntentType = "email"
)

// IntentState is where an intent is in its delivery life. `pending` is the only state a
// worker acts on; `delivered` and `cancelled` are terminal; `dead_letter` is terminal until
// an operator retries it.
type IntentState string

const (
	IntentPending    IntentState = "pending"
	IntentDelivered  IntentState = "delivered"
	IntentDeadLetter IntentState = "dead_letter"
	IntentCancelled  IntentState = "cancelled"
)

// AttemptOutcome is what one send attempt came back as.
type AttemptOutcome string

const (
	AttemptSuccess AttemptOutcome = "success"
	AttemptFailure AttemptOutcome = "failure"
)

// snapshotKeyNotification marks an intent that EXISTS because another intent died. The worker
// reads it to stop the notification chain: a dead-lettered dead-letter mail must not enqueue
// yet another dead-letter mail, or one unreachable relay fills the table.
const snapshotKeyNotification = "notification"

// notificationDeadLetter is the snapshotKeyNotification value for the dead-letter mail.
const notificationDeadLetter = "dead_letter"

// IntentLineage is the originating envelope's identity, recorded so an outward effect can
// always be traced back to the fact that caused it. EventSeq is deliberately absent: the bus
// sequence is the event_log's own ordering column and is not carried in the kernel Envelope
// (EB-02), so recording it here would mean inventing a number.
type IntentLineage struct {
	SourceContext string    `json:"source_context"`
	EventType     string    `json:"event_type"`
	EventID       string    `json:"event_id"`
	EventTime     time.Time `json:"event_time"`
	CorrelationID string    `json:"correlation_id"`
}

// Intent is one durable "this must go out" record. It carries NO credential and NO model
// output: the eventual payload derives from Snapshot and from nothing else (RC-7). The
// payload columns (PayloadSHA256 / PayloadBytes) stay empty in N-M1a — materialization is
// N-M1b's, and an invented shape would have to be migrated away.
type Intent struct {
	ID          string
	Type        IntentType
	Destination string // a GOVERNED name (an audience, a project alias) — never an address or a key
	State       IntentState

	Attempts      int
	NextAttemptAt time.Time
	LastAttemptAt time.Time // zero = never attempted
	LastError     string
	Result        map[string]string // delivery outcome metadata, recorded on success

	PayloadSHA256 string
	PayloadBytes  []byte

	Snapshot map[string]string // immutable facts at creation
	Lineage  IntentLineage

	// OriginEventID is the kernel envelope id that caused this intent; empty means
	// worker-originated (stored NULL, so it takes part in no uniqueness).
	OriginEventID string

	ProductID  string
	ProjectID  string
	ReleaseID  string
	FindingID  string
	ProposalID string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// IsDeadLetterNotification reports whether this intent exists to tell a person that another
// intent died.
func (i Intent) IsDeadLetterNotification() bool {
	return i.Snapshot[snapshotKeyNotification] == notificationDeadLetter
}

// Attempt is one append-only row of the attempt ledger plus the intent counters it moves.
// NextAttemptAt is supplied by the caller because the backoff schedule is the WORKER's
// configuration (initial/max), not the store's — the store would have to guess it.
type Attempt struct {
	IntentID        string
	AttemptNo       int
	Outcome         AttemptOutcome
	StatusCode      int // 0 = no status (a transport failure, or a channel without one)
	ResponseExcerpt string
	Error           string
	At              time.Time
	NextAttemptAt   time.Time
}

// DeliveryIntents is the delivery-intent store port. CreateIntent is idempotent on the
// originating event id; everything else keys on the intent id.
//
// State transitions belong to MarkDelivered / MarkDeadLetter / CancelIntent / RetryIntent —
// RecordAttempt moves only the counters (attempts, last_attempt_at, last_error,
// next_attempt_at) and appends the ledger row. One writer per transition is what keeps
// "which call decided this row is dead" answerable; a crash between the failed attempt and
// the dead-letter is self-healing, because a worker that fetches a pending intent whose
// attempts already reached the maximum dead-letters it without sending again.
type DeliveryIntents interface {
	// CreateIntent persists the intent and returns it as stored. When OriginEventID is set
	// and a row already carries it, the EXISTING intent is returned and nothing is created —
	// which is what makes an at-least-once redelivery harmless.
	CreateIntent(ctx context.Context, in Intent) (Intent, error)
	// GetIntent loads one intent, or ErrIntentNotFound.
	GetIntent(ctx context.Context, id string) (Intent, error)
	// GetPendingForWork returns pending intents due at or before now (next_attempt_at asc,
	// attempts asc), up to limit.
	GetPendingForWork(ctx context.Context, now time.Time, limit int) ([]Intent, error)
	// RecordAttempt appends the attempt row and advances the intent's counters.
	RecordAttempt(ctx context.Context, a Attempt) error
	// MarkDelivered moves the intent to `delivered` and records the outcome metadata.
	MarkDelivered(ctx context.Context, id string, result map[string]string) error
	// MarkDeadLetter moves the intent to `dead_letter` with the error that exhausted it.
	MarkDeadLetter(ctx context.Context, id, lastError string) error
	// CancelIntent moves a non-delivered intent to `cancelled` (operator).
	CancelIntent(ctx context.Context, id string) error
	// ListDeadLetters returns dead-lettered intents updated at or after since, newest first.
	ListDeadLetters(ctx context.Context, since time.Time, limit int) ([]Intent, error)
	// RetryIntent resets a dead-lettered or failed intent to pending with attempts=0, no last
	// error and next_attempt_at=now (operator).
	RetryIntent(ctx context.Context, id string) error
}

// DeliveryIntentConfig names the GOVERNED destinations an intent may carry. They are names,
// resolved to real addresses/projects by the sender at delivery time — an intent never holds
// an address or a credential (RC-5/RC-7).
type DeliveryIntentConfig struct {
	JiraDestination    string // issue-tracker project alias for release remediation tickets
	DecisionAudience   string // audience notified when a proposal is accepted
	DeadLetterAudience string // audience told that a delivery gave up
}

// Default destination names, used for any field left empty.
const (
	defaultJiraDestination    = "themis-remediation"
	defaultDecisionAudience   = "security-decisions"
	defaultDeadLetterAudience = "operations"
)

func (c DeliveryIntentConfig) withDefaults() DeliveryIntentConfig {
	if strings.TrimSpace(c.JiraDestination) == "" {
		c.JiraDestination = defaultJiraDestination
	}
	if strings.TrimSpace(c.DecisionAudience) == "" {
		c.DecisionAudience = defaultDecisionAudience
	}
	if strings.TrimSpace(c.DeadLetterAudience) == "" {
		c.DeadLetterAudience = defaultDeadLetterAudience
	}
	return c
}

// DeliveryIntentService records what must go out. It is the ONLY way an intent is created,
// which is what keeps three guarantees in one place: the destination is a governed name, the
// snapshot carries the identity facts of record (a caller cannot omit them), and nothing is
// enqueued for an indeterminate subject.
//
// It performs no delivery and talks to no external system, so the inbound event reader can
// call it inside the inbox transaction: persisting an intent is the whole of the reader's
// outward work (N-M1a).
type DeliveryIntentService struct {
	intents DeliveryIntents
	ids     IDGenerator
	clock   Clock
	cfg     DeliveryIntentConfig
}

// NewDeliveryIntentService wires the service over the intent store; empty destination names
// fall back to the documented defaults.
func NewDeliveryIntentService(intents DeliveryIntents, ids IDGenerator, clock Clock, cfg DeliveryIntentConfig) *DeliveryIntentService {
	return &DeliveryIntentService{intents: intents, ids: ids, clock: clock, cfg: cfg.withDefaults()}
}

// DeadLetterAudience is the governed audience a dead-letter notification goes to.
func (s *DeliveryIntentService) DeadLetterAudience() string { return s.cfg.DeadLetterAudience }

// EnqueueJiraForRelease records the remediation ticket intent for a Release — one ticket per
// Release (RC-2), deduplicated by the originating event id. productID/projectID are recorded
// when the originating event carries them and left empty otherwise: resolving them would mean
// a Registry read on the reader path, and the reader never waits on another system.
func (s *DeliveryIntentService) EnqueueJiraForRelease(ctx context.Context, lineage IntentLineage, originEventID, releaseID, productID, projectID string, snapshot map[string]string) (Intent, error) {
	if strings.TrimSpace(releaseID) == "" {
		return Intent{}, ErrNoSubject
	}
	in := s.newIntent(IntentJiraIssue, s.cfg.JiraDestination, lineage, originEventID, snapshot)
	in.ReleaseID, in.ProductID, in.ProjectID = releaseID, productID, projectID
	in.Snapshot["release_id"] = releaseID
	putIfSet(in.Snapshot, "product_id", productID)
	putIfSet(in.Snapshot, "project_id", projectID)
	return s.intents.CreateIntent(ctx, in)
}

// EnqueueDecisionMail records the notification intent for an accepted proposal — a decision
// about exposure is told to the governed audience. An empty audience uses the configured
// default.
func (s *DeliveryIntentService) EnqueueDecisionMail(ctx context.Context, lineage IntentLineage, originEventID, proposalID, findingID, releaseID, audience string, snapshot map[string]string) (Intent, error) {
	if strings.TrimSpace(proposalID) == "" && strings.TrimSpace(findingID) == "" {
		return Intent{}, ErrNoSubject
	}
	if strings.TrimSpace(audience) == "" {
		audience = s.cfg.DecisionAudience
	}
	in := s.newIntent(IntentEmail, audience, lineage, originEventID, snapshot)
	in.ProposalID, in.FindingID, in.ReleaseID = proposalID, findingID, releaseID
	putIfSet(in.Snapshot, "proposal_id", proposalID)
	putIfSet(in.Snapshot, "finding_id", findingID)
	putIfSet(in.Snapshot, "release_id", releaseID)
	return s.intents.CreateIntent(ctx, in)
}

// EnqueueDeadLetterMail records the notification intent for an intent that gave up. It is
// worker-originated, so it carries NO originating event id (nothing deduplicates it but the
// fact that an intent dead-letters once) and it is marked as a notification so a failure to
// deliver IT cannot start a chain.
func (s *DeliveryIntentService) EnqueueDeadLetterMail(ctx context.Context, lineage IntentLineage, intentID, audience string, snapshot map[string]string) (Intent, error) {
	if strings.TrimSpace(intentID) == "" {
		return Intent{}, ErrNoSubject
	}
	if strings.TrimSpace(audience) == "" {
		audience = s.cfg.DeadLetterAudience
	}
	in := s.newIntent(IntentEmail, audience, lineage, "", snapshot)
	in.Snapshot[snapshotKeyNotification] = notificationDeadLetter
	in.Snapshot["dead_letter_intent_id"] = intentID
	return s.intents.CreateIntent(ctx, in)
}

// newIntent builds a pending intent with the facts of record stamped into the snapshot. The
// caller's snapshot is copied (never retained) and the service-owned keys win, so a caller
// cannot overwrite the lineage it is being held to.
func (s *DeliveryIntentService) newIntent(typ IntentType, destination string, lineage IntentLineage, originEventID string, snapshot map[string]string) Intent {
	now := s.clock.Now()
	snap := make(map[string]string, len(snapshot)+4)
	for k, v := range snapshot {
		snap[k] = v
	}
	putIfSet(snap, "event_type", lineage.EventType)
	putIfSet(snap, "event_id", lineage.EventID)
	if !lineage.EventTime.IsZero() {
		snap["event_time"] = lineage.EventTime.UTC().Format(time.RFC3339Nano)
	}
	return Intent{
		ID:            s.ids.NewID(),
		Type:          typ,
		Destination:   destination,
		State:         IntentPending,
		NextAttemptAt: now,
		Result:        map[string]string{},
		Snapshot:      snap,
		Lineage:       lineage,
		OriginEventID: originEventID,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func putIfSet(m map[string]string, key, value string) {
	if strings.TrimSpace(value) != "" {
		m[key] = value
	}
}
