package app

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/communication/domain"
)

// DeliveryIntentConfig is the recording half of the outward-actions knobs (R2): how many
// times a worker may try, how long it waits between tries, and which governed destination
// name an intent is addressed to. At N-M1a there is exactly ONE destination per kind
// ("default"); the column exists — and is part of the dedup key — so multiple targets per
// kind can be added later without a migration or a change to the uniqueness guarantee.
type DeliveryIntentConfig struct {
	MaxAttempts int
	Backoff     domain.BackoffPolicy
	Destination string
}

// DefaultIntentDestination is the single governed target name of N-M1a. It is a NAME, never
// a credential: an intent records where an action is addressed, and the worker's sender
// resolves that name to an endpoint and a secret it holds itself (D-N-6).
const DefaultIntentDestination = "default"

// IntentFilter narrows an operator's list of delivery intents. An empty status or kind means
// "any"; Limit is clamped by the service so a caller cannot ask for the whole table.
type IntentFilter struct {
	Status domain.IntentStatus
	Kind   domain.DeliveryKind
	Limit  int
	Offset int
}

// The page-size contract, in ONE place because two rings depend on it and they must not be
// able to disagree. `DefaultIntentPageSize` is also the `default:` declared for `limit` in
// `api/communication.openapi.yaml`; oapi-codegen does not bind a declared default (an omitted
// `limit` arrives as a nil pointer), so the HTTP adapter applies it explicitly from this
// constant rather than from a literal of its own.
const (
	// DefaultIntentPageSize is the page size an operator gets when they ask for no particular
	// one. It must equal the `limit` default declared in the OpenAPI spec.
	DefaultIntentPageSize = 50
	// MaxIntentPageSize caps what a caller may ask for, so one operator query cannot pull the
	// whole table.
	MaxIntentPageSize = 500
)

// DeliveryIntentRepository persists delivery intents and their append-only attempt history.
// Intents are never deleted — statuses move forward and a retry re-opens them — so there is
// deliberately no Delete method on this port.
type DeliveryIntentRepository interface {
	// SaveIntent records a new intent. created=false means an intent for the same
	// (origin event, event type, kind, destination) already exists and this one was NOT
	// written — the dedup that makes a bus replay or a redelivered envelope harmless.
	SaveIntent(ctx context.Context, intent domain.DeliveryIntent) (created bool, err error)
	// DueIntents returns PENDING intents of one kind whose backoff has elapsed, oldest
	// first — the worker's queue, scoped so one channel's backlog never starves another.
	DueIntents(ctx context.Context, kind domain.DeliveryKind, now time.Time, limit int) ([]domain.DeliveryIntent, error)
	// RecordAttempt persists the intent's new state and appends the attempt row atomically,
	// so the history can never disagree with the counter it is the evidence for.
	RecordAttempt(ctx context.Context, intent domain.DeliveryIntent, attempt domain.DeliveryAttempt) error
	// SaveIntentState persists an operator-driven state change (retry / cancel) with no
	// attempt row — nothing was tried.
	SaveIntentState(ctx context.Context, intent domain.DeliveryIntent) error
	// GetIntent loads one intent; ErrIntentNotFound when it does not exist.
	GetIntent(ctx context.Context, id string) (domain.DeliveryIntent, error)
	// IntentAttempts returns one intent's history, oldest first.
	IntentAttempts(ctx context.Context, id string) ([]domain.DeliveryAttempt, error)
	// ListIntents returns intents matching the filter, newest first.
	ListIntents(ctx context.Context, filter IntentFilter) ([]domain.DeliveryIntent, error)
	// CountIntentsByStatus returns how many intents sit in each status — the one number an
	// operator (and scripts/vm-verify.sh) needs to see that outward actions are moving.
	CountIntentsByStatus(ctx context.Context) (map[domain.IntentStatus]int, error)
}

// DeliveryIntentService is the outward-actions use case (N-M1a). Its two halves never meet:
// the RECORDING half runs inside the governance bus reader's transaction and does nothing
// but write rows, and the SENDING half runs in separate per-channel workers. That is the
// whole point of the milestone — an unreachable Jira must not be able to stall, fail or
// retry the event stream, and it cannot, because the event path has no sender to call.
type DeliveryIntentService struct {
	repo  DeliveryIntentRepository
	ids   IDGenerator
	clock Clock
	cfg   DeliveryIntentConfig
}

// NewDeliveryIntentService wires the use case. A zero MaxAttempts or Destination takes the
// documented default, so a partially configured node still behaves predictably.
func NewDeliveryIntentService(repo DeliveryIntentRepository, ids IDGenerator, clock Clock, cfg DeliveryIntentConfig) *DeliveryIntentService {
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 5
	}
	if cfg.Destination == "" {
		cfg.Destination = DefaultIntentDestination
	}
	return &DeliveryIntentService{repo: repo, ids: ids, clock: clock, cfg: cfg}
}

// RecordFindingOpened records the outward actions a newly opened Finding calls for: a
// tracker issue. Nothing is sent here — see the type comment.
func (s *DeliveryIntentService) RecordFindingOpened(ctx context.Context, origin domain.DeliveryOrigin) (int, error) {
	return s.record(ctx, origin, domain.DeliveryJiraIssue)
}

// RecordProposalAccepted records the outward actions an accepted proposal calls for. An
// e-mail ALWAYS: somebody outside the tool needs to know a position was taken. A CI build
// only when the proposal rested on a commissioned harness execution — a build is how that
// execution's claim gets checked, and firing one for a proposal a human simply wrote would
// be a build with nothing to verify.
func (s *DeliveryIntentService) RecordProposalAccepted(ctx context.Context, origin domain.DeliveryOrigin, harnessExecution bool) (int, error) {
	kinds := []domain.DeliveryKind{domain.DeliveryEmail}
	if harnessExecution {
		kinds = append([]domain.DeliveryKind{domain.DeliveryCIBuild}, kinds...)
	}
	return s.record(ctx, origin, kinds...)
}

// record materializes and persists one intent per kind, and reports how many were newly
// created. A kind whose intent already exists for this origin event is skipped silently:
// that is the dedup working, not a failure, and returning an error would make the bus
// reader retry an envelope it has already fully applied.
func (s *DeliveryIntentService) record(ctx context.Context, origin domain.DeliveryOrigin, kinds ...domain.DeliveryKind) (int, error) {
	now := s.clock.Now()
	created := 0
	for _, kind := range kinds {
		intent, err := domain.NewDeliveryIntent(s.ids.NewID(), kind, s.cfg.Destination, origin, s.cfg.MaxAttempts, now)
		if err != nil {
			return created, err
		}
		ok, err := s.repo.SaveIntent(ctx, intent)
		if err != nil {
			return created, err
		}
		if ok {
			created++
		}
	}
	return created, nil
}

// DueIntents returns the next batch of intents of one kind whose backoff has elapsed.
func (s *DeliveryIntentService) DueIntents(ctx context.Context, kind domain.DeliveryKind, limit int) ([]domain.DeliveryIntent, error) {
	if limit <= 0 {
		limit = DefaultIntentPageSize
	}
	return s.repo.DueIntents(ctx, kind, s.clock.Now(), limit)
}

// RecordOutcome applies one send's result: DELIVERED on success, another attempt (or
// DEAD_LETTER once they run out) on failure. Either way an attempt row is appended, so the
// history is complete whichever way the send went.
//
// It RETURNS the updated intent because the caller's copy is now stale, and the caller is
// the worker that has to say what happened. Taking the intent by value and discarding the
// result would leave the worker logging the pre-attempt state — so a dead letter would be
// announced as an ordinary retry, which is exactly the line an operator is watching for.
func (s *DeliveryIntentService) RecordOutcome(ctx context.Context, intent domain.DeliveryIntent, sendErr error) (domain.DeliveryIntent, error) {
	now := s.clock.Now()
	var (
		attempt domain.DeliveryAttempt
		ok      bool
	)
	if sendErr != nil {
		attempt, ok = intent.RecordFailure(sendErr.Error(), now, s.cfg.Backoff)
	} else {
		attempt, ok = intent.RecordSuccess(now)
	}
	if !ok {
		return intent, nil // already DELIVERED — a duplicate outcome is not a second attempt
	}
	if err := s.repo.RecordAttempt(ctx, intent, attempt); err != nil {
		return intent, err
	}
	return intent, nil
}

// GetIntent returns one intent with its full attempt history — the operator's view of what
// Themis tried and what the other side said.
func (s *DeliveryIntentService) GetIntent(ctx context.Context, id string) (domain.DeliveryIntent, []domain.DeliveryAttempt, error) {
	intent, err := s.repo.GetIntent(ctx, id)
	if err != nil {
		return domain.DeliveryIntent{}, nil, err
	}
	attempts, err := s.repo.IntentAttempts(ctx, id)
	if err != nil {
		return domain.DeliveryIntent{}, nil, err
	}
	return intent, attempts, nil
}

// ListIntents returns the filtered intent list, clamping the page size so an operator query
// cannot pull the whole table.
//
// The clamp is a FLOOR under every caller, not the place the HTTP default lives: a non-positive
// limit from any ring becomes the default page size here, so no caller can turn a list into
// `LIMIT 0` — an empty page that reads exactly like "there are no failures". The HTTP adapter
// applies the same default at the edge as well, because that is where the OpenAPI declares it;
// both read it from DefaultIntentPageSize, so the two cannot drift.
func (s *DeliveryIntentService) ListIntents(ctx context.Context, filter IntentFilter) ([]domain.DeliveryIntent, error) {
	if filter.Limit <= 0 {
		filter.Limit = DefaultIntentPageSize
	}
	if filter.Limit > MaxIntentPageSize {
		filter.Limit = MaxIntentPageSize
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	return s.repo.ListIntents(ctx, filter)
}

// RetryIntent re-opens a dead-lettered or cancelled intent for the workers. The attempt
// history is kept: a retry adds to the record of what was tried, it does not rewrite it.
func (s *DeliveryIntentService) RetryIntent(ctx context.Context, id string) (domain.DeliveryIntent, error) {
	intent, err := s.repo.GetIntent(ctx, id)
	if err != nil {
		return domain.DeliveryIntent{}, err
	}
	if err := intent.Retry(s.clock.Now()); err != nil {
		return domain.DeliveryIntent{}, err
	}
	if err := s.repo.SaveIntentState(ctx, intent); err != nil {
		return domain.DeliveryIntent{}, err
	}
	return intent, nil
}

// CancelIntent withdraws a pending intent. The record survives as the statement that a human
// decided this outward action should not happen.
func (s *DeliveryIntentService) CancelIntent(ctx context.Context, id string) (domain.DeliveryIntent, error) {
	intent, err := s.repo.GetIntent(ctx, id)
	if err != nil {
		return domain.DeliveryIntent{}, err
	}
	if err := intent.Cancel(s.clock.Now()); err != nil {
		return domain.DeliveryIntent{}, err
	}
	if err := s.repo.SaveIntentState(ctx, intent); err != nil {
		return domain.DeliveryIntent{}, err
	}
	return intent, nil
}

// IntentCounts returns the per-status totals for the startup log and the operator report.
func (s *DeliveryIntentService) IntentCounts(ctx context.Context) (map[domain.IntentStatus]int, error) {
	return s.repo.CountIntentsByStatus(ctx)
}
