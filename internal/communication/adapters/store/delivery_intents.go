package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// intentColumns is the delivery_intents projection, in the order scanIntent reads it.
const intentColumns = `id, kind, destination, status, attempts, max_attempts, last_error,
	origin_event_id, origin_event_type, origin_event_time, finding_id, release_id, product_id,
	position_version, snapshot, payload_bytes, payload_hash, next_attempt_at, created_at, updated_at`

// SaveIntent records a new delivery intent, or reports created=false when one already exists
// for the same (origin event, event type, kind, destination). The dedup is the UNIQUE index,
// not a prior SELECT: two readers draining the same replayed envelope concurrently would both
// see "absent" and both insert, and only the index can refuse the second one.
//
// It joins the inbox unit of work when one rides the context (EB-06), so the intent commits
// atomically with the envelope claim — the recording half of N-M1a is INSIDE the reader's
// transaction, and only the recording half.
func (s *Store) SaveIntent(ctx context.Context, in domain.DeliveryIntent) (bool, error) {
	o := in.Origin()
	ct, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO delivery_intents (`+intentColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT (origin_event_id, origin_event_type, kind, destination) DO NOTHING`,
		in.ID(), string(in.Kind()), in.Destination(), string(in.Status()), in.Attempts(), in.MaxAttempts(), in.LastError(),
		o.EventID, o.EventType, o.EventTime, o.FindingID, o.ReleaseID, o.ProductID,
		o.PositionVersion, string(in.Snapshot()), in.Payload(), in.PayloadHash(),
		in.NextAttemptAt(), in.CreatedAt(), in.UpdatedAt())
	if err != nil {
		return false, err
	}
	return ct.RowsAffected() == 1, nil
}

// DueIntents returns PENDING intents of one kind whose backoff has elapsed, oldest first.
// Scoping by kind is what isolates the channels from each other: a Jira outage fills the jira
// worker's queue and leaves the mail worker's untouched.
func (s *Store) DueIntents(ctx context.Context, kind domain.DeliveryKind, now time.Time, limit int) ([]domain.DeliveryIntent, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+intentColumns+`
		FROM delivery_intents
		WHERE kind=$1 AND status=$2 AND next_attempt_at <= $3
		ORDER BY created_at, id LIMIT $4`,
		string(kind), string(domain.IntentPending), now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectIntents(rows)
}

// RecordAttempt persists the intent's new state and appends the attempt row in ONE
// transaction. Split, the two could disagree — an attempts counter with no matching history
// row is exactly the state an operator cannot reason about.
func (s *Store) RecordAttempt(ctx context.Context, in domain.DeliveryIntent, att domain.DeliveryAttempt) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE delivery_intents
		SET status=$1, attempts=$2, last_error=$3, next_attempt_at=$4, updated_at=$5
		WHERE id=$6`,
		string(in.Status()), in.Attempts(), in.LastError(), in.NextAttemptAt(), in.UpdatedAt(), in.ID()); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO delivery_attempts (intent_id, attempt_no, ok, error, attempted_at)
		VALUES ($1,$2,$3,$4,$5)`,
		in.ID(), att.AttemptNo, att.OK, att.Error, att.At); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SaveIntentState persists an operator-driven transition (retry / cancel). No attempt row is
// written because nothing was tried.
func (s *Store) SaveIntentState(ctx context.Context, in domain.DeliveryIntent) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE delivery_intents
		SET status=$1, attempts=$2, last_error=$3, next_attempt_at=$4, updated_at=$5
		WHERE id=$6`,
		string(in.Status()), in.Attempts(), in.LastError(), in.NextAttemptAt(), in.UpdatedAt(), in.ID())
	return err
}

// GetIntent loads one intent; app.ErrIntentNotFound when it does not exist.
func (s *Store) GetIntent(ctx context.Context, id string) (domain.DeliveryIntent, error) {
	in, err := scanIntent(s.pool.QueryRow(ctx, `SELECT `+intentColumns+` FROM delivery_intents WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.DeliveryIntent{}, app.ErrIntentNotFound
	}
	return in, err
}

// IntentAttempts returns one intent's send history, oldest first.
func (s *Store) IntentAttempts(ctx context.Context, id string) ([]domain.DeliveryAttempt, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT attempt_no, ok, error, attempted_at
		FROM delivery_attempts WHERE intent_id=$1 ORDER BY attempt_no, id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.DeliveryAttempt
	for rows.Next() {
		var a domain.DeliveryAttempt
		if err := rows.Scan(&a.AttemptNo, &a.OK, &a.Error, &a.At); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListIntents returns intents matching the filter, newest first. An empty status or kind
// means "any" — expressed as a NULL-or-match predicate so one statement serves every
// combination rather than four hand-built ones that can drift.
func (s *Store) ListIntents(ctx context.Context, f app.IntentFilter) ([]domain.DeliveryIntent, error) {
	var status, kind *string
	if f.Status != "" {
		v := string(f.Status)
		status = &v
	}
	if f.Kind != "" {
		v := string(f.Kind)
		kind = &v
	}
	rows, err := s.pool.Query(ctx, `SELECT `+intentColumns+`
		FROM delivery_intents
		WHERE ($1::text IS NULL OR status = $1) AND ($2::text IS NULL OR kind = $2)
		ORDER BY created_at DESC, id DESC
		LIMIT $3 OFFSET $4`, status, kind, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectIntents(rows)
}

// CountIntentsByStatus returns the per-status totals (the startup log + vm-verify line).
func (s *Store) CountIntentsByStatus(ctx context.Context) (map[domain.IntentStatus]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT status, count(*) FROM delivery_intents GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[domain.IntentStatus]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[domain.IntentStatus(status)] = n
	}
	return out, rows.Err()
}

func collectIntents(rows pgx.Rows) ([]domain.DeliveryIntent, error) {
	var out []domain.DeliveryIntent
	for rows.Next() {
		in, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func scanIntent(r row) (domain.DeliveryIntent, error) {
	var (
		id, kind, destination, status       string
		attempts, maxAttempts               int
		lastError                           string
		originEventID, originEventType      string
		originEventTime                     time.Time
		findingID, releaseID, productID     string
		positionVersion                     int
		snapshot, payload                   []byte
		payloadHash                         string
		nextAttemptAt, createdAt, updatedAt time.Time
	)
	if err := r.Scan(&id, &kind, &destination, &status, &attempts, &maxAttempts, &lastError,
		&originEventID, &originEventType, &originEventTime, &findingID, &releaseID, &productID,
		&positionVersion, &snapshot, &payload, &payloadHash,
		&nextAttemptAt, &createdAt, &updatedAt); err != nil {
		return domain.DeliveryIntent{}, err
	}
	// The columns are the QUERYABLE projection of the lineage; the snapshot is its whole
	// truth (it also carries the faultline, the CVE and the proposal). Read the snapshot,
	// and fall back to the columns if it is unreadable — a record whose JSON went bad is
	// still a real historical intent and must stay retrievable, exactly as a Publication
	// with corrupt components does.
	origin, err := domain.UnmarshalDeliverySnapshot(snapshot)
	if err != nil || origin.EventID == "" {
		origin = domain.DeliveryOrigin{}
	}
	origin.EventID, origin.EventType, origin.EventTime = originEventID, originEventType, originEventTime
	origin.FindingID, origin.ReleaseID, origin.ProductID = findingID, releaseID, productID
	origin.PositionVersion = positionVersion
	return domain.ReconstituteDeliveryIntent(id, domain.DeliveryKind(kind), destination, origin,
		snapshot, payload, payloadHash, domain.IntentStatus(status),
		attempts, maxAttempts, lastError, nextAttemptAt, createdAt, updatedAt), nil
}
