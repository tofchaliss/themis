package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/communication/app"
)

// The Store is the delivery-intent port's one implementation; asserted here so a port change
// fails the build in this package rather than at a composition root.
var _ app.DeliveryIntents = (*Store)(nil)

// querier is the read+write surface shared by *pgxpool.Pool and pgx.Tx. The intent writes
// need QueryRow (the idempotent insert RETURNS the stored row), which the Exec-only execer
// cannot give them.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// q returns the ambient inbox transaction when one rides the context — so an intent written
// by the inbound reader commits atomically with the envelope claim (EB-06) — else the pool.
func (s *Store) q(ctx context.Context) querier {
	if tx, ok := txFromCtx(ctx); ok {
		return tx
	}
	return s.pool
}

const intentColumns = `id, created_at, updated_at, type, destination, state, attempts,
	next_attempt_at, last_attempt_at, last_error, result, payload_sha256, payload_bytes,
	snapshot, lineage, origin_event_id, product_id, project_id, release_id, finding_id, proposal_id`

// CreateIntent persists the intent and returns it as stored. It is IDEMPOTENT on the
// originating event id: the partial unique index makes a replay of the same envelope conflict,
// the conflict does nothing, and the already-stored intent is returned — so an at-least-once
// redelivery yields one ticket and one mail, not two. An intent with no originating event
// (worker-sourced) stores NULL and takes part in no uniqueness.
func (s *Store) CreateIntent(ctx context.Context, in app.Intent) (app.Intent, error) {
	row := s.q(ctx).QueryRow(ctx, `
		INSERT INTO delivery_intents (`+intentColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		ON CONFLICT (origin_event_id) WHERE origin_event_id IS NOT NULL DO NOTHING
		RETURNING `+intentColumns,
		in.ID, in.CreatedAt, in.UpdatedAt, string(in.Type), in.Destination, string(in.State), in.Attempts,
		in.NextAttemptAt, nullTime(in.LastAttemptAt), in.LastError, jsonMap(in.Result), in.PayloadSHA256, payloadOrEmpty(in.PayloadBytes),
		jsonMap(in.Snapshot), jsonValue(in.Lineage), nullString(in.OriginEventID),
		in.ProductID, in.ProjectID, in.ReleaseID, in.FindingID, in.ProposalID)

	stored, err := scanIntent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// The event is already recorded — return what is there, which is the whole point of
		// keying idempotence on the event id rather than on the intent's own fields.
		return s.intentByOriginEvent(ctx, in.OriginEventID)
	}
	if err != nil {
		return app.Intent{}, err
	}
	return stored, nil
}

func (s *Store) intentByOriginEvent(ctx context.Context, originEventID string) (app.Intent, error) {
	row := s.q(ctx).QueryRow(ctx,
		`SELECT `+intentColumns+` FROM delivery_intents WHERE origin_event_id=$1`, originEventID)
	in, err := scanIntent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.Intent{}, app.ErrIntentNotFound
	}
	if err != nil {
		return app.Intent{}, err
	}
	return in, nil
}

// GetIntent loads one intent by id, or app.ErrIntentNotFound.
func (s *Store) GetIntent(ctx context.Context, id string) (app.Intent, error) {
	row := s.q(ctx).QueryRow(ctx, `SELECT `+intentColumns+` FROM delivery_intents WHERE id=$1`, id)
	in, err := scanIntent(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.Intent{}, app.ErrIntentNotFound
	}
	if err != nil {
		return app.Intent{}, err
	}
	return in, nil
}

// GetPendingForWork returns pending intents due at or before now, oldest-due first and
// fewest-attempts first, up to limit.
func (s *Store) GetPendingForWork(ctx context.Context, now time.Time, limit int) ([]app.Intent, error) {
	rows, err := s.q(ctx).Query(ctx, `SELECT `+intentColumns+`
		FROM delivery_intents
		WHERE state='pending' AND next_attempt_at <= $1
		ORDER BY next_attempt_at, attempts, id LIMIT $2`, now, limit)
	if err != nil {
		return nil, err
	}
	return collectIntents(rows)
}

// ListDeadLetters returns dead-lettered intents updated at or after since, newest first — the
// operator's queue (deliveryctl list-deadletters).
func (s *Store) ListDeadLetters(ctx context.Context, since time.Time, limit int) ([]app.Intent, error) {
	rows, err := s.q(ctx).Query(ctx, `SELECT `+intentColumns+`
		FROM delivery_intents
		WHERE state='dead_letter' AND updated_at >= $1
		ORDER BY updated_at DESC, id LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	return collectIntents(rows)
}

// RecordAttempt appends the append-only attempt row and advances the intent's counters
// (attempts, last_attempt_at, last_error, next_attempt_at). It does NOT change state: the
// transition is owned by MarkDelivered / MarkDeadLetter / CancelIntent / RetryIntent, so
// exactly one call is answerable for where an intent ended up.
func (s *Store) RecordAttempt(ctx context.Context, a app.Attempt) error {
	q := s.q(ctx)
	if _, err := q.Exec(ctx, `
		INSERT INTO delivery_attempts (intent_id, attempt_no, attempted_at, outcome, status_code, response_excerpt, error)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.IntentID, a.AttemptNo, a.At, string(a.Outcome), nullInt(a.StatusCode), a.ResponseExcerpt, a.Error); err != nil {
		return err
	}
	ct, err := q.Exec(ctx, `
		UPDATE delivery_intents
		SET attempts=$1, last_attempt_at=$2, last_error=$3, next_attempt_at=$4, updated_at=$2
		WHERE id=$5`,
		a.AttemptNo, a.At, a.Error, a.NextAttemptAt, a.IntentID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return app.ErrIntentNotFound
	}
	return nil
}

// MarkDelivered moves the intent to `delivered` and records the outcome metadata. It is
// guarded on the pending state so a concurrent cancel is not overwritten.
func (s *Store) MarkDelivered(ctx context.Context, id string, result map[string]string) error {
	return s.transition(ctx, `
		UPDATE delivery_intents SET state='delivered', result=$1, last_error='', updated_at=now()
		WHERE id=$2 AND state='pending'`, jsonMap(result), id)
}

// MarkDeadLetter moves the intent to `dead_letter` with the error that exhausted it.
func (s *Store) MarkDeadLetter(ctx context.Context, id, lastError string) error {
	return s.transition(ctx, `
		UPDATE delivery_intents SET state='dead_letter', last_error=$1, updated_at=now()
		WHERE id=$2 AND state='pending'`, lastError, id)
}

// CancelIntent moves a not-yet-delivered intent to `cancelled` (operator). A delivered intent
// cannot be cancelled — the mail has gone.
func (s *Store) CancelIntent(ctx context.Context, id string) error {
	return s.transition(ctx, `
		UPDATE delivery_intents SET state='cancelled', updated_at=now()
		WHERE id=$1 AND state <> 'delivered'`, id)
}

// RetryIntent resets an intent to pending with a clean slate — attempts 0, no last error, due
// now (operator). The attempt ledger is untouched: the counter answers "may we try again",
// the ledger answers "what happened", and a retry must not erase the second.
func (s *Store) RetryIntent(ctx context.Context, id string) error {
	return s.transition(ctx, `
		UPDATE delivery_intents
		SET state='pending', attempts=0, last_error='', next_attempt_at=now(), updated_at=now()
		WHERE id=$1 AND state <> 'delivered'`, id)
}

// transition runs a guarded state update; zero rows means the id is unknown or the guard
// refused, and the operator is told rather than seeing a silent success.
func (s *Store) transition(ctx context.Context, sql string, args ...any) error {
	ct, err := s.q(ctx).Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return app.ErrIntentNotFound
	}
	return nil
}

func collectIntents(rows pgx.Rows) ([]app.Intent, error) {
	defer rows.Close()
	var out []app.Intent
	for rows.Next() {
		in, err := scanIntent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

func scanIntent(r row) (app.Intent, error) {
	var (
		in                                 app.Intent
		typ, state                         string
		lastAttemptAt                      *time.Time
		originEventID                      *string
		resultRaw, snapshotRaw, lineageRaw []byte
	)
	if err := r.Scan(&in.ID, &in.CreatedAt, &in.UpdatedAt, &typ, &in.Destination, &state, &in.Attempts,
		&in.NextAttemptAt, &lastAttemptAt, &in.LastError, &resultRaw, &in.PayloadSHA256, &in.PayloadBytes,
		&snapshotRaw, &lineageRaw, &originEventID,
		&in.ProductID, &in.ProjectID, &in.ReleaseID, &in.FindingID, &in.ProposalID); err != nil {
		return app.Intent{}, err
	}
	in.Type, in.State = app.IntentType(typ), app.IntentState(state)
	if lastAttemptAt != nil {
		in.LastAttemptAt = *lastAttemptAt
	}
	if originEventID != nil {
		in.OriginEventID = *originEventID
	}
	in.Result = stringMapFrom(resultRaw)
	in.Snapshot = stringMapFrom(snapshotRaw)
	in.Lineage = lineageFrom(lineageRaw)
	return in, nil
}

// stringMapFrom decodes a stored jsonb string map. Anything unreadable degrades to empty
// rather than failing the read: an intent whose snapshot cannot be parsed is still a record of
// something that had to go out, and it must stay visible to an operator.
func stringMapFrom(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]string{}
	}
	return out
}

func lineageFrom(raw []byte) app.IntentLineage {
	var l app.IntentLineage
	if len(raw) == 0 {
		return l
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return app.IntentLineage{}
	}
	return l
}

// jsonMap renders a string map for a jsonb column; a nil map is stored as {} so the column's
// NOT NULL holds and readers never special-case absence.
func jsonMap(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}" // unreachable for map[string]string
	}
	return string(b)
}

func jsonValue(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}" // unreachable for the lineage struct
	}
	return string(b)
}

func payloadOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullInt(n int) *int {
	if n == 0 {
		return nil
	}
	return &n
}
