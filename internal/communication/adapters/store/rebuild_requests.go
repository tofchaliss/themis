package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
)

// Compile-time proof that the Store is the rebuild request port (EDR-REBUILD-01 R3).
var _ app.RebuildRequests = (*Store)(nil)

const requestColumns = `intent_id, cycle_id, release_id, decision_id, attempt, try, channel, state, reason, build_ref,
	execution_started_at, requested_at, delivered_at, status_at, reported_by, settled_answer, settled_by, settled_at, settle_note`

// CreateRequest stores a request once per intent id.
func (s *Store) CreateRequest(ctx context.Context, r app.RebuildRequest) error {
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO rebuild_requests (intent_id, cycle_id, release_id, decision_id, attempt, try, channel, state, requested_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (intent_id) DO NOTHING`,
		r.IntentID, r.CycleID, r.ReleaseID, r.DecisionID, r.Attempt, r.Try, r.Channel, r.State, r.RequestedAt)
	return err
}

// RequestByIntent returns one request, or app.ErrRebuildRequestNotFound.
func (s *Store) RequestByIntent(ctx context.Context, intentID string) (app.RebuildRequest, error) {
	r, err := scanRequest(s.q(ctx).QueryRow(ctx, `SELECT `+requestColumns+` FROM rebuild_requests WHERE intent_id=$1`, intentID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildRequest{}, app.ErrRebuildRequestNotFound
	}
	return r, err
}

// LatestRequest returns the newest request of a cycle: highest attempt, then highest try.
func (s *Store) LatestRequest(ctx context.Context, cycleID int64) (app.RebuildRequest, bool, error) {
	r, err := scanRequest(s.q(ctx).QueryRow(ctx, `SELECT `+requestColumns+` FROM rebuild_requests
		WHERE cycle_id=$1 ORDER BY attempt DESC, try DESC LIMIT 1`, cycleID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildRequest{}, false, nil
	}
	return r, err == nil, err
}

// ListRequests returns a cycle's requests, oldest first.
func (s *Store) ListRequests(ctx context.Context, cycleID int64) ([]app.RebuildRequest, error) {
	return s.queryRequests(ctx, `SELECT `+requestColumns+` FROM rebuild_requests WHERE cycle_id=$1 ORDER BY attempt, try`, cycleID)
}

// SilentRequests returns webhook requests that are still `delivered` since before the time
// given: the connector made no status call and no build was reported (D28 item 3).
func (s *Store) SilentRequests(ctx context.Context, before time.Time) ([]app.RebuildRequest, error) {
	return s.queryRequests(ctx, `SELECT `+requestColumns+` FROM rebuild_requests
		WHERE state='delivered' AND channel='webhook' AND delivered_at < $1 ORDER BY delivered_at`, before)
}

func (s *Store) queryRequests(ctx context.Context, sql string, args ...any) ([]app.RebuildRequest, error) {
	rows, err := s.q(ctx).Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []app.RebuildRequest{}
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRequest persists what can change on a request.
func (s *Store) UpdateRequest(ctx context.Context, r app.RebuildRequest) error {
	_, err := s.q(ctx).Exec(ctx, `
		UPDATE rebuild_requests SET state=$2, reason=$3, build_ref=$4, execution_started_at=$5, delivered_at=$6,
			status_at=$7, reported_by=$8, settled_answer=$9, settled_by=$10, settled_at=$11, settle_note=$12
		WHERE intent_id=$1`,
		r.IntentID, r.State, r.Reason, r.BuildRef, nullTime(r.ExecutionStartedAt), nullTime(r.DeliveredAt),
		nullTime(r.StatusAt), r.ReportedBy, r.SettledAnswer, r.SettledBy, nullTime(r.SettledAt), r.SettleNote)
	return err
}

// LastDeliveredAt is when a request of the Release was last delivered (D14).
func (s *Store) LastDeliveredAt(ctx context.Context, releaseID string) (time.Time, bool, error) {
	var at *time.Time
	if err := s.q(ctx).QueryRow(ctx, `SELECT max(delivered_at) FROM rebuild_requests WHERE release_id=$1`, releaseID).Scan(&at); err != nil {
		return time.Time{}, false, err
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return at.UTC(), true, nil
}

// SaveHold records why the Release's last decision opened no cycle; one row per Release.
func (s *Store) SaveHold(ctx context.Context, h app.RebuildHold) error {
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO rebuild_holds (release_id, decision_id, reason, held_until, recorded_at) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (release_id) DO UPDATE SET decision_id=EXCLUDED.decision_id, reason=EXCLUDED.reason,
			held_until=EXCLUDED.held_until, recorded_at=EXCLUDED.recorded_at`,
		h.ReleaseID, h.DecisionID, h.Reason, nullTime(h.Until), h.RecordedAt)
	return err
}

// ClearHold removes the Release's hold.
func (s *Store) ClearHold(ctx context.Context, releaseID string) error {
	_, err := s.q(ctx).Exec(ctx, `DELETE FROM rebuild_holds WHERE release_id=$1`, releaseID)
	return err
}

// Hold returns the Release's hold, found=false when it has none.
func (s *Store) Hold(ctx context.Context, releaseID string) (app.RebuildHold, bool, error) {
	var (
		h     app.RebuildHold
		until *time.Time
	)
	err := s.q(ctx).QueryRow(ctx, `SELECT release_id, decision_id, reason, held_until, recorded_at FROM rebuild_holds WHERE release_id=$1`, releaseID).
		Scan(&h.ReleaseID, &h.DecisionID, &h.Reason, &until, &h.RecordedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildHold{}, false, nil
	}
	if err != nil {
		return app.RebuildHold{}, false, err
	}
	h.Until, h.RecordedAt = timeOf(until), h.RecordedAt.UTC()
	return h, true, nil
}

// SaveLastSBOM records the SBOM evaluated last for a Release.
func (s *Store) SaveLastSBOM(ctx context.Context, releaseID, sbomID string, at time.Time) error {
	_, err := s.q(ctx).Exec(ctx, `
		INSERT INTO release_last_sbom (release_id, sbom_id, evaluated_at) VALUES ($1,$2,$3)
		ON CONFLICT (release_id) DO UPDATE SET sbom_id=EXCLUDED.sbom_id, evaluated_at=EXCLUDED.evaluated_at`,
		releaseID, sbomID, at)
	return err
}

// LastSBOM returns the SBOM evaluated last for a Release, "" when none is on record.
func (s *Store) LastSBOM(ctx context.Context, releaseID string) (string, error) {
	var id string
	err := s.q(ctx).QueryRow(ctx, `SELECT sbom_id FROM release_last_sbom WHERE release_id=$1`, releaseID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func scanRequest(row pgx.Row) (app.RebuildRequest, error) {
	var (
		r                                       app.RebuildRequest
		started, delivered, statusAt, settledAt *time.Time
	)
	err := row.Scan(&r.IntentID, &r.CycleID, &r.ReleaseID, &r.DecisionID, &r.Attempt, &r.Try, &r.Channel, &r.State, &r.Reason, &r.BuildRef,
		&started, &r.RequestedAt, &delivered, &statusAt, &r.ReportedBy, &r.SettledAnswer, &r.SettledBy, &settledAt, &r.SettleNote)
	r.ExecutionStartedAt, r.DeliveredAt, r.StatusAt, r.SettledAt = timeOf(started), timeOf(delivered), timeOf(statusAt), timeOf(settledAt)
	r.RequestedAt = r.RequestedAt.UTC()
	return r, err
}

func timeOf(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}
