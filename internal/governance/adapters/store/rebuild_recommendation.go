package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild recommendations (EDR-REBUILD-01 step R4). They are the rows of rebuild_decisions
// with outcome 'recommend'; migrations/000032_rebuild_recommendations.up.sql gives them a state.

var _ app.RebuildApprovalStore = (*Store)(nil)

const rebuildRecommendationColumns = `facts, state, COALESCE(state_at, decided_at), superseded_by, approval, cycle_closed_at IS NOT NULL`

func scanRebuildRecommendation(row pgx.Row) (app.RebuildRecommendation, error) {
	var (
		rec             app.RebuildRecommendation
		facts, approval []byte
	)
	if err := row.Scan(&facts, &rec.State, &rec.StateAt, &rec.SupersededBy, &approval, &rec.CycleClosed); err != nil {
		return app.RebuildRecommendation{}, err
	}
	rec.StateAt = rec.StateAt.UTC()
	if err := json.Unmarshal(facts, &rec.Decision); err != nil {
		return app.RebuildRecommendation{}, err
	}
	if approval != nil {
		rec.Approval = &domain.RebuildApproval{}
		if err := json.Unmarshal(approval, rec.Approval); err != nil {
			return app.RebuildRecommendation{}, err
		}
	}
	return rec, nil
}

// oneRebuildRecommendation reads at most one recommendation.
func (s *Store) oneRebuildRecommendation(ctx context.Context, where string, args ...any) (app.RebuildRecommendation, bool, error) {
	rec, err := scanRebuildRecommendation(s.pool.QueryRow(ctx,
		`SELECT `+rebuildRecommendationColumns+` FROM rebuild_decisions WHERE outcome = 'recommend' AND `+where, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildRecommendation{}, false, nil
	}
	return rec, err == nil, err
}

// RebuildRecommendation reads one recommendation by its decision id.
func (s *Store) RebuildRecommendation(ctx context.Context, decisionID string) (app.RebuildRecommendation, bool, error) {
	return s.oneRebuildRecommendation(ctx, `decision_id = $1`, decisionID)
}

// LatestRebuildRecommendation reads the newest recommendation of a Release, in any state.
func (s *Store) LatestRebuildRecommendation(ctx context.Context, releaseID string) (app.RebuildRecommendation, bool, error) {
	return s.oneRebuildRecommendation(ctx, `release_id = $1 ORDER BY decided_at DESC, decision_id DESC LIMIT 1`, releaseID)
}

// RebuildRecommendationStatus reads the standing recommendation of a Release, and the newest
// approved one whose cycle is not known to be closed.
func (s *Store) RebuildRecommendationStatus(ctx context.Context, releaseID string) (app.RebuildRecommendationStatus, error) {
	var out app.RebuildRecommendationStatus
	standing, found, err := s.oneRebuildRecommendation(ctx, `release_id = $1 AND state = 'standing'`, releaseID)
	if err != nil {
		return out, err
	}
	if found {
		out.Standing = &standing
	}
	open, found, err := s.oneRebuildRecommendation(ctx,
		`release_id = $1 AND state = 'approved' AND cycle_closed_at IS NULL ORDER BY state_at DESC LIMIT 1`, releaseID)
	if err != nil {
		return out, err
	}
	if found {
		out.ApprovedOpen = &open
	}
	return out, nil
}

// StandingRebuildRecommendationsBefore lists standing recommendations decided at or before the
// given time, oldest first.
func (s *Store) StandingRebuildRecommendationsBefore(ctx context.Context, before time.Time, limit int) ([]app.RebuildRecommendation, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+rebuildRecommendationColumns+` FROM rebuild_decisions
		WHERE state = 'standing' AND decided_at <= $1 ORDER BY decided_at, decision_id LIMIT $2`, before.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.RebuildRecommendation
	for rows.Next() {
		rec, err := scanRebuildRecommendation(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// expireRebuildRecommendationTx is the one conditional move standing -> expired with its event.
func expireRebuildRecommendationTx(ctx context.Context, tx pgx.Tx, decisionID, releaseID string, at time.Time, note app.OutboxNote) (bool, error) {
	payload, err := json.Marshal(note.Event)
	if err != nil {
		return false, err
	}
	ct, err := tx.Exec(ctx, `UPDATE rebuild_decisions SET state = 'expired', state_at = $2
		WHERE decision_id = $1 AND state = 'standing'`, decisionID, at.UTC())
	if err != nil || ct.RowsAffected() == 0 {
		return false, err
	}
	return true, rebuildOutbox(ctx, tx, releaseID, note.EventType, payload, note.OccurredAt)
}

// ExpireRebuildRecommendation moves a standing recommendation to expired and appends its event,
// in one transaction. Only one caller can make the move (D46 item 1).
func (s *Store) ExpireRebuildRecommendation(ctx context.Context, decisionID string, at time.Time, note app.OutboxNote) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var releaseID string
	err = tx.QueryRow(ctx, `SELECT release_id FROM rebuild_decisions WHERE decision_id = $1`, decisionID).Scan(&releaseID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	moved, err := expireRebuildRecommendationTx(ctx, tx, decisionID, releaseID, at, note)
	if err != nil || !moved {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// rebuildPolicyGate is the advisory lock that orders approvals against policy writes: an
// approval holds it shared until it commits, every policy write takes it exclusive first (D46
// items 3 and 4). So no policy change can commit between an approval's check and its write.
const rebuildPolicyGate = `hashtextextended('rebuild_policy:approval-gate', 0)`

// rebuildPolicyVersionsTx reads the versions of the three records that can apply to a Release.
func rebuildPolicyVersionsTx(ctx context.Context, tx pgx.Tx, productID, releaseID string) (domain.RebuildPolicyVersions, error) {
	var v domain.RebuildPolicyVersions
	err := tx.QueryRow(ctx, `SELECT
		COALESCE((SELECT version FROM rebuild_policies WHERE scope_kind = 'installation' AND scope_id = ''), 0),
		COALESCE((SELECT version FROM rebuild_policies WHERE scope_kind = 'product' AND scope_id = $1), 0),
		COALESCE((SELECT version FROM rebuild_policies WHERE scope_kind = 'release' AND scope_id = $2), 0)`,
		productID, releaseID).Scan(&v.Installation, &v.Product, &v.Release)
	return v, err
}

// ApproveRebuildRecommendation is the one conditional write of an approval; see the port.
func (s *Store) ApproveRebuildRecommendation(ctx context.Context, in app.RebuildApprovalWrite) (string, error) {
	approval, err := json.Marshal(in.Approval)
	if err != nil {
		return "", err
	}
	request, err := json.Marshal(in.Request.Event)
	if err != nil {
		return "", err
	}
	d := in.Decision
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(`+rebuildPolicyGate+`)`); err != nil {
		return "", err
	}
	versions, err := rebuildPolicyVersionsTx(ctx, tx, d.ProductID, d.ReleaseID)
	if err != nil {
		return "", err
	}
	if versions != in.Expected {
		return app.RebuildApprovalWritePolicyChanged, nil
	}
	var decidedAt time.Time
	err = tx.QueryRow(ctx, `SELECT decided_at FROM rebuild_decisions
		WHERE decision_id = $1 AND state = 'standing' FOR UPDATE`, d.DecisionID).Scan(&decidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildApprovalNotStanding, nil
	}
	if err != nil {
		return "", err
	}
	result := app.RebuildApprovalApproved
	switch {
	case domain.RebuildRecommendationExpired(decidedAt, in.Now):
		// Expiry comes first, whatever the mode is (D46 item 1).
		result = app.RebuildApprovalExpired
		if _, err := expireRebuildRecommendationTx(ctx, tx, d.DecisionID, d.ReleaseID, in.Now, in.Expired); err != nil {
			return "", err
		}
	case in.Approve:
		if _, err := tx.Exec(ctx, `UPDATE rebuild_decisions SET state = 'approved', state_at = $2, approval = $3
			WHERE decision_id = $1`, d.DecisionID, in.Now.UTC(), string(approval)); err != nil {
			return "", err
		}
		if err := rebuildOutbox(ctx, tx, d.ReleaseID, in.Request.EventType, request, in.Request.OccurredAt); err != nil {
			return "", err
		}
	default:
		result = app.RebuildApprovalWithdrawn
		if _, err := tx.Exec(ctx, `UPDATE rebuild_decisions SET state = 'withdrawn', state_at = $2
			WHERE decision_id = $1`, d.DecisionID, in.Now.UTC()); err != nil {
			return "", err
		}
		if err := enqueueRebuildTrigger(ctx, tx, in.TriggerID, domain.RebuildTriggerModeChanged, d.ReleaseID); err != nil {
			return "", err
		}
	}
	return result, tx.Commit(ctx)
}
