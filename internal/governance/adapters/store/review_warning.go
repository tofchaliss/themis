package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The review-warning store (EDR-REMEDIATION-01 D2): which current decisions are near their
// review-by date, and the once-per-version record of having said so.

var _ app.ReviewWarnings = (*Store)(nil)

// ReviewsDueSoon lists Findings whose CURRENT Position is an acceptance or a not_affected with a
// review-by date in (now, until], not yet warned for that version and not already re-surfaced.
// Nearest date first, bounded by limit.
func (s *Store) ReviewsDueSoon(ctx context.Context, now, until time.Time, limit int) ([]domain.FindingID, error) {
	rows, err := s.querier(ctx).Query(ctx, `
		SELECT f.id
		FROM findings f
		JOIN finding_positions po ON po.finding_id = f.id AND po.version = f.current_position_version
		LEFT JOIN review_warnings w ON w.finding_id = f.id AND w.position_version = po.version
		WHERE f.current_stance IN ('accepted_risk', 'deferred', 'not_affected')
		  AND f.stale_since IS NULL
		  AND po.review_by > $1 AND po.review_by <= $2
		  AND w.finding_id IS NULL
		ORDER BY po.review_by, f.id
		LIMIT $3`, now, until, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.FindingID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, domain.FindingID(id))
	}
	return out, rows.Err()
}

// RecordReviewWarning writes the warning for (Finding, Position version) and its outbox note in
// one transaction, once: false when that version was already warned.
func (s *Store) RecordReviewWarning(ctx context.Context, id domain.FindingID, positionVersion int, reviewBy time.Time, note app.OutboxNote) (bool, error) {
	payload, err := json.Marshal(note.Event)
	if err != nil {
		return false, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ct, err := tx.Exec(ctx, `
		INSERT INTO review_warnings (finding_id, position_version, review_by, recorded_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (finding_id, position_version) DO NOTHING`,
		string(id), positionVersion, reviewBy, note.OccurredAt)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		return false, nil
	}
	if err := insertNote(ctx, tx, string(id), note, payload); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}
