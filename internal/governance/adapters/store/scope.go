package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The scoped-decision queue (EDR-SYNC-01 D4). The Position row is the queue row: a directly
// taken Position with a propagating scope is pending until the sweep stamps scope_applied_at.
// Both methods are plain reads/writes of finding_positions; the partial index keeps the pending
// scan cheap however many Positions the estate holds.

// PendingScopedPositions lists up to limit unapplied, directly taken scoped decisions, oldest
// first. A propagated Position is born applied and never listed.
func (s *Store) PendingScopedPositions(ctx context.Context, limit int) ([]app.ScopedPosition, error) {
	rows, err := s.querier(ctx).Query(ctx, `
		SELECT finding_id, version FROM finding_positions
		WHERE scope IN ('project', 'product') AND scope_applied_at IS NULL AND propagated_from_finding = ''
		ORDER BY established_at, finding_id, version LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.ScopedPosition
	for rows.Next() {
		var (
			id      string
			version int
		)
		if err := rows.Scan(&id, &version); err != nil {
			return nil, err
		}
		out = append(out, app.ScopedPosition{FindingID: domain.FindingID(id), Version: version})
	}
	return out, rows.Err()
}

// MarkScopeApplied stamps the row; an already stamped or unknown row is left as it is.
func (s *Store) MarkScopeApplied(ctx context.Context, findingID domain.FindingID, version int) error {
	_, err := s.exec(ctx).Exec(ctx, `
		UPDATE finding_positions SET scope_applied_at = $3
		WHERE finding_id = $1 AND version = $2 AND scope_applied_at IS NULL`,
		string(findingID), version, time.Now().UTC())
	return err
}
