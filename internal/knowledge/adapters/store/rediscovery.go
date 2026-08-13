package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// UpsertCorrelatedRelease records that discovery ran for a release against the given evidence
// (KN-RECOR-1). Called from inside ApplyCorrelation's unit of work, so it joins the inbox
// transaction when one rides the context — the ledger entry and the matches it accounts for
// commit or roll back together.
func (s *Store) UpsertCorrelatedRelease(ctx context.Context, releaseID, evidenceID string, at time.Time) error {
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO correlated_releases (release_id, evidence_id, last_discovered_at)
		VALUES ($1, $2, $3)
		ON CONFLICT (release_id)
		DO UPDATE SET evidence_id = EXCLUDED.evidence_id,
		              last_discovered_at = EXCLUDED.last_discovered_at`,
		releaseID, evidenceID, at); err != nil {
		return err
	}
	if own {
		return tx.Commit(ctx)
	}
	return nil
}

// StaleReleases returns up to limit releases whose last discovery is older than olderThan,
// stalest first — the re-discovery sweep's queue. A release re-correlated by any path (a new
// upload, a previous sweep) leaves the queue until it ages again.
func (s *Store) StaleReleases(ctx context.Context, olderThan time.Time, limit int) ([]app.CorrelatedRelease, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT release_id, evidence_id FROM correlated_releases
		WHERE last_discovered_at < $1
		ORDER BY last_discovered_at ASC
		LIMIT $2`, olderThan, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.CorrelatedRelease
	for rows.Next() {
		var r app.CorrelatedRelease
		if err := rows.Scan(&r.ReleaseID, &r.EvidenceID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
