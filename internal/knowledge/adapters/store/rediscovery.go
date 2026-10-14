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

// TouchScannerRelease gives a scanner-only release a ledger row — no evidence id, since there is
// no SBOM to re-read — only when none exists, so an SBOM's row is never overwritten (KN-SCAN-5).
// Implements app.ScannerReleaseLedger.
func (s *Store) TouchScannerRelease(ctx context.Context, releaseID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO correlated_releases (release_id, evidence_id, last_discovered_at)
		VALUES ($1, '', $2)
		ON CONFLICT (release_id) DO NOTHING`, releaseID, at)
	return err
}

// StampDiscovered moves a release's last_discovered_at after a sweep step that is not an SBOM
// correlation (the scanner-only re-discovery), so it does not read as eternally stale.
func (s *Store) StampDiscovered(ctx context.Context, releaseID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE correlated_releases SET last_discovered_at = $2 WHERE release_id = $1`, releaseID, at)
	return err
}

// BackfillScannerReleases gives every release that has matches but no ledger row a row with no
// evidence id, dated old enough to be swept next (KN-SCAN-5b, 2026-10-14). TouchScannerRelease
// runs on a NEW ingest only, so the scanner-only releases an estate already held when KN-SCAN-5
// landed never joined the sweep. Additive and idempotent: existing rows are untouched.
// Implements app.ScannerReleaseLedger.
func (s *Store) BackfillScannerReleases(ctx context.Context, at time.Time) (int, error) {
	ct, err := s.pool.Exec(ctx, `
		INSERT INTO correlated_releases (release_id, evidence_id, last_discovered_at)
		SELECT DISTINCT m.release_id, '', $1::timestamptz
		  FROM faultline_matches m
		 WHERE NOT EXISTS (SELECT 1 FROM correlated_releases c WHERE c.release_id = m.release_id)`, at)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}
