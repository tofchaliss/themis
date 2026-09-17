package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Component retirement (KN-SCAN-4(b)).

// DuplicateIdentityRows lists occurrences whose recorded identity is not a usable purl AND whose
// canonical twin is already recorded on the same (release, card) — the measured shape: a scanner
// report named a component under a raw string while the SBOM path had already recorded the same
// component properly.
//
// The name+version join is what makes this a DEDUPLICATION rather than a guess: it lists a row
// only when the same component demonstrably already has an identified row beside it. A raw row
// with no such twin is NOT listed — it may be the only record of something real, and retiring it
// would delete evidence rather than a duplicate.
//
// Retired rows are excluded, so the sweep converges. Implements app.DuplicateIdentitySource.
func (s *Store) DuplicateIdentityRows(ctx context.Context, limit int) ([]app.DuplicateIdentityRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT raw.release_id, raw.faultline_id, f.cve, raw.component_purl
		FROM faultline_matches raw
		JOIN faultlines f ON f.id = raw.faultline_id
		WHERE raw.component_purl NOT LIKE 'pkg:%'
		  AND raw.retired_at IS NULL
		  AND EXISTS (
		    SELECT 1 FROM faultline_matches good
		    WHERE good.release_id = raw.release_id
		      AND good.faultline_id = raw.faultline_id
		      AND good.component_purl LIKE 'pkg:%'
		      AND good.retired_at IS NULL
		      AND lower(good.component_name) = lower(raw.component_name)
		      AND good.component_version = raw.component_version)
		ORDER BY raw.release_id, raw.faultline_id, raw.component_purl
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.DuplicateIdentityRow
	for rows.Next() {
		var r app.DuplicateIdentityRow
		var fid string
		if err := rows.Scan(&r.ReleaseID, &fid, &r.CVE, &r.PURL); err != nil {
			return nil, err
		}
		r.FaultlineID = domain.FaultlineID(fid)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RetireMatch marks one occurrence retired and queues its retirement event in ONE transaction.
//
// Atomicity is the point, and it is the same lesson the re-classification stamp learned: a row
// marked retired with no event emitted would leave Governance showing the duplicate forever,
// with nothing left to re-drive it — the sweep would have "succeeded" and fixed nothing.
//
// Idempotent: the UPDATE is guarded on `retired_at IS NULL`, so a re-run touches no row and
// queues no second event. A row already retired is a no-op, reported as created=false.
// Implements app.MatchRetirer.
func (s *Store) RetireMatch(ctx context.Context, r app.DuplicateIdentityRow, at time.Time, event any) (bool, error) {
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return false, err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}
	ct, err := tx.Exec(ctx, `
		UPDATE faultline_matches SET retired_at = $4
		WHERE release_id=$1 AND faultline_id=$2 AND component_purl=$3 AND retired_at IS NULL`,
		r.ReleaseID, string(r.FaultlineID), r.PURL, at.UTC())
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		if own {
			return false, tx.Commit(ctx)
		}
		return false, nil // already retired — no event, no second assertion
	}
	if qerr := s.queueOutbox(ctx, tx, app.EventComponentRetired, string(r.FaultlineID), event, at); qerr != nil {
		return false, qerr
	}
	if own {
		return true, tx.Commit(ctx)
	}
	return true, nil
}
