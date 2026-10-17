package store

import (
	"context"

	"github.com/themis-project/themis/internal/knowledge/app"
)

// RecordSuspectFanout upserts one fan-out flag (KN-SANITY-1). Implements app.SanityRecorder.
func (s *Store) RecordSuspectFanout(ctx context.Context, f app.SuspectFanout) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO correlation_sanity (release_id, purl, version, ecosystem, cves, reason, flagged_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (release_id, purl) DO UPDATE
		  SET version = EXCLUDED.version, ecosystem = EXCLUDED.ecosystem, cves = EXCLUDED.cves,
		      reason = EXCLUDED.reason, flagged_at = EXCLUDED.flagged_at`,
		f.ReleaseID, f.PURL, f.Version, f.Ecosystem, f.CVEs, f.Reason, f.FlaggedAt)
	return err
}

// SuspectFanouts lists every standing flag, most CVEs first. Implements app.SanityReader.
func (s *Store) SuspectFanouts(ctx context.Context) ([]app.SuspectFanout, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT release_id, purl, version, ecosystem, cves, reason, flagged_at
		  FROM correlation_sanity ORDER BY cves DESC, purl, release_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.SuspectFanout
	for rows.Next() {
		var f app.SuspectFanout
		if err := rows.Scan(&f.ReleaseID, &f.PURL, &f.Version, &f.Ecosystem, &f.CVEs, &f.Reason, &f.FlaggedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
