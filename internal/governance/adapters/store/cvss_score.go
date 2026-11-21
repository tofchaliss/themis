package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/app"
)

// The CVSS assessment store (EDR-SCORING-01 S4, shadow): append-only revisions, never updated.

var _ app.ScoreStore = (*Store)(nil)

// CurrentScores reads the newest revision of every component and of the roll-up.
func (s *Store) CurrentScores(ctx context.Context, findingID string) ([]app.ScoreRevision, *app.RollupRevision, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT ON (purl) purl, revision, cause, fingerprint, snapshot, recorded_at
		FROM component_score_revisions WHERE finding_id = $1
		ORDER BY purl, revision DESC`, findingID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var comps []app.ScoreRevision
	for rows.Next() {
		r := app.ScoreRevision{FindingID: findingID}
		var snap []byte
		if err := rows.Scan(&r.PURL, &r.Revision, &r.Cause, &r.Fingerprint, &snap, &r.RecordedAt); err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(snap, &r.Snapshot); err != nil {
			return nil, nil, err
		}
		r.RecordedAt = r.RecordedAt.UTC()
		comps = append(comps, r)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	roll := &app.RollupRevision{FindingID: findingID}
	var snap []byte
	err = s.pool.QueryRow(ctx, `
		SELECT revision, cause, fingerprint, snapshot, recorded_at FROM finding_score_revisions
		WHERE finding_id = $1 ORDER BY revision DESC LIMIT 1`, findingID).
		Scan(&roll.Revision, &roll.Cause, &roll.Fingerprint, &snap, &roll.RecordedAt)
	switch {
	case err == pgx.ErrNoRows:
		return comps, nil, nil
	case err != nil:
		return nil, nil, err
	}
	if err := json.Unmarshal(snap, &roll.Snapshot); err != nil {
		return nil, nil, err
	}
	roll.RecordedAt = roll.RecordedAt.UTC()
	return comps, roll, nil
}

// AppendScores writes the revisions in one transaction, each numbered after its current one.
// A per-Finding advisory lock keeps two writers from numbering the same revision.
func (s *Store) AppendScores(ctx context.Context, findingID string, comps []app.ScoreRevision, rollup *app.RollupRevision) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('score:' || $1))`, findingID); err != nil {
		return err
	}
	for _, c := range comps {
		snap, err := json.Marshal(c.Snapshot)
		if err != nil {
			return err
		}
		var score *float64
		if c.Snapshot.Scores != nil {
			v := c.Snapshot.Scores.Environmental
			score = &v
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO component_score_revisions (finding_id, purl, revision, cause, fingerprint, score_status, score, snapshot, recorded_at)
			SELECT $1, $2, COALESCE(MAX(revision), 0) + 1, $3, $4, $5, $6, $7, $8
			FROM component_score_revisions WHERE finding_id = $1 AND purl = $2`,
			findingID, c.PURL, c.Cause, c.Fingerprint, c.Snapshot.Status, score, snap, c.RecordedAt.UTC()); err != nil {
			return err
		}
	}
	if rollup != nil {
		snap, err := json.Marshal(rollup.Snapshot)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO finding_score_revisions (finding_id, revision, cause, fingerprint, state, score, snapshot, recorded_at)
			SELECT $1, COALESCE(MAX(revision), 0) + 1, $2, $3, $4, $5, $6, $7
			FROM finding_score_revisions WHERE finding_id = $1`,
			findingID, rollup.Cause, rollup.Fingerprint, rollup.Snapshot.State, rollup.Snapshot.Score, snap, rollup.RecordedAt.UTC()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ScoreHistory lists every component revision of a Finding, newest first.
func (s *Store) ScoreHistory(ctx context.Context, findingID string) ([]app.ScoreRevisionSummary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT purl, revision, cause, score_status, score, recorded_at FROM component_score_revisions
		WHERE finding_id = $1 ORDER BY recorded_at DESC, purl, revision DESC`, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []app.ScoreRevisionSummary{}
	for rows.Next() {
		var r app.ScoreRevisionSummary
		var at time.Time
		if err := rows.Scan(&r.PURL, &r.Revision, &r.Cause, &r.Status, &r.Score, &at); err != nil {
			return nil, err
		}
		r.RecordedAt = at.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// FindingIDsAfter pages Finding ids in id order.
func (s *Store) FindingIDsAfter(ctx context.Context, after string, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM findings WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
