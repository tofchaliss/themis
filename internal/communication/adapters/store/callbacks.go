package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
)

// Compile-time proof that the Store is the callback port (N-M2h).
var _ app.RebuildCallbacks = (*Store)(nil)

const callbackColumns = `intent_id, sbom_id, image_digest, build_id, git_ref, reported_by, received_at`

// RecordCallback persists one build-system report against its intent, idempotent per
// (intent, sbom): a job retrying its callback conflicts on the primary key, the conflict does
// nothing, and the first report is returned. The FK makes a report about an unknown intent a
// database error — the service checks the intent first, so this is the backstop, not the rule.
func (s *Store) RecordCallback(ctx context.Context, cb app.RebuildCallback) (app.RebuildCallback, error) {
	row := s.q(ctx).QueryRow(ctx, `
		INSERT INTO delivery_callbacks (`+callbackColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (intent_id, sbom_id) DO NOTHING
		RETURNING `+callbackColumns,
		cb.IntentID, cb.SBOMID, cb.ImageDigest, cb.BuildID, cb.GitRef, cb.ReportedBy, cb.ReceivedAt)
	stored, err := scanCallback(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return scanCallback(s.q(ctx).QueryRow(ctx,
			`SELECT `+callbackColumns+` FROM delivery_callbacks WHERE intent_id=$1 AND sbom_id=$2`, cb.IntentID, cb.SBOMID))
	}
	return stored, err
}

// ListCallbacks returns the callbacks recorded for one intent, oldest first.
func (s *Store) ListCallbacks(ctx context.Context, intentID string) ([]app.RebuildCallback, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+callbackColumns+` FROM delivery_callbacks WHERE intent_id=$1 ORDER BY received_at, sbom_id`, intentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.RebuildCallback
	for rows.Next() {
		cb, err := scanCallback(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, cb)
	}
	return out, rows.Err()
}

func scanCallback(row pgx.Row) (app.RebuildCallback, error) {
	var cb app.RebuildCallback
	err := row.Scan(&cb.IntentID, &cb.SBOMID, &cb.ImageDigest, &cb.BuildID, &cb.GitRef, &cb.ReportedBy, &cb.ReceivedAt)
	return cb, err
}
