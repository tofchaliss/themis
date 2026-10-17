package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
)

// Compile-time proof that the Store is the cycle port (N-M2i).
var _ app.RebuildCycles = (*Store)(nil)

const cycleColumns = `id, release_id, origin_event_id, baseline_sbom_id, last_sbom_id, targeted_cves, attempts, state, opened_at, updated_at`

// OpenCycle returns the Release's one open cycle (the partial unique index guarantees at most one).
func (s *Store) OpenCycle(ctx context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	c, err := scanCycle(s.q(ctx).QueryRow(ctx, `SELECT `+cycleColumns+` FROM rebuild_cycles WHERE release_id=$1 AND state='open'`, releaseID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildCycle{}, false, nil
	}
	if err != nil {
		return app.RebuildCycle{}, false, err
	}
	return c, true, nil
}

// CreateCycle persists a new open cycle. A second open cycle for the Release is a database
// error — the loop asks OpenCycle first, so this is the backstop under concurrency.
func (s *Store) CreateCycle(ctx context.Context, c app.RebuildCycle) (app.RebuildCycle, error) {
	return scanCycle(s.q(ctx).QueryRow(ctx, `
		INSERT INTO rebuild_cycles (release_id, origin_event_id, baseline_sbom_id, last_sbom_id, targeted_cves, attempts, state, opened_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING `+cycleColumns,
		c.ReleaseID, c.OriginEventID, c.BaselineSBOMID, c.LastSBOMID, c.Targeted, c.Attempts, c.State, c.OpenedAt, c.UpdatedAt))
}

// UpdateCycle persists the mutable half of a cycle.
func (s *Store) UpdateCycle(ctx context.Context, c app.RebuildCycle) error {
	_, err := s.q(ctx).Exec(ctx, `
		UPDATE rebuild_cycles SET last_sbom_id=$2, attempts=$3, state=$4, updated_at=$5 WHERE id=$1`,
		c.ID, c.LastSBOMID, c.Attempts, c.State, c.UpdatedAt)
	return err
}

func scanCycle(row pgx.Row) (app.RebuildCycle, error) {
	var c app.RebuildCycle
	err := row.Scan(&c.ID, &c.ReleaseID, &c.OriginEventID, &c.BaselineSBOMID, &c.LastSBOMID, &c.Targeted, &c.Attempts, &c.State, &c.OpenedAt, &c.UpdatedAt)
	return c, err
}
