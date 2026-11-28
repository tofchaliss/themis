package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/communication/app"
)

// Compile-time proof that the Store is the cycle port (N-M2i).
var _ app.RebuildCycles = (*Store)(nil)

const cycleColumns = `id, release_id, origin_event_id, baseline_sbom_id, last_sbom_id, targeted_cves, attempts, state, opened_at, updated_at,
	origin, decision_id, decision, product_id, project_id, refusals, joined_decision_ids, closed_by, closed_note`

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
		INSERT INTO rebuild_cycles (release_id, origin_event_id, baseline_sbom_id, last_sbom_id, targeted_cves, attempts, state, opened_at, updated_at,
			origin, decision_id, decision, product_id, project_id, refusals, joined_decision_ids)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+cycleColumns,
		c.ReleaseID, c.OriginEventID, c.BaselineSBOMID, c.LastSBOMID, c.Targeted, c.Attempts, c.State, c.OpenedAt, c.UpdatedAt,
		originOf(c), c.DecisionID, string(c.Decision), c.ProductID, c.ProjectID, c.Refusals, notNil(c.Joined)))
}

// UpdateCycle persists the mutable half of a cycle.
func (s *Store) UpdateCycle(ctx context.Context, c app.RebuildCycle) error {
	_, err := s.q(ctx).Exec(ctx, `
		UPDATE rebuild_cycles SET last_sbom_id=$2, attempts=$3, state=$4, updated_at=$5,
			refusals=$6, joined_decision_ids=$7, closed_by=$8, closed_note=$9 WHERE id=$1`,
		c.ID, c.LastSBOMID, c.Attempts, c.State, c.UpdatedAt, c.Refusals, notNil(c.Joined), c.ClosedBy, c.ClosedNote)
	return err
}

// LatestCycle returns the Release's newest cycle in any state.
func (s *Store) LatestCycle(ctx context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	return foundCycle(scanCycle(s.q(ctx).QueryRow(ctx, `SELECT `+cycleColumns+` FROM rebuild_cycles WHERE release_id=$1 ORDER BY id DESC LIMIT 1`, releaseID)))
}

// CycleByID returns one cycle.
func (s *Store) CycleByID(ctx context.Context, id int64) (app.RebuildCycle, bool, error) {
	return foundCycle(scanCycle(s.q(ctx).QueryRow(ctx, `SELECT `+cycleColumns+` FROM rebuild_cycles WHERE id=$1`, id)))
}

func foundCycle(c app.RebuildCycle, err error) (app.RebuildCycle, bool, error) {
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildCycle{}, false, nil
	}
	return c, err == nil, err
}

// originOf is the cycle's origin; a cycle that names none was opened by the posture.
func originOf(c app.RebuildCycle) string {
	if c.Origin == app.CycleOriginDecision {
		return app.CycleOriginDecision
	}
	return app.CycleOriginEvaluation
}

func notNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func scanCycle(row pgx.Row) (app.RebuildCycle, error) {
	var (
		c        app.RebuildCycle
		decision string
	)
	err := row.Scan(&c.ID, &c.ReleaseID, &c.OriginEventID, &c.BaselineSBOMID, &c.LastSBOMID, &c.Targeted, &c.Attempts, &c.State, &c.OpenedAt, &c.UpdatedAt,
		&c.Origin, &c.DecisionID, &decision, &c.ProductID, &c.ProjectID, &c.Refusals, &c.Joined, &c.ClosedBy, &c.ClosedNote)
	if decision != "" {
		c.Decision = []byte(decision)
	}
	return c, err
}

// Compile-time proof that the Store tells Governance about a closed cycle (D21).
var _ app.CycleClosedNotifier = (*Store)(nil)

// CycleClosed writes communication.rebuild_cycle_closed to the outbox, in the caller's
// transaction when there is one. The relay publishes it; Governance evaluates the Release's
// policy once more. The subject is the Release.
func (s *Store) CycleClosed(ctx context.Context, c app.RebuildCycle) error {
	payload, err := json.Marshal(app.CycleClosedEvent(c))
	if err != nil {
		return err
	}
	_, err = s.q(ctx).Exec(ctx, `
		INSERT INTO communication_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), sourceContext, c.ReleaseID, app.EventRebuildCycleClosed, schemaRefFor(app.EventRebuildCycleClosed),
		c.ReleaseID, string(payload), c.UpdatedAt)
	return err
}
