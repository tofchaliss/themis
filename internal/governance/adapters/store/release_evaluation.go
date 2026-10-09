package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The pending release-evaluation queue (EDR-DELIVERY-01 N-M2b): the inbound seam enqueues,
// the worker drains. See migrations/000015_release_evaluations.up.sql for why the two halves
// are split.

// Compile-time proof that the Store is both halves of the queue. Stated here so a signature
// drift fails in this file rather than at the composition root.
var (
	_ app.PendingEvaluations = (*Store)(nil)
	_ app.ReleaseEvaluations = (*Store)(nil)
)

// EnqueuePendingReleaseEvaluation records that (release, sbom, cause) is due for evaluation.
//
// It writes through s.exec, so when an inbox transaction rides the context — which is the only
// way this is called in production — the row is claimed atomically with the envelope: the event
// is never marked processed without its to-do, and a rolled-back envelope leaves no to-do
// behind. Idempotent on the triple, so a redelivery adds nothing.
func (s *Store) EnqueuePendingReleaseEvaluation(ctx context.Context, releaseID, sbomID, cause string) error {
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO release_evaluations_pending (release_id, sbom_id, cause)
		VALUES ($1,$2,$3) ON CONFLICT (release_id, sbom_id, cause) DO NOTHING`,
		releaseID, sbomID, cause)
	return err
}

// ListPendingReleaseEvaluations returns up to limit unpublished rows, oldest first.
func (s *Store) ListPendingReleaseEvaluations(ctx context.Context, limit int) ([]app.PendingEvaluation, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, release_id, sbom_id, cause, received_at
		FROM release_evaluations_pending
		WHERE published_at IS NULL
		ORDER BY received_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.PendingEvaluation
	for rows.Next() {
		var p app.PendingEvaluation
		if err := rows.Scan(&p.ID, &p.ReleaseID, &p.SBOMID, &p.Cause, &p.ReceivedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountFindingsByBaseScoreBuckets buckets every Finding of the Release by the M1b-5 ladder.
//
// The query fetches the scores and the DOMAIN buckets them (domain.CountSeverityBuckets), for
// the same reason ReleaseScope derives its major in Go: a second implementation of the ladder —
// here, as SQL thresholds — is a second thing to keep in step with the Jira body's buckets, and
// the one place they must agree is the one place the rule should live.
//
// No disposition filter: a suppressed Finding is still a Finding of this Release (M1b-4). A
// `base_score` of 0 reaches the domain and is counted in no bucket.
func (s *Store) CountFindingsByBaseScoreBuckets(ctx context.Context, releaseID string) (domain.SeverityCounts, error) {
	rows, err := s.pool.Query(ctx, `SELECT base_score FROM findings WHERE release_id = $1`, releaseID)
	if err != nil {
		return domain.SeverityCounts{}, err
	}
	defer rows.Close()

	var scores []int
	for rows.Next() {
		var score int
		if err := rows.Scan(&score); err != nil {
			return domain.SeverityCounts{}, err
		}
		scores = append(scores, score)
	}
	if err := rows.Err(); err != nil {
		return domain.SeverityCounts{}, err
	}
	return domain.CountSeverityBuckets(scores), nil
}

// PublishEvaluatedAndMark appends governance.release_evaluated.v1 to the outbox and marks the
// pending row published, in ONE transaction.
//
// The two are inseparable on purpose. Appending without marking republishes on every pass;
// marking without appending loses the only signal the rebuild loop runs on. The UPDATE is
// guarded by `published_at IS NULL`, so if another worker (or another node) published this row
// first, this transaction rolls back and reports success — nothing is lost and nothing is
// published twice.
//
// The outbox subject is the RELEASE, not a Finding: this is the one Governance event whose
// subject is not an aggregate id.
func (s *Store) PublishEvaluatedAndMark(ctx context.Context, row app.PendingEvaluation, ev domain.ReleaseEvaluated, occurredAt time.Time) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	// Its OWN transaction, unconditionally — the worker runs on a background loop, never inside
	// the inbox unit of work, and "these two writes commit together" must not depend on who
	// called it.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx,
		`UPDATE release_evaluations_pending SET published_at = now() WHERE id = $1 AND published_at IS NULL`, row.ID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return nil // already published by another pass — the deferred rollback drops this attempt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO governance_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), sourceContext, row.ReleaseID, app.EventReleaseEvaluated,
		schemaRefFor(app.EventReleaseEvaluated), row.ReleaseID, string(payload), occurredAt); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
