package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The owner-set severity store (EDR-SCORING-01 section 7.1). finding_owner_severities is the
// record: a row is ended, never deleted or rewritten. findings.owner_base_score /
// owner_sla_bucket are the read columns priority, the deadline and the counts use.

var _ app.OwnerSeverityStore = (*Store)(nil)

const ownerSeverityColumns = `finding_id, kind, level, vector, score, original_score, reason, actor_id, set_at, picked_from, original_vector`

// ownerSeverityRead adds the keep mark, which only a read carries.
const ownerSeverityRead = ownerSeverityColumns + `, kept_at, kept_by, kept_score, kept_vector`

type rowScanner interface{ Scan(dest ...any) error }

func scanOwnerSeverity(row rowScanner, extra ...any) (domain.FindingID, domain.OwnerSeverity, error) {
	var (
		id, level, actor, picked string
		o                        domain.OwnerSeverity
		keptAt                   *time.Time
		kept                     domain.SeverityKept
	)
	dest := append([]any{&id, &o.Kind, &level, &o.Vector, &o.Score, &o.OriginalScore, &o.Reason, &actor, &o.SetAt, &picked,
		&o.OriginalVector, &keptAt, &kept.By, &kept.Score, &kept.Vector}, extra...)
	if err := row.Scan(dest...); err != nil {
		return "", domain.OwnerSeverity{}, err
	}
	o.Level, o.SetAt, o.PickedFrom = domain.SeverityLevel(level), o.SetAt.UTC(), domain.FindingID(picked)
	o.Actor = domain.Actor{Kind: domain.ActorHuman, ID: actor}
	if keptAt != nil {
		kept.At = keptAt.UTC()
		o.Kept = &kept
	}
	return domain.FindingID(id), o, nil
}

// CurrentOwnerSeverities reads the severity in force on each of the given Findings; a Finding
// with none is absent from the map.
func (s *Store) CurrentOwnerSeverities(ctx context.Context, ids []domain.FindingID) (map[domain.FindingID]domain.OwnerSeverity, error) {
	out := map[domain.FindingID]domain.OwnerSeverity{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+ownerSeverityRead+` FROM finding_owner_severities
		WHERE finding_id = ANY($1) AND ended_at IS NULL`, idStrings(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		id, o, err := scanOwnerSeverity(rows)
		if err != nil {
			return nil, err
		}
		out[id] = o
	}
	return out, rows.Err()
}

// OwnerSeverityHistory reads every owner-set severity one Finding ever had, oldest first.
func (s *Store) OwnerSeverityHistory(ctx context.Context, id domain.FindingID) ([]app.OwnerSeverityRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+ownerSeverityRead+`, ended_at, ended_by, end_cause FROM finding_owner_severities
		WHERE finding_id = $1 ORDER BY id`, string(id))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.OwnerSeverityRecord
	for rows.Next() {
		var (
			r     app.OwnerSeverityRecord
			ended *time.Time
		)
		_, o, err := scanOwnerSeverity(rows, &ended, &r.EndedBy, &r.EndCause)
		if err != nil {
			return nil, err
		}
		r.OwnerSeverity, r.EndedAt = o, utcOrZero(ended)
		out = append(out, r)
	}
	return out, rows.Err()
}

// OriginalSeverities reads, per Finding, the original score and the vector Themis selected,
// from the newest stored CVSS assessment of its current components. The original is the highest
// source Base score over the open carrier components, falling back to every current component
// (the same rule as the posture list's Original column), and the vector is the one of the
// component that gave it. A Finding with no assessment is absent from the map.
func (s *Store) OriginalSeverities(ctx context.Context, ids []domain.FindingID) (map[domain.FindingID]app.OriginalSeverity, error) {
	out := map[domain.FindingID]app.OriginalSeverity{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (c.finding_id, c.purl) c.finding_id, c.snapshot
			FROM component_score_revisions c
			JOIN finding_components m ON m.finding_id = c.finding_id AND m.purl = c.purl AND m.retired_at IS NULL
			WHERE c.finding_id = ANY($1)
			ORDER BY c.finding_id, c.purl, c.revision DESC)
		SELECT DISTINCT ON (finding_id) finding_id, (snapshot->'scores'->>'base')::float8,
		       COALESCE(snapshot->>'assessment_vector', '')
		FROM latest
		WHERE snapshot->'scores' IS NOT NULL AND jsonb_typeof(snapshot->'scores') = 'object'
		ORDER BY finding_id,
		         (COALESCE((snapshot->>'eligible')::bool, false) AND COALESCE((snapshot->>'open')::bool, false)) DESC,
		         (snapshot->'scores'->>'base')::float8 DESC`, idStrings(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id string
			o  app.OriginalSeverity
		)
		if err := rows.Scan(&id, &o.Score, &o.Vector); err != nil {
			return nil, err
		}
		out[domain.FindingID(id)] = o
	}
	return out, rows.Err()
}

// SaveOwnerSeverities ends the severity in force on each Finding and records the new one, and
// sets the read columns, in ONE transaction.
func (s *Store) SaveOwnerSeverities(ctx context.Context, writes []app.OwnerSeverityWrite) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, w := range writes {
		o, id := w.Severity, string(w.FindingID)
		if _, err := tx.Exec(ctx, `
			UPDATE finding_owner_severities SET ended_at = $2, ended_by = $3, end_cause = 'replaced'
			WHERE finding_id = $1 AND ended_at IS NULL`, id, o.SetAt, o.Actor.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO finding_owner_severities (`+ownerSeverityColumns+`)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			id, o.Kind, string(o.Level), o.Vector, o.Score, o.OriginalScore, o.Reason, o.Actor.ID, o.SetAt, string(o.PickedFrom), o.OriginalVector); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET owner_base_score = $2, owner_sla_bucket = $3 WHERE id = $1`,
			id, o.BaseScore(), o.SLABucket()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// EndOwnerSeverity ends the severity in force and clears the read columns, in one transaction.
func (s *Store) EndOwnerSeverity(ctx context.Context, id domain.FindingID, actorID string, at time.Time) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		UPDATE finding_owner_severities SET ended_at = $2, ended_by = $3, end_cause = 'removed'
		WHERE finding_id = $1 AND ended_at IS NULL`, string(id), at, actorID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() == 0 {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET owner_base_score = NULL, owner_sla_bucket = '' WHERE id = $1`, string(id)); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

// KeepOwnerSeverity marks the severity in force as kept against the given original (OS6): who,
// when, and the original they saw. False when there is none in force.
func (s *Store) KeepOwnerSeverity(ctx context.Context, id domain.FindingID, kept domain.SeverityKept) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE finding_owner_severities SET kept_at = $2, kept_by = $3, kept_score = $4, kept_vector = $5
		WHERE finding_id = $1 AND ended_at IS NULL`, string(id), kept.At, kept.By, kept.Score, kept.Vector)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
