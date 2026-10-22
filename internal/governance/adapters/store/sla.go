package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The SLA store (EDR-REMEDIATION-01 D1): the policy table, the facts the clock reads, and the
// breach log. The clock itself is domain.EvaluateSLA; nothing here computes a deadline.

var _ app.SLAStore = (*Store)(nil)

// SLAPolicies returns every stored policy, the estate one ('' scope) first.
func (s *Store) SLAPolicies(ctx context.Context) ([]app.SLAPolicyRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT scope, critical_days, critical_enforce, high_days, high_enforce,
		       medium_days, medium_enforce, low_days, low_enforce, updated_at, updated_by
		FROM sla_policies ORDER BY scope`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.SLAPolicyRecord
	for rows.Next() {
		var r app.SLAPolicyRecord
		p := &r.Policy
		if err := rows.Scan(&r.Scope, &p.Critical.Days, &p.Critical.Enforce, &p.High.Days, &p.High.Enforce,
			&p.Medium.Days, &p.Medium.Enforce, &p.Low.Days, &p.Low.Enforce, &r.UpdatedAt, &r.UpdatedBy); err != nil {
			return nil, err
		}
		r.UpdatedAt = r.UpdatedAt.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// PutSLAPolicy inserts or replaces one scope's policy.
func (s *Store) PutSLAPolicy(ctx context.Context, r app.SLAPolicyRecord) error {
	p := r.Policy
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sla_policies (scope, critical_days, critical_enforce, high_days, high_enforce,
		                          medium_days, medium_enforce, low_days, low_enforce, updated_at, updated_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (scope) DO UPDATE SET
		    critical_days = EXCLUDED.critical_days, critical_enforce = EXCLUDED.critical_enforce,
		    high_days = EXCLUDED.high_days, high_enforce = EXCLUDED.high_enforce,
		    medium_days = EXCLUDED.medium_days, medium_enforce = EXCLUDED.medium_enforce,
		    low_days = EXCLUDED.low_days, low_enforce = EXCLUDED.low_enforce,
		    updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		r.Scope, p.Critical.Days, p.Critical.Enforce, p.High.Days, p.High.Enforce,
		p.Medium.Days, p.Medium.Enforce, p.Low.Days, p.Low.Enforce, r.UpdatedAt, r.UpdatedBy)
	return err
}

const slaFactsSelect = `
	SELECT f.id, f.release_id, f.faultline_id, f.cve, f.stage, f.created_at, f.base_score, f.sla_bucket,
	       f.stale_since, f.signal_kev_due, f.stage_stopped_at
	FROM findings f`

// SLAFactsForRelease returns the clock facts for every Finding of one Release.
func (s *Store) SLAFactsForRelease(ctx context.Context, releaseID string) ([]app.SLAFacts, error) {
	facts, err := s.scanSLAFacts(ctx, slaFactsSelect+` WHERE f.release_id = $1 ORDER BY f.id`, releaseID)
	if err != nil {
		return nil, err
	}
	return s.attachSLAPositions(ctx, facts)
}

// RunningSLAFacts pages through the Findings whose clock may still run: not resolved or
// archived, and not resting on a stopping Position (not_affected / mitigated).
func (s *Store) RunningSLAFacts(ctx context.Context, afterID string, limit int) ([]app.SLAFacts, error) {
	facts, err := s.scanSLAFacts(ctx, slaFactsSelect+`
		WHERE f.stage NOT IN ('resolved', 'archived')
		  AND (f.current_stance IS NULL OR f.current_stance NOT IN ('not_affected', 'mitigated'))
		  AND (f.sla_bucket <> '' OR f.base_score > 0 OR f.signal_kev_due IS NOT NULL)
		  AND f.id > $1
		ORDER BY f.id LIMIT $2`, afterID, limit)
	if err != nil {
		return nil, err
	}
	return s.attachSLAPositions(ctx, facts)
}

func (s *Store) scanSLAFacts(ctx context.Context, sql string, args ...any) ([]app.SLAFacts, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.SLAFacts
	for rows.Next() {
		var (
			f                          app.SLAFacts
			id, stage, bucket          string
			created                    time.Time
			stale, kevDue, stageStopAt *time.Time
		)
		if err := rows.Scan(&id, &f.ReleaseID, &f.FaultlineID, &f.CVE, &stage, &created, &f.BaseScore, &bucket,
			&stale, &kevDue, &stageStopAt); err != nil {
			return nil, err
		}
		f.FindingID = domain.FindingID(id)
		f.Input = domain.SLAInput{
			CreatedAt: created.UTC(), Bucket: bucket, CurrentBucket: domain.SLABucketOf(f.BaseScore),
			Stage: domain.Stage(stage), StaleSince: utcOrZero(stale), KEVDue: utcOrZero(kevDue),
			StageStoppedAt: utcOrZero(stageStopAt),
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// attachSLAPositions fills each Finding's Position history (stance, established_at, review_by)
// in ONE query for the page.
func (s *Store) attachSLAPositions(ctx context.Context, facts []app.SLAFacts) ([]app.SLAFacts, error) {
	if len(facts) == 0 {
		return facts, nil
	}
	ids := make([]string, len(facts))
	at := make(map[string]int, len(facts))
	for i, f := range facts {
		ids[i] = string(f.FindingID)
		at[ids[i]] = i
	}
	rows, err := s.pool.Query(ctx, `
		SELECT finding_id, stance, established_at, review_by
		FROM finding_positions WHERE finding_id = ANY($1) ORDER BY finding_id, version`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			fid, stance string
			established time.Time
			reviewBy    *time.Time
		)
		if err := rows.Scan(&fid, &stance, &established, &reviewBy); err != nil {
			return nil, err
		}
		i := at[fid]
		facts[i].Input.Positions = append(facts[i].Input.Positions, domain.SLAPositionFact{
			Stance: domain.Stance(stance), EstablishedAt: established.UTC(), ReviewBy: utcOrZero(reviewBy),
		})
	}
	return facts, rows.Err()
}

// RecordSLABreach writes one (Finding, period) breach and its outbox note in one transaction,
// once. These two rows are the breach path's ONLY writes (S1).
func (s *Store) RecordSLABreach(ctx context.Context, findingID domain.FindingID, periodStart time.Time, note app.OutboxNote) (bool, error) {
	payload, err := json.Marshal(note.Event)
	if err != nil {
		return false, err
	}
	due := note.OccurredAt
	if ev, ok := note.Event.(domain.SLABreachedEvent); ok {
		due = ev.Due
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	ct, err := tx.Exec(ctx, `
		INSERT INTO sla_breaches (finding_id, period_start, due, recorded_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (finding_id, period_start) DO NOTHING`,
		string(findingID), periodStart, due, note.OccurredAt)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		return false, nil // this period's breach is already on record
	}
	if err := insertNote(ctx, tx, string(findingID), note, payload); err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

func insertNote(ctx context.Context, tx pgx.Tx, subject string, n app.OutboxNote, payload []byte) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO governance_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), sourceContext, subject, n.EventType, schemaRefFor(n.EventType), subject, string(payload), n.OccurredAt)
	return err
}

func utcOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}
