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

// Rebuild triggers and decisions (EDR-REBUILD-01 step R2 part 2). See
// migrations/000030_rebuild_decisions.up.sql for the two tables.

var _ app.RebuildTriggerStore = (*Store)(nil)

// enqueueRebuildTrigger records, inside the caller's transaction, that the event just written
// is a rebuild trigger for the Release. The event id is the trigger id (D27), so the trigger
// commits or rolls back with its event.
func enqueueRebuildTrigger(ctx context.Context, tx pgx.Tx, eventID, triggerType, releaseID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO rebuild_triggers (trigger_id, trigger_source, trigger_type, release_id)
		VALUES ($1,$2,$3,$4) ON CONFLICT (trigger_source, trigger_id) DO NOTHING`,
		eventID, sourceContext, triggerType, releaseID)
	return err
}

var _ app.RebuildTriggerRecorder = (*Store)(nil)

// RecordRebuildTrigger stores an open trigger that came from another context (a closed rebuild
// cycle, D21), in the inbox transaction when one rides the context. The same (source, id) twice
// stores one.
func (s *Store) RecordRebuildTrigger(ctx context.Context, triggerID, source, triggerType, releaseID string) error {
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO rebuild_triggers (trigger_id, trigger_source, trigger_type, release_id)
		VALUES ($1,$2,$3,$4) ON CONFLICT (trigger_source, trigger_id) DO NOTHING`,
		triggerID, source, triggerType, releaseID)
	return err
}

// MarkRebuildCyclesClosed notes on the approved recommendations among decisionIDs that their
// rebuild cycle closed, in the inbox transaction when one rides the context. It reports whether
// one of them had kept a trigger back.
func (s *Store) MarkRebuildCyclesClosed(ctx context.Context, decisionIDs []string) (bool, error) {
	if len(decisionIDs) == 0 {
		return false, nil
	}
	var retrigger bool
	err := s.exec(ctx).QueryRow(ctx, `
		WITH closed AS (
			UPDATE rebuild_decisions SET cycle_closed_at = now()
			WHERE decision_id = ANY($1) AND state = 'approved' AND cycle_closed_at IS NULL
			RETURNING retrigger)
		SELECT COALESCE(bool_or(retrigger), false) FROM closed`, decisionIDs).Scan(&retrigger)
	return retrigger, err
}

// PendingRebuildTriggers lists open triggers, oldest first.
func (s *Store) PendingRebuildTriggers(ctx context.Context, limit int) ([]app.RebuildTrigger, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, trigger_id, trigger_source, trigger_type, release_id, received_at
		FROM rebuild_triggers WHERE settled_at IS NULL
		ORDER BY received_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.RebuildTrigger
	for rows.Next() {
		var t app.RebuildTrigger
		if err := rows.Scan(&t.ID, &t.TriggerID, &t.Source, &t.Type, &t.ReleaseID, &t.ReceivedAt); err != nil {
			return nil, err
		}
		t.ReceivedAt = t.ReceivedAt.UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

// SettleRebuildTrigger closes the trigger and, with a decision, stores it and appends its event
// (subject: the Release), in one transaction. The UPDATE is guarded by `settled_at IS NULL`: a
// trigger another pass closed first rolls this attempt back and reports success.
//
// Step R4: the same transaction ends the standing recommendation the result names, checks that
// an "unchanged" result still points at the standing one, and flags the approved one that kept
// the trigger back. When any of those no longer holds, or the new recommendation meets the
// one-standing-per-Release index, nothing is written and app.ErrRebuildStandingChanged is
// returned: the trigger stays open and is judged again (D44 items 4 and 5).
func (s *Store) SettleRebuildTrigger(ctx context.Context, trig app.RebuildTrigger, res app.RebuildTriggerResult, decision *domain.RebuildDecision, note app.OutboxNote) error {
	var facts, payload []byte
	var decisionID *string
	newID := ""
	if decision != nil {
		var err error
		if facts, err = json.Marshal(decision); err != nil {
			return err
		}
		if payload, err = json.Marshal(note.Event); err != nil {
			return err
		}
		decisionID, newID = &decision.DecisionID, decision.DecisionID
	} else if res.PointsTo != "" {
		decisionID = &res.PointsTo
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx, `
		UPDATE rebuild_triggers
		SET settled_at = $2, outcome = $3, reason = $4, effective_mode = $5, mode_set_by = $6,
		    considered = $7, targeted = $8, decision_id = $9
		WHERE id = $1 AND settled_at IS NULL`,
		trig.ID, res.SettledAt.UTC(), res.Outcome, res.Reason, res.EffectiveMode, res.ModeSetBy,
		res.Considered, res.Targeted, decisionID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return nil
	}
	// Each guard is one conditional statement; a miss means the recommendation moved first.
	guards := []struct {
		id, sql string
		args    []any
	}{
		{res.EndStanding, `UPDATE rebuild_decisions SET state = $2, state_at = $3, superseded_by = $4
			WHERE decision_id = $1 AND state = 'standing'`,
			[]any{res.EndStanding, res.EndState, res.SettledAt.UTC(), supersededBy(res, newID)}},
		{res.PointsTo, `UPDATE rebuild_decisions SET state = state WHERE decision_id = $1 AND state = 'standing'`,
			[]any{res.PointsTo}},
		{res.Retrigger, `UPDATE rebuild_decisions SET retrigger = true
			WHERE decision_id = $1 AND state = 'approved' AND cycle_closed_at IS NULL`,
			[]any{res.Retrigger}},
	}
	for _, g := range guards {
		if g.id == "" {
			continue
		}
		ct, err := tx.Exec(ctx, g.sql, g.args...)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return app.ErrRebuildStandingChanged
		}
	}
	if decision != nil {
		state := ""
		if decision.Outcome == domain.RebuildOutcomeRecommend {
			state = domain.RebuildRecStanding
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO rebuild_decisions (decision_id, release_id, trigger_source, trigger_id, outcome, decided_at, facts, state, state_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$6)`,
			decision.DecisionID, decision.ReleaseID, decision.TriggerSource, decision.TriggerID,
			decision.Outcome, decision.DecidedAt.UTC(), string(facts), state); err != nil {
			if isUniqueViolation(err) {
				return app.ErrRebuildStandingChanged
			}
			return err
		}
		if err := rebuildOutbox(ctx, tx, decision.ReleaseID, note.EventType, payload, note.OccurredAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// supersededBy names the new recommendation on the one it replaces; a withdrawn one names none.
func supersededBy(res app.RebuildTriggerResult, newID string) string {
	if res.EndState == domain.RebuildRecSuperseded {
		return newID
	}
	return ""
}

// rebuildOutbox appends one rebuild event of a Release to the outbox.
func rebuildOutbox(ctx context.Context, tx pgx.Tx, releaseID, eventType string, payload []byte, at time.Time) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO governance_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), sourceContext, releaseID, eventType, schemaRefFor(eventType),
		releaseID, string(payload), at.UTC())
	return err
}

// RebuildTriggerRecords lists the triggers of one Release, newest first, each with its decision
// when it ended in one.
func (s *Store) RebuildTriggerRecords(ctx context.Context, releaseID string, limit int) ([]app.RebuildTriggerRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.trigger_id, t.trigger_source, t.trigger_type, t.release_id, t.received_at,
		       t.settled_at, COALESCE(t.outcome, ''), t.reason, t.effective_mode, t.mode_set_by,
		       t.considered, t.targeted, d.facts
		FROM rebuild_triggers t
		LEFT JOIN rebuild_decisions d ON d.decision_id = t.decision_id
		WHERE t.release_id = $1
		ORDER BY t.received_at DESC, t.id DESC LIMIT $2`, releaseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []app.RebuildTriggerRecord{}
	for rows.Next() {
		var rec app.RebuildTriggerRecord
		var settledAt *time.Time
		var facts []byte
		if err := rows.Scan(&rec.ID, &rec.TriggerID, &rec.Source, &rec.Type, &rec.ReleaseID, &rec.ReceivedAt,
			&settledAt, &rec.Result.Outcome, &rec.Result.Reason, &rec.Result.EffectiveMode, &rec.Result.ModeSetBy,
			&rec.Result.Considered, &rec.Result.Targeted, &facts); err != nil {
			return nil, err
		}
		rec.ReceivedAt = rec.ReceivedAt.UTC()
		if settledAt != nil {
			rec.Settled, rec.Result.SettledAt = true, settledAt.UTC()
		}
		if facts != nil {
			var d domain.RebuildDecision
			if err := json.Unmarshal(facts, &d); err != nil {
				return nil, err
			}
			rec.Decision = &d
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
