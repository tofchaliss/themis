package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild policy store (EDR-REBUILD-01 steps R1 and R1a): the policy in force per scope and
// every version it ever had, removals included. It stores and reads; the rules are
// domain.EvaluateRebuild and domain.ResolveRebuildPolicy.

var _ app.RebuildPolicyStore = (*Store)(nil)

const rebuildPolicyColumns = `scope_kind, scope_id, version, fix_required, severity_floor,
	count_known_exploited, skip_decided, carrier_only, cool_down_seconds, mode, updated_at, updated_by`

// scanRebuildPolicy reads rebuildPolicyColumns, then any extra columns into more.
func scanRebuildPolicy(row pgx.Row, more ...any) (app.RebuildPolicyRecord, error) {
	var (
		r       app.RebuildPolicyRecord
		seconds int64
		mode    string
	)
	p := &r.Policy
	dest := append([]any{&r.ScopeKind, &r.ScopeID, &r.Version, &p.FixRequired, &p.SeverityFloor,
		&p.CountKnownExploited, &p.SkipDecided, &p.CarrierOnly, &seconds, &mode, &r.UpdatedAt, &r.UpdatedBy}, more...)
	if err := row.Scan(dest...); err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	p.CoolDown, p.Mode = time.Duration(seconds)*time.Second, domain.RebuildMode(mode)
	r.UpdatedAt = r.UpdatedAt.UTC()
	return r, nil
}

// RebuildPolicy returns the policy in force for one scope; found is false when none is stored.
func (s *Store) RebuildPolicy(ctx context.Context, scopeKind, scopeID string) (app.RebuildPolicyRecord, bool, error) {
	rec, err := scanRebuildPolicy(s.pool.QueryRow(ctx,
		`SELECT `+rebuildPolicyColumns+` FROM rebuild_policies WHERE scope_kind = $1 AND scope_id = $2`,
		scopeKind, scopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildPolicyRecord{}, false, nil
	}
	if err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	return rec, true, nil
}

// lockRebuildScope serializes the changes of one scope for the rest of the transaction and
// returns the scope's next version. The version counts every change of the scope from 1 and
// keeps counting across a removal, so it is read from the history, not from the row in force.
func lockRebuildScope(ctx context.Context, tx pgx.Tx, scopeKind, scopeID string) (int, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('rebuild_policy:' || $1 || ':' || $2, 0))`,
		scopeKind, scopeID); err != nil {
		return 0, err
	}
	var next int
	err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM rebuild_policy_history
		WHERE scope_kind = $1 AND scope_id = $2`, scopeKind, scopeID).Scan(&next)
	return next, err
}

// PutRebuildPolicy stores the next version of one scope's policy and appends it to the history,
// in ONE transaction. Two changes at once get two consecutive versions and neither is lost.
func (s *Store) PutRebuildPolicy(ctx context.Context, rec app.RebuildPolicyRecord) (app.RebuildPolicyRecord, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if rec.Version, err = lockRebuildScope(ctx, tx, rec.ScopeKind, rec.ScopeID); err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	p := rec.Policy
	seconds := int64(p.CoolDown / time.Second)
	if _, err := tx.Exec(ctx, `
		INSERT INTO rebuild_policies (`+rebuildPolicyColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (scope_kind, scope_id) DO UPDATE SET
		    version = EXCLUDED.version,
		    fix_required = EXCLUDED.fix_required, severity_floor = EXCLUDED.severity_floor,
		    count_known_exploited = EXCLUDED.count_known_exploited, skip_decided = EXCLUDED.skip_decided,
		    carrier_only = EXCLUDED.carrier_only, cool_down_seconds = EXCLUDED.cool_down_seconds,
		    mode = EXCLUDED.mode, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		rec.ScopeKind, rec.ScopeID, rec.Version, p.FixRequired, p.SeverityFloor, p.CountKnownExploited,
		p.SkipDecided, p.CarrierOnly, seconds, string(p.Mode), rec.UpdatedAt, rec.UpdatedBy); err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rebuild_policy_history (`+rebuildPolicyColumns+`)
		SELECT `+rebuildPolicyColumns+` FROM rebuild_policies WHERE scope_kind = $1 AND scope_id = $2`,
		rec.ScopeKind, rec.ScopeID); err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	rec.UpdatedAt = rec.UpdatedAt.UTC()
	rec.Policy.CoolDown = time.Duration(seconds) * time.Second // what was stored: whole seconds
	rec.Removed = false
	return rec, nil
}

// RemoveRebuildPolicy deletes the policy in force for one scope and records the removal in the
// history as the scope's next version, in ONE transaction: the values are the removed policy's,
// the time and the actor are the removal's. found is false when the scope had no policy.
func (s *Store) RemoveRebuildPolicy(ctx context.Context, scopeKind, scopeID string, at time.Time, by string) (app.RebuildPolicyRecord, bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	next, err := lockRebuildScope(ctx, tx, scopeKind, scopeID)
	if err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	rec, err := scanRebuildPolicy(tx.QueryRow(ctx,
		`DELETE FROM rebuild_policies WHERE scope_kind = $1 AND scope_id = $2 RETURNING `+rebuildPolicyColumns,
		scopeKind, scopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return app.RebuildPolicyRecord{}, false, nil
	}
	if err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	rec.Version, rec.UpdatedAt, rec.UpdatedBy, rec.Removed = next, at.UTC(), by, true
	p := rec.Policy
	if _, err := tx.Exec(ctx, `
		INSERT INTO rebuild_policy_history (`+rebuildPolicyColumns+`, removed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true)`,
		rec.ScopeKind, rec.ScopeID, rec.Version, p.FixRequired, p.SeverityFloor, p.CountKnownExploited,
		p.SkipDecided, p.CarrierOnly, int64(p.CoolDown/time.Second), string(p.Mode), rec.UpdatedAt, rec.UpdatedBy); err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return app.RebuildPolicyRecord{}, false, err
	}
	return rec, true, nil
}

func collectRebuildPolicies(rows pgx.Rows, withRemoved bool) ([]app.RebuildPolicyRecord, error) {
	defer rows.Close()
	var out []app.RebuildPolicyRecord
	for rows.Next() {
		var (
			r       app.RebuildPolicyRecord
			removed bool
			err     error
		)
		if withRemoved {
			r, err = scanRebuildPolicy(rows, &removed)
		} else {
			r, err = scanRebuildPolicy(rows)
		}
		if err != nil {
			return nil, err
		}
		r.Removed = removed
		out = append(out, r)
	}
	return out, rows.Err()
}

// RebuildPolicyHistory returns every version of one scope's policy, newest first.
func (s *Store) RebuildPolicyHistory(ctx context.Context, scopeKind, scopeID string) ([]app.RebuildPolicyRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+rebuildPolicyColumns+`, removed FROM rebuild_policy_history
		 WHERE scope_kind = $1 AND scope_id = $2 ORDER BY version DESC`, scopeKind, scopeID)
	if err != nil {
		return nil, err
	}
	return collectRebuildPolicies(rows, true)
}

// RebuildPolicies returns every policy in force: the installation's, then the Products', then
// the Releases', each group by scope id.
func (s *Store) RebuildPolicies(ctx context.Context) ([]app.RebuildPolicyRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+rebuildPolicyColumns+` FROM rebuild_policies
		 ORDER BY CASE scope_kind WHEN 'installation' THEN 0 WHEN 'product' THEN 1 ELSE 2 END, scope_id`)
	if err != nil {
		return nil, err
	}
	return collectRebuildPolicies(rows, false)
}
