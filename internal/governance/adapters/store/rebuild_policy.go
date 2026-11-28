package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild policy store (EDR-REBUILD-01 step R1): the policy in force per scope and every
// version it ever had. It stores and reads; the rule is domain.EvaluateRebuild.

var _ app.RebuildPolicyStore = (*Store)(nil)

const rebuildPolicyColumns = `scope_kind, scope_id, version, fix_required, severity_floor,
	count_known_exploited, skip_decided, carrier_only, cool_down_seconds, mode, updated_at, updated_by`

func scanRebuildPolicy(row pgx.Row) (app.RebuildPolicyRecord, error) {
	var (
		r       app.RebuildPolicyRecord
		seconds int64
		mode    string
	)
	p := &r.Policy
	if err := row.Scan(&r.ScopeKind, &r.ScopeID, &r.Version, &p.FixRequired, &p.SeverityFloor,
		&p.CountKnownExploited, &p.SkipDecided, &p.CarrierOnly, &seconds, &mode, &r.UpdatedAt, &r.UpdatedBy); err != nil {
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

// PutRebuildPolicy stores the next version of one scope's policy and appends it to the history,
// in ONE transaction. The upsert locks the scope's row, so two changes at once get two
// consecutive versions and neither is lost.
func (s *Store) PutRebuildPolicy(ctx context.Context, rec app.RebuildPolicyRecord) (app.RebuildPolicyRecord, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return app.RebuildPolicyRecord{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	p := rec.Policy
	seconds := int64(p.CoolDown / time.Second)
	if err := tx.QueryRow(ctx, `
		INSERT INTO rebuild_policies (scope_kind, scope_id, version, fix_required, severity_floor,
		        count_known_exploited, skip_decided, carrier_only, cool_down_seconds, mode, updated_at, updated_by)
		VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (scope_kind, scope_id) DO UPDATE SET
		    version = rebuild_policies.version + 1,
		    fix_required = EXCLUDED.fix_required, severity_floor = EXCLUDED.severity_floor,
		    count_known_exploited = EXCLUDED.count_known_exploited, skip_decided = EXCLUDED.skip_decided,
		    carrier_only = EXCLUDED.carrier_only, cool_down_seconds = EXCLUDED.cool_down_seconds,
		    mode = EXCLUDED.mode, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
		RETURNING version`,
		rec.ScopeKind, rec.ScopeID, p.FixRequired, p.SeverityFloor, p.CountKnownExploited, p.SkipDecided,
		p.CarrierOnly, seconds, string(p.Mode), rec.UpdatedAt, rec.UpdatedBy).Scan(&rec.Version); err != nil {
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
	return rec, nil
}

// RebuildPolicyHistory returns every version of one scope's policy, newest first.
func (s *Store) RebuildPolicyHistory(ctx context.Context, scopeKind, scopeID string) ([]app.RebuildPolicyRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+rebuildPolicyColumns+` FROM rebuild_policy_history
		 WHERE scope_kind = $1 AND scope_id = $2 ORDER BY version DESC`, scopeKind, scopeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.RebuildPolicyRecord
	for rows.Next() {
		r, err := scanRebuildPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
