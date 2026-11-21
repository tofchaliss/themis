package store

import (
	"context"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

var _ app.RequirementStore = (*Store)(nil)

// AppendRequirement records one change of security requirements (EDR-SCORING-01 S3). Insert
// only.
func (s *Store) AppendRequirement(ctx context.Context, r domain.RequirementRecord) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO registry_security_requirements
		(entity_kind, entity_id, cr, ir, ar, reason, actor, via, recorded_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		string(r.Level), r.EntityID, string(r.Requirements.CR), string(r.Requirements.IR), string(r.Requirements.AR),
		r.Reason, r.Actor, r.Via, r.At)
	return err
}

// RequirementHistory lists one entity's records, newest first.
func (s *Store) RequirementHistory(ctx context.Context, level domain.RequirementLevel, id string) ([]domain.RequirementRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT cr, ir, ar, reason, actor, via, recorded_at FROM registry_security_requirements
		WHERE entity_kind = $1 AND entity_id = $2 ORDER BY seq DESC`, string(level), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.RequirementRecord
	for rows.Next() {
		r := domain.RequirementRecord{Level: level, EntityID: id}
		var cr, ir, ar string
		if err := rows.Scan(&cr, &ir, &ar, &r.Reason, &r.Actor, &r.Via, &r.At); err != nil {
			return nil, err
		}
		r.Requirements = domain.Requirements{CR: domain.Requirement(cr), IR: domain.Requirement(ir), AR: domain.Requirement(ar)}
		r.At = r.At.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}
