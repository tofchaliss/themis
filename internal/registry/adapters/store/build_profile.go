package store

import (
	"context"

	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

var _ app.BuildProfileStore = (*Store)(nil)

// AppendBuildProfile records one change of a build profile (EDR-REBUILD-01 D10) as the
// entity's next revision. Insert only. The revision is taken inside the insert, and the unique
// constraint on (entity, revision) makes two writers at once fail one of them instead of
// sharing a number.
func (s *Store) AppendBuildProfile(ctx context.Context, r domain.BuildProfileRecord) (domain.BuildProfileRecord, error) {
	var profile *string
	if !r.Removed {
		text := string(r.Profile)
		profile = &text
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO registry_build_profiles (entity_kind, entity_id, revision, profile, removed, actor, via, recorded_at)
		SELECT $1, $2, COALESCE(MAX(revision), 0) + 1, $3, $4, $5, $6, $7
		FROM registry_build_profiles WHERE entity_kind = $1 AND entity_id = $2
		RETURNING revision`,
		string(r.Level), r.EntityID, profile, r.Removed, r.Actor, r.Via, r.At).Scan(&r.Revision)
	if err != nil {
		return domain.BuildProfileRecord{}, err
	}
	return r, nil
}

// BuildProfileHistory lists one entity's records, newest first.
func (s *Store) BuildProfileHistory(ctx context.Context, level domain.BuildProfileLevel, id string) ([]domain.BuildProfileRecord, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT revision, profile, removed, actor, via, recorded_at FROM registry_build_profiles
		WHERE entity_kind = $1 AND entity_id = $2 ORDER BY revision DESC`, string(level), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.BuildProfileRecord
	for rows.Next() {
		r := domain.BuildProfileRecord{Level: level, EntityID: id}
		var profile *string
		if err := rows.Scan(&r.Revision, &profile, &r.Removed, &r.Actor, &r.Via, &r.At); err != nil {
			return nil, err
		}
		if profile != nil {
			r.Profile = []byte(*profile)
		}
		r.At = r.At.UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}
