package store

import (
	"context"

	"github.com/themis-project/themis/internal/registry/domain"
)

// SetTags replaces one entity's own tag set in one transaction (EDR-REMEDIATION-01 D7).
func (s *Store) SetTags(ctx context.Context, kind domain.TagEntity, id string, tags []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM registry_tags WHERE entity_kind = $1 AND entity_id = $2`, string(kind), id); err != nil {
		return err
	}
	for _, t := range tags {
		if _, err := tx.Exec(ctx, `INSERT INTO registry_tags (entity_kind, entity_id, tag) VALUES ($1,$2,$3)
			ON CONFLICT DO NOTHING`, string(kind), id, t); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// TagsOf reads the own tags of many entities of one kind, sorted per entity.
func (s *Store) TagsOf(ctx context.Context, kind domain.TagEntity, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT entity_id, tag FROM registry_tags
		WHERE entity_kind = $1 AND entity_id = ANY($2) ORDER BY entity_id, tag`, string(kind), ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, tag string
		if err := rows.Scan(&id, &tag); err != nil {
			return nil, err
		}
		out[id] = append(out[id], tag)
	}
	return out, rows.Err()
}

// TaggedReleases lists the releases whose own, project's or product's tags carry tag.
func (s *Store) TaggedReleases(ctx context.Context, tag string) ([]domain.Release, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT r.id, r.project_id, r.version
		FROM releases r JOIN projects p ON p.id = r.project_id
		WHERE EXISTS (SELECT 1 FROM registry_tags t WHERE t.tag = $1 AND (
		        (t.entity_kind = 'release' AND t.entity_id = r.id) OR
		        (t.entity_kind = 'project' AND t.entity_id = r.project_id) OR
		        (t.entity_kind = 'product' AND t.entity_id = p.product_id)))
		ORDER BY r.id`, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Release
	for rows.Next() {
		var id, proj, ver string
		if err := rows.Scan(&id, &proj, &ver); err != nil {
			return nil, err
		}
		rel, err := domain.NewRelease(domain.ReleaseID(id), domain.ProjectID(proj), ver)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}
