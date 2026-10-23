package store

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

var _ app.MetricsReader = (*Store)(nil)

// MetricsFindings reads every Finding's metric facts in ONE query (EDR-REMEDIATION-01 D6):
// creation, stage, frozen bucket, the first human Position, the absence mark, the first human
// Position at or after it, and the stage stop.
func (s *Store) MetricsFindings(ctx context.Context) ([]app.MetricsRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT f.id, f.release_id, f.created_at, f.stage, f.sla_bucket, f.absent_since, f.stage_stopped_at,
		       (SELECT min(p.established_at) FROM finding_positions p
		         WHERE p.finding_id = f.id AND p.actor_kind = 'human'),
		       (SELECT min(p.established_at) FROM finding_positions p
		         WHERE p.finding_id = f.id AND p.actor_kind = 'human' AND f.absent_since IS NOT NULL
		           AND p.established_at >= f.absent_since)
		FROM findings f ORDER BY f.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.MetricsRow
	for rows.Next() {
		var (
			id, rel, stage, bucket                   string
			created                                  time.Time
			absent, stopped, firstHuman, afterAbsent *time.Time
		)
		if err := rows.Scan(&id, &rel, &created, &stage, &bucket, &absent, &stopped, &firstHuman, &afterAbsent); err != nil {
			return nil, err
		}
		st := domain.Stage(stage)
		open := st != domain.StageResolved && st != domain.StageArchived
		resolved := utcOrZero(stopped)
		if open {
			resolved = time.Time{}
		}
		out = append(out, app.MetricsRow{FindingID: domain.FindingID(id), ReleaseID: rel, Finding: domain.MetricsFinding{
			CreatedAt: created.UTC(), Open: open, Bucket: bucket, FirstHumanAt: utcOrZero(firstHuman),
			AbsentSince: utcOrZero(absent), HumanAfterAbsentAt: utcOrZero(afterAbsent), ResolvedAt: resolved,
		}})
	}
	return out, rows.Err()
}
