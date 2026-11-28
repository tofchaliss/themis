package store

import (
	"context"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// RebuildFacts returns, for every Finding of one Release, the facts the rebuild policy reads
// (EDR-REBUILD-01 D34): stage, the stance in force, the score priority and the SLA read, the
// known-exploited signal, and the live matched components with their claim class and verdict.
// Two queries for the whole Release, never one per Finding. Read-only. Implements
// app.RebuildFactsReader.
func (s *Store) RebuildFacts(ctx context.Context, releaseID string) ([]app.RebuildFindingFacts, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, faultline_id, cve, stage, COALESCE(current_stance, ''),
		       COALESCE(owner_base_score, base_score), owner_base_score IS NOT NULL, signal_kev
		FROM findings WHERE release_id = $1 ORDER BY id`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.RebuildFindingFacts
	index := map[string]int{}
	for rows.Next() {
		var f app.RebuildFindingFacts
		var id, stage, stance string
		if err := rows.Scan(&id, &f.FaultlineID, &f.CVE, &stage, &stance, &f.BaseScore, &f.OwnerSet, &f.KnownExploited); err != nil {
			return nil, err
		}
		f.FindingID, f.Stage, f.Stance = domain.FindingID(id), domain.Stage(stage), domain.Stance(stance)
		index[id] = len(out)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}

	comps, err := s.pool.Query(ctx, `
		SELECT c.finding_id, c.purl, c.name, c.version, c.ecosystem, c.claim_class, c.verdict_state
		FROM finding_components c
		JOIN findings f ON f.id = c.finding_id
		WHERE f.release_id = $1 AND c.retired_at IS NULL
		ORDER BY c.finding_id, c.purl`, releaseID)
	if err != nil {
		return nil, err
	}
	defer comps.Close()
	for comps.Next() {
		var fid string
		var c domain.MatchedComponent
		if err := comps.Scan(&fid, &c.PURL, &c.Name, &c.Version, &c.Ecosystem, &c.ClaimClass, &c.VerdictState); err != nil {
			return nil, err
		}
		if i, ok := index[fid]; ok {
			out[i].Components = append(out[i].Components, c)
		}
	}
	return out, comps.Err()
}
