package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Re-verdict queries (EDR-VERDICT-01 D6). The stamp comparison IS the queue: a row whose
// verdict_card_version lags its card's version needs re-judging — which covers every
// pre-feature row (stamp 0) and every row whose card learned something since. There is no
// separate list to maintain, so there is nothing that can go stale beside the stamps
// themselves.

// StaleVerdictOccurrences returns up to limit match rows needing re-judgement, ordered by
// release so one sweep batch clusters its bridge-context reads. Implements
// app.StaleOccurrenceSource.
func (s *Store) StaleVerdictOccurrences(ctx context.Context, limit int) ([]app.StaleOccurrence, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT m.release_id, m.faultline_id, f.cve, m.component_purl,
		       m.component_name, m.component_version, m.component_ecosystem, m.component_source,
		       m.verdict_state
		FROM faultline_matches m
		JOIN faultlines f ON f.id = m.faultline_id
		WHERE m.verdict_card_version < f.version
		ORDER BY m.release_id, m.faultline_id, m.component_purl
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.StaleOccurrence
	for rows.Next() {
		var o app.StaleOccurrence
		var fid, state string
		if err := rows.Scan(&o.ReleaseID, &fid, &o.CVE, &o.Component.PURL,
			&o.Component.Name, &o.Component.Version, &o.Component.Ecosystem, &o.Component.Source,
			&state); err != nil {
			return nil, err
		}
		o.FaultlineID = domain.FaultlineID(fid)
		o.Current = domain.VerdictState(state)
		out = append(out, o)
	}
	return out, rows.Err()
}

// EvidenceForRelease resolves a release to its latest correlated evidence id (the KN-RECOR-1
// ledger row). found=false for a release correlation never ran for — a scanner-only release.
// Implements app.ReleaseEvidenceSource.
func (s *Store) EvidenceForRelease(ctx context.Context, releaseID string) (string, bool, error) {
	var evidenceID string
	err := s.pool.QueryRow(ctx,
		`SELECT evidence_id FROM correlated_releases WHERE release_id = $1`, releaseID).Scan(&evidenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return evidenceID, true, nil
}

// MatchComponentsForRelease lists every component recorded on a release's matches — the
// fallback sibling set for a release with no correlated inventory (D2 records every examined
// occurrence, so for a scanner-only release these rows are the report's component set).
// Implements app.ReleaseOccurrenceSource.
func (s *Store) MatchComponentsForRelease(ctx context.Context, releaseID string) ([]app.InventoryComponent, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT component_purl, component_name, component_version, component_ecosystem, component_source
		FROM faultline_matches WHERE release_id = $1`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.InventoryComponent
	for rows.Next() {
		var c app.InventoryComponent
		if err := rows.Scan(&c.PURL, &c.Name, &c.Version, &c.Ecosystem, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
