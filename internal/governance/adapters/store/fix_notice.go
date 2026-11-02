package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The fix-notice store (EDR-INCIDENT-01 D1): the per-occurrence "fix published" facts Knowledge
// announced, and the once-per-release announcement that sends them on.

var _ app.FixNoticeStore = (*Store)(nil)

// RecordFixNotices stores the notices inside the inbox transaction when one rides the context;
// an already recorded (release, faultline, purl, fix) is left as it is.
func (s *Store) RecordFixNotices(ctx context.Context, notices []app.FixNotice) error {
	ex := s.exec(ctx)
	for _, n := range notices {
		advisories := n.Advisories
		if advisories == nil {
			advisories = []string{}
		}
		if _, err := ex.Exec(ctx, `
			INSERT INTO fix_notices (release_id, faultline_id, purl, fix, cve, package, ecosystem, advisories, learned_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT (release_id, faultline_id, purl, fix) DO NOTHING`,
			n.ReleaseID, n.FaultlineID, n.PURL, n.Fix, n.CVE, n.Package, n.Ecosystem, advisories, n.LearnedAt.UTC()); err != nil {
			return err
		}
	}
	return nil
}

// PendingFixNotices lists the unannounced notices, oldest first, with the Finding of
// (release, faultline) joined when Governance has one. A notice whose Finding rests on a
// not_affected Position is excluded: a fix for a flaw the release does not have is not news.
func (s *Store) PendingFixNotices(ctx context.Context, limit int) ([]app.FixNotice, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT n.release_id, n.faultline_id, n.purl, n.fix, n.cve, n.package, n.ecosystem, n.advisories, n.learned_at,
		       COALESCE(f.id, '')
		FROM fix_notices n
		LEFT JOIN findings f ON f.release_id = n.release_id AND f.faultline_id = n.faultline_id
		WHERE n.announced_at IS NULL
		  AND (f.current_stance IS NULL OR f.current_stance <> 'not_affected')
		ORDER BY n.learned_at, n.release_id, n.cve, n.package, n.fix
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []app.FixNotice
	for rows.Next() {
		var n app.FixNotice
		var fid string
		if err := rows.Scan(&n.ReleaseID, &n.FaultlineID, &n.PURL, &n.Fix, &n.CVE, &n.Package, &n.Ecosystem, &n.Advisories, &n.LearnedAt, &fid); err != nil {
			return nil, err
		}
		n.LearnedAt = n.LearnedAt.UTC()
		n.FindingID = domain.FindingID(fid)
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkFixNoticesAnnounced writes the announcement's outbox note (subject: the release) and marks
// the listed notices announced with its id, in one transaction.
func (s *Store) MarkFixNoticesAnnounced(ctx context.Context, releaseID string, notices []app.FixNotice, note app.OutboxNote) error {
	payload, err := json.Marshal(note.Event)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	announcement := uuid.NewString()
	for _, n := range notices {
		if _, err := tx.Exec(ctx, `
			UPDATE fix_notices SET announced_at = $5, announcement = $6
			WHERE release_id = $1 AND faultline_id = $2 AND purl = $3 AND fix = $4 AND announced_at IS NULL`,
			n.ReleaseID, n.FaultlineID, n.PURL, n.Fix, note.OccurredAt.UTC(), announcement); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO governance_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		announcement, sourceContext, releaseID, note.EventType, schemaRefFor(note.EventType), releaseID, string(payload), note.OccurredAt.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
