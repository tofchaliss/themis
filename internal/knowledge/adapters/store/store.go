// Package store is the Knowledge context's Postgres persistence adapter: it owns the
// faultlines / faultline_proposals / knowledge_outbox tables and implements the
// application Repository port as an aggregate-root store with optimistic concurrency
// and a transactional outbox (D9). jsonb columns receive string(...) because pgx
// encodes []byte as bytea.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// ErrNotFound is returned by GetByID when no card exists.
var ErrNotFound = errors.New("knowledge: faultline not found")

// Store is the Knowledge Faultline aggregate repository.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// GetByCVE loads the card for a canonical CVE; found=false if none exists.
func (s *Store) GetByCVE(ctx context.Context, cve string) (domain.Faultline, bool, error) {
	f, err := s.load(ctx, "cve", cve)
	if errors.Is(err, ErrNotFound) {
		return domain.Faultline{}, false, nil
	}
	if err != nil {
		return domain.Faultline{}, false, err
	}
	return f, true, nil
}

// GetByID loads the card by its own identity.
func (s *Store) GetByID(ctx context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	return s.load(ctx, "id", string(id))
}

func (s *Store) load(ctx context.Context, column, arg string) (domain.Faultline, error) {
	var (
		id, cve, stage string
		version        int
		viewRaw        []byte
	)
	query := "SELECT id, cve, stage, version, view FROM faultlines WHERE " + column + " = $1"
	err := s.pool.QueryRow(ctx, query, arg).Scan(&id, &cve, &stage, &version, &viewRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Faultline{}, ErrNotFound
	}
	if err != nil {
		return domain.Faultline{}, err
	}

	cveID, err := value.NewCVEID(cve)
	if err != nil {
		return domain.Faultline{}, err
	}
	view, err := unmarshalView(viewRaw)
	if err != nil {
		return domain.Faultline{}, err
	}

	rows, err := s.pool.Query(ctx,
		`SELECT source, observed_at, kind, payload FROM faultline_proposals WHERE faultline_id = $1 ORDER BY seq`, id)
	if err != nil {
		return domain.Faultline{}, err
	}
	defer rows.Close()

	var proposals []domain.Proposal
	for rows.Next() {
		var source, kind string
		var observedAt time.Time
		var payload []byte
		if err := rows.Scan(&source, &observedAt, &kind, &payload); err != nil {
			return domain.Faultline{}, err
		}
		p, err := unmarshalProposal(source, observedAt, kind, payload)
		if err != nil {
			return domain.Faultline{}, err
		}
		proposals = append(proposals, p)
	}
	if err := rows.Err(); err != nil {
		return domain.Faultline{}, err
	}

	return domain.Reconstitute(domain.FaultlineID(id), cveID, proposals, view, domain.Stage(stage), version), nil
}

// Save persists the aggregate + outbox notes atomically. A new card is inserted; an
// existing card is updated under optimistic concurrency (WHERE version=prevVersion),
// returning app.ErrConcurrent on a mismatch. Newly-appended proposals are inserted by
// sequence with ON CONFLICT DO NOTHING, so a retry re-persists only the new tail.
func (s *Store) Save(ctx context.Context, f domain.Faultline, created bool, prevVersion int, notes []app.OutboxNote) error {
	viewRaw, err := marshalView(f.View())
	if err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := time.Now().UTC()
	if created {
		if _, err := tx.Exec(ctx, `
			INSERT INTO faultlines (id, cve, stage, version, view, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$6)`,
			string(f.ID()), f.CVE().String(), string(f.Stage()), f.Version(), string(viewRaw), now); err != nil {
			// A concurrent writer created this CVE first — converge by retrying as an update.
			if isUniqueViolation(err) {
				return app.ErrConcurrent
			}
			return err
		}
	} else {
		ct, err := tx.Exec(ctx, `
			UPDATE faultlines SET stage=$1, version=$2, view=$3, updated_at=$4
			WHERE id=$5 AND version=$6`,
			string(f.Stage()), f.Version(), string(viewRaw), now, string(f.ID()), prevVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return app.ErrConcurrent
		}
	}

	for seq, p := range f.Proposals() {
		payload, err := marshalProposalPayload(p)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO faultline_proposals (faultline_id, seq, source, observed_at, kind, payload)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (faultline_id, seq) DO NOTHING`,
			string(f.ID()), seq, p.Source(), p.ObservedAt(), string(p.Kind()), string(payload)); err != nil {
			return err
		}
	}

	for _, n := range notes {
		payload, err := json.Marshal(n.Event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO knowledge_outbox (id, faultline_id, event_type, payload, occurred_at)
			VALUES ($1,$2,$3,$4,$5)`,
			uuid.NewString(), string(f.ID()), n.EventType, string(payload), n.OccurredAt); err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

// RecordMatch records a release-component match idempotently (D3). On a new match it
// advances the card to Correlated (monotonic — never regressing a mature/superseded
// card) and queues a ComponentMatched event, all in one transaction. A re-scan of the
// same occurrence records nothing and emits no duplicate.
func (s *Store) RecordMatch(ctx context.Context, m app.Match) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ct, err := tx.Exec(ctx, `
		INSERT INTO faultline_matches (release_id, faultline_id, component_purl, matched_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		m.ReleaseID, string(m.FaultlineID), m.Component.PURL, m.OccurredAt)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		return false, tx.Commit(ctx) // already matched — idempotent
	}

	if _, err := tx.Exec(ctx, `
		UPDATE faultlines SET stage='correlated', version=version+1, updated_at=now()
		WHERE id=$1 AND stage IN ('created','enriched')`, string(m.FaultlineID)); err != nil {
		return false, err
	}

	event := domain.ComponentMatched{
		FaultlineID: m.FaultlineID, CVE: m.CVE, ReleaseID: m.ReleaseID,
		Components: []domain.MatchedComponent{{PURL: m.Component.PURL, Name: m.Component.Name, Version: m.Component.Version, Ecosystem: m.Component.Ecosystem}},
		OccurredAt: m.OccurredAt.UTC(),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO knowledge_outbox (id, faultline_id, event_type, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5)`,
		uuid.NewString(), string(m.FaultlineID), app.EventComponentMatched, string(payload), m.OccurredAt); err != nil {
		return false, err
	}

	return true, tx.Commit(ctx)
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation
// (SQLSTATE 23505) — e.g. two writers creating the same CVE at once.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// AffectedReleases returns the releases affected by a card — the projection over the
// faultline_matches rows (D10).
func (s *Store) AffectedReleases(ctx context.Context, faultlineID string) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT release_id FROM faultline_matches WHERE faultline_id = $1 ORDER BY release_id`, faultlineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var rel string
		if err := rows.Scan(&rel); err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, rows.Err()
}

// ReconcileStuckStages advances any card that has matches but never reached the
// Correlated stage — state-based recovery from persisted authoritative state (D11), no
// workflow replay. It returns how many cards it fixed.
func (s *Store) ReconcileStuckStages(ctx context.Context) (int, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE faultlines SET stage='correlated', version=version+1, updated_at=now()
		WHERE stage IN ('created','enriched')
		  AND EXISTS (SELECT 1 FROM faultline_matches m WHERE m.faultline_id = faultlines.id)`)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// LastSuccess returns the scheduled-watch watermark, or the zero time if the watch has
// never completed a pass (D5/D11).
func (s *Store) LastSuccess(ctx context.Context) (time.Time, error) {
	var t time.Time
	err := s.pool.QueryRow(ctx, `SELECT last_success FROM knowledge_watch_state WHERE id = 1`).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, nil
	}
	return t, err
}

// SetLastSuccess advances the scheduled-watch watermark.
func (s *Store) SetLastSuccess(ctx context.Context, t time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO knowledge_watch_state (id, last_success) VALUES (1, $1)
		ON CONFLICT (id) DO UPDATE SET last_success = EXCLUDED.last_success`, t)
	return err
}

// Purge removes all Knowledge rows (dev/test only).
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE knowledge_watch_state, faultline_matches, knowledge_outbox, faultline_proposals, faultlines RESTART IDENTITY CASCADE`)
	return err
}
