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

// sourceContext stamps every outbox row's source_context (M5 EB-02). correlation_id
// defaults to the subject (the faultline) until true upstream propagation is threaded
// with the pipeline wiring (EB-07/08).
const sourceContext = "knowledge"

// schemaRefByEventType pins each published Knowledge event type to its frozen
// integration-contract v1 schema (M5 EB-03 / D9 / BCK-0046). This producer-owned mapping
// is what stamps the outbox row's schema_ref; the checked-in schemas under schemas/ and
// the contract test guard the wire shape so a domain refactor fails the build rather than
// silently breaking a consumer.
var schemaRefByEventType = map[string]string{
	app.EventFaultlineCreated:    "knowledge.faultline_created.v1",
	app.EventFaultlineEnriched:   "knowledge.faultline_enriched.v1",
	app.EventFaultlineMatured:    "knowledge.faultline_matured.v1",
	app.EventFaultlineSuperseded: "knowledge.faultline_superseded.v1",
	app.EventComponentMatched:    "knowledge.component_matched.v1",
}

// schemaRefFor returns the pinned v1 schema_ref for a published event type. An unmapped
// type (a new event added without freezing its contract) falls back to the raw type so
// the outbox write still succeeds; the contract test forbids that gap.
func schemaRefFor(eventType string) string {
	if ref, ok := schemaRefByEventType[eventType]; ok {
		return ref
	}
	return eventType
}

// Store is the Knowledge Faultline aggregate repository.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// rowQuerier is the read subset shared by *pgxpool.Pool and pgx.Tx.
type rowQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// querier returns the ambient inbox transaction when one rides the context, else the pool.
// Reading through the joined tx lets a load see that transaction's own in-flight writes — e.g.
// a Faultline card created for the same CVE earlier in the same correlation batch — so a later
// component reuses it (update path) instead of re-inserting and colliding on faultlines_cve_key.
func (s *Store) querier(ctx context.Context) rowQuerier {
	if tx, ok := txFromCtx(ctx); ok {
		return tx
	}
	return s.pool
}

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
	q := s.querier(ctx)
	query := "SELECT id, cve, stage, version, view FROM faultlines WHERE " + column + " = $1"
	err := q.QueryRow(ctx, query, arg).Scan(&id, &cve, &stage, &version, &viewRaw)
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

	rows, err := q.Query(ctx,
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

	// Join the inbox unit of work when one rides the context (EB-06), so the aggregate
	// write commits atomically with the envelope claim; otherwise own a fresh transaction.
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	now := time.Now().UTC()
	if created {
		// Guard the INSERT with a savepoint: a duplicate-CVE unique violation (a concurrent
		// creator, or one that raced the GetByCVE read) otherwise aborts a joined inbox tx, so
		// no later statement — including the ErrConcurrent retry's reload — can run. Rolling
		// back to the savepoint clears the abort; ErrConcurrent then reloads and folds as an
		// update. (A fresh, self-owned tx would abort too, so the savepoint is needed either way.)
		if _, err := tx.Exec(ctx, "SAVEPOINT faultline_ins"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO faultlines (id, cve, stage, version, view, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$6)`,
			string(f.ID()), f.CVE().String(), string(f.Stage()), f.Version(), string(viewRaw), now); err != nil {
			// A concurrent writer created this CVE first — converge by retrying as an update.
			if isUniqueViolation(err) {
				if _, rbErr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT faultline_ins"); rbErr != nil {
					return rbErr
				}
				return app.ErrConcurrent
			}
			return err
		}
		if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT faultline_ins"); err != nil {
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
			INSERT INTO knowledge_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			uuid.NewString(), sourceContext, string(f.ID()), n.EventType, schemaRefFor(n.EventType), string(f.ID()), string(payload), n.OccurredAt); err != nil {
			return err
		}
	}

	if own {
		return tx.Commit(ctx)
	}
	return nil // the inbox unit of work owns the commit
}

// RecordMatch records a release-component match idempotently (D3). On a new match it
// advances the card to Correlated (monotonic — never regressing a mature/superseded
// card) and queues a ComponentMatched event, all in one transaction. A re-scan of the
// same occurrence records nothing and emits no duplicate.
func (s *Store) RecordMatch(ctx context.Context, m app.Match) (bool, error) {
	// Join the inbox unit of work when one rides the context (EB-06); correlation fans out
	// over an SBOM's components, so every match for one EvidenceRegistered shares one tx.
	tx, own, err := s.beginOrJoin(ctx)
	if err != nil {
		return false, err
	}
	if own {
		defer func() { _ = tx.Rollback(ctx) }()
	}

	ct, err := tx.Exec(ctx, `
		INSERT INTO faultline_matches (release_id, faultline_id, component_purl, matched_at)
		VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
		m.ReleaseID, string(m.FaultlineID), m.Component.PURL, m.OccurredAt)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		if own {
			return false, tx.Commit(ctx) // already matched — idempotent
		}
		return false, nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE faultlines SET stage='correlated', version=version+1, updated_at=now()
		WHERE id=$1 AND stage IN ('created','enriched')`, string(m.FaultlineID)); err != nil {
		return false, err
	}

	event := domain.ComponentMatched{
		FaultlineID: m.FaultlineID, CVE: m.CVE, ReleaseID: m.ReleaseID,
		// Source rides along (AI-GROUND-1): it is already on the inventory component and was
		// being dropped here, which left every downstream consumer unable to tell which of a
		// card's fix versions belongs to this component.
		Components: []domain.MatchedComponent{{
			PURL: m.Component.PURL, Name: m.Component.Name, Version: m.Component.Version,
			Ecosystem: m.Component.Ecosystem, Source: m.Component.Source,
		}},
		Score:      m.Score,
		OccurredAt: m.OccurredAt.UTC(),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO knowledge_outbox (id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.NewString(), sourceContext, string(m.FaultlineID), app.EventComponentMatched, schemaRefFor(app.EventComponentMatched), string(m.FaultlineID), string(payload), m.OccurredAt); err != nil {
		return false, err
	}

	if own {
		return true, tx.Commit(ctx)
	}
	return true, nil // the inbox unit of work owns the commit
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

// CVEsNeedingRefresh returns the carded CVEs a source is due to visit: never-enriched cards
// first, then those whose newest Proposal from that source is older than staleAfter. Capped at
// limit.
//
// Ordering never-enriched first, then oldest-enriched, makes the sweep DETERMINISTIC and fair:
// a large estate drains front-to-back instead of re-rolling the same dice and leaving some cards
// permanently unvisited.
//
// It selects by STALENESS rather than by absence, which is the difference between a sweep that
// is correct on the day it runs and one that stays correct. Upstream data changes — scores get
// revised, severities corrected, CVEs rejected — and an enrich-once queue would report itself
// empty while carrying stale facts and live cards for withdrawn CVEs.
//
// Superseded cards are excluded: the lifecycle is terminal there, so re-fetching them would
// spend requests to learn nothing and would keep a retired card in the rotation forever.
//
// This replaces the watch watermark that used to live here. There is no watermark now, and that
// is the structural point: the QUERY is the state, so there is nothing to advance past unread
// work — the failure mode NVD-WATCH-1 was.
func (s *Store) CVEsNeedingRefresh(ctx context.Context, source string, staleAfter time.Duration, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT f.cve
		  FROM faultlines f
		  LEFT JOIN LATERAL (
		       SELECT max(p.observed_at) AS last_at
		         FROM faultline_proposals p
		        WHERE p.faultline_id = f.id AND p.source = $1
		  ) e ON TRUE
		 WHERE f.stage <> 'superseded'
		   AND (e.last_at IS NULL OR e.last_at < $2)
		 ORDER BY e.last_at ASC NULLS FIRST, f.created_at, f.cve
		 LIMIT $3`, source, time.Now().UTC().Add(-staleAfter), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		out = append(out, cve)
	}
	return out, rows.Err()
}

// KnownCVEs returns the set of canonical CVEs that already have a card — the relevance
// bound for the scheduled watch (D5): the modified-since feed is filtered to these so the
// watch enriches known cards instead of mirroring the whole feed.
func (s *Store) KnownCVEs(ctx context.Context) (map[string]struct{}, error) {
	rows, err := s.pool.Query(ctx, `SELECT cve FROM faultlines`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]struct{}{}
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		set[cve] = struct{}{}
	}
	return set, rows.Err()
}

// Purge removes all Knowledge rows (dev/test only).
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE processed_events, knowledge_watch_state, faultline_matches, knowledge_outbox, faultline_proposals, faultlines RESTART IDENTITY CASCADE`)
	return err
}
