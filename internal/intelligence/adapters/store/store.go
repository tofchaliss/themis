// Package store is the Intelligence context's Postgres persistence adapter: it owns the
// position_embeddings table — the Operational Semantic Index (KS2, Book IV Chapter 8) — and
// the processed_events consumer inbox. This is the AI Gateway's ONLY datastore and it holds
// NO truth: every row is a derived, rebuildable embedding of a past Enterprise Position that
// Governance still owns (D12 / EDR-INTELLIGENCE-01 Rev 4). Vectors are plain float32[]
// serialized little-endian into a BYTEA column — no pgvector extension — because the corpus
// (the enterprise's own <=~50k Positions) is searched by brute-force cosine in-process.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EmbeddingRecord is one row of the Operational Semantic Index: a past Enterprise Position's
// precedent labels (release, component, stance, rationale, source CVE) plus the embedding of
// its subject Finding's text. Score is NOT stored — it is the query-time cosine similarity.
type EmbeddingRecord struct {
	FindingID   string
	FaultlineID string
	ReleaseID   string
	CVE         string
	Component   string
	Stance      string
	Rationale   string
	Model       string
	Vector      []float32
	TextHash    string
}

// Store is the Intelligence Operational Semantic Index repository.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// HasPool reports whether the Store has a live pool. The wiring path constructs a
// pool-less Store to exercise the stateful branch without a database; the boot-time Δ4a
// version seed and capturer must skip it rather than dereference a nil pool.
func (s *Store) HasPool() bool { return s != nil && s.pool != nil }

// Upsert writes (or replaces) the embedding for a Finding's current Enterprise Position,
// keyed by Finding id — a later PositionRevised re-embeds and overwrites the one row. When
// the population consumer's inbox transaction rides the context (A4) the write joins it
// (exactly-once with the envelope claim); otherwise it runs directly on the pool.
func (s *Store) Upsert(ctx context.Context, rec EmbeddingRecord) error {
	if rec.FindingID == "" {
		return errors.New("intelligence store: Upsert requires a FindingID")
	}
	if len(rec.Vector) == 0 {
		return errors.New("intelligence store: Upsert requires a non-empty vector")
	}
	_, err := s.exec(ctx).Exec(ctx, `
		INSERT INTO position_embeddings
		  (finding_id, faultline_id, release_id, cve, component, stance, rationale, model, dim, vector, text_hash, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (finding_id) DO UPDATE SET
		  faultline_id=EXCLUDED.faultline_id, release_id=EXCLUDED.release_id, cve=EXCLUDED.cve,
		  component=EXCLUDED.component, stance=EXCLUDED.stance, rationale=EXCLUDED.rationale,
		  model=EXCLUDED.model, dim=EXCLUDED.dim, vector=EXCLUDED.vector, text_hash=EXCLUDED.text_hash,
		  updated_at=EXCLUDED.updated_at`,
		rec.FindingID, rec.FaultlineID, rec.ReleaseID, rec.CVE, rec.Component, rec.Stance, rec.Rationale,
		rec.Model, len(rec.Vector), encodeVector(rec.Vector), rec.TextHash, time.Now().UTC())
	return err
}

// LoadAll returns every embedding — the in-memory VectorIndex is populated from this on boot
// (A3). Cheap: one sequential scan of a <=~50k-row table.
func (s *Store) LoadAll(ctx context.Context) ([]EmbeddingRecord, error) {
	rows, err := s.exec(ctx).Query(ctx, `
		SELECT finding_id, faultline_id, release_id, cve, component, stance, rationale, model, dim, vector, text_hash
		FROM position_embeddings ORDER BY finding_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []EmbeddingRecord
	for rows.Next() {
		var (
			rec    EmbeddingRecord
			dim    int
			vecRaw []byte
		)
		if err := rows.Scan(&rec.FindingID, &rec.FaultlineID, &rec.ReleaseID, &rec.CVE, &rec.Component,
			&rec.Stance, &rec.Rationale, &rec.Model, &dim, &vecRaw, &rec.TextHash); err != nil {
			return nil, err
		}
		vec, err := decodeVector(vecRaw)
		if err != nil {
			return nil, fmt.Errorf("intelligence store: finding %s: %w", rec.FindingID, err)
		}
		if len(vec) != dim {
			return nil, fmt.Errorf("intelligence store: finding %s: stored dim %d != vector length %d", rec.FindingID, dim, len(vec))
		}
		rec.Vector = vec
		out = append(out, rec)
	}
	return out, rows.Err()
}

// CachedEmbedding returns the stored embed-text hash AND vector for a Finding, so the
// population consumer can skip the embed call when the subject text has not changed.
//
// It returns the vector, not just the hash, because knowing the text is unchanged is only half
// the job: the row still has to be rewritten with the new stance/rationale, and rewriting it
// needs a vector. Fetching the hash alone would prove an embed is unnecessary and then leave no
// way to avoid it. found=false when no row exists (the first Position for a Finding).
func (s *Store) CachedEmbedding(ctx context.Context, findingID string) (hash string, vector []float32, found bool, err error) {
	var (
		h      string
		vecRaw []byte
	)
	err = s.exec(ctx).QueryRow(ctx,
		`SELECT text_hash, vector FROM position_embeddings WHERE finding_id = $1`, findingID).
		Scan(&h, &vecRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, false, nil
	}
	if err != nil {
		return "", nil, false, err
	}
	vec, derr := decodeVector(vecRaw)
	if derr != nil {
		// A corrupt stored vector must not stall the consumer: report not-found so the caller
		// re-embeds and overwrites the bad row, rather than retrying a poison record forever.
		return "", nil, false, nil
	}
	return h, vec, true, nil
}

// IndexedFinding is the identity of one already-indexed Finding — enough to rebuild its
// embedding without asking any other context which Findings a Faultline touches.
type IndexedFinding struct {
	FindingID   string
	FaultlineID string
	ReleaseID   string
	CVE         string
	Stance      string
}

// IndexedForFaultline lists the Findings already indexed for a Faultline, so a change to that
// Faultline's severity can re-embed exactly the rows whose subject text it feeds.
//
// It queries Intelligence's OWN index rather than asking Governance which Findings reference
// the Faultline. That is the point: the index is derived and rebuildable, so the set that needs
// refreshing is by definition the set already in it. Asking another context would add a read
// dependency to answer a question this store already knows the answer to.
func (s *Store) IndexedForFaultline(ctx context.Context, faultlineID string) ([]IndexedFinding, error) {
	rows, err := s.exec(ctx).Query(ctx,
		`SELECT finding_id, faultline_id, release_id, cve, stance
		   FROM position_embeddings WHERE faultline_id = $1 ORDER BY finding_id`, faultlineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IndexedFinding
	for rows.Next() {
		var f IndexedFinding
		if err := rows.Scan(&f.FindingID, &f.FaultlineID, &f.ReleaseID, &f.CVE, &f.Stance); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// Count returns the number of indexed embeddings (dev / test / telemetry).
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.exec(ctx).QueryRow(ctx, `SELECT count(*) FROM position_embeddings`).Scan(&n)
	return n, err
}

// Purge removes all Intelligence rows — a full rebuild after a model change, and test
// cleanup. The index is derived, so a rebuild replays the bus / re-reads the read-APIs (D12).
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `TRUNCATE processed_events, position_embeddings, invocation_log, golden_entries, eval_reports, prompt_versions, autonomous_proposals`)
	return err
}
