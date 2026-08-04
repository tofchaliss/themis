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

// TextHash returns the stored embed-text hash for a Finding so the population consumer can
// skip re-embedding when the subject text is unchanged. found=false when no row exists.
func (s *Store) TextHash(ctx context.Context, findingID string) (string, bool, error) {
	var h string
	err := s.exec(ctx).QueryRow(ctx,
		`SELECT text_hash FROM position_embeddings WHERE finding_id = $1`, findingID).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return h, true, nil
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
	_, err := s.pool.Exec(ctx, `TRUNCATE processed_events, position_embeddings`)
	return err
}
