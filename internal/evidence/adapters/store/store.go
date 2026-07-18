// Package store is the Evidence context's PostgreSQL persistence: the aggregate-root
// repository plus the transactional-outbox relay. It owns the Evidence tables
// (Book III §3.5) and is the only place SQL for this context lives.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

const eventTypeEvidenceRegistered = "EvidenceRegistered"

// ErrNotFound indicates no Evidence exists for the requested id.
var ErrNotFound = errors.New("evidence: not found")

// Store is the Evidence aggregate-root repository over PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given connection pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// SaveResult reports the outcome of Save.
type SaveResult struct {
	ID      domain.EvidenceID
	Created bool // false when a byte-identical record already existed (dedup, D3)
}

// Save persists an Evidence aggregate and, atomically in the same transaction, its
// EvidenceRegistered outbox note (BCK-0041). It is idempotent by content
// fingerprint (D3): a byte-identical record already present is not re-inserted and
// no new event is emitted — its existing id is returned with Created=false.
func (s *Store) Save(ctx context.Context, e domain.Evidence, raw []byte, event domain.EvidenceRegistered) (SaveResult, error) {
	inv, err := marshalInventory(e.Inventory())
	if err != nil {
		return SaveResult{}, err
	}
	payload, err := json.Marshal(newEventPayload(event))
	if err != nil {
		return SaveResult{}, err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return SaveResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var insertedID string
	err = tx.QueryRow(ctx, `
		INSERT INTO evidence (id, kind, fingerprint, subject_release_id, provenance_source,
			provenance_image_digest, trust_status, raw_document, canonical_inventory, filed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (fingerprint) DO NOTHING
		RETURNING id
	`, string(e.ID()), string(e.Kind()), e.Fingerprint().String(), e.Subject().ReleaseID,
		e.Provenance().Source, e.Provenance().ImageDigest, string(e.Trust()), raw, string(inv), e.FiledAt(),
	).Scan(&insertedID)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Dedup: a byte-identical record already exists — return its id, no event.
		var existingID string
		if err := tx.QueryRow(ctx, `SELECT id FROM evidence WHERE fingerprint = $1`, e.Fingerprint().String()).Scan(&existingID); err != nil {
			return SaveResult{}, fmt.Errorf("evidence: resolve dedup id: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return SaveResult{}, err
		}
		return SaveResult{ID: domain.EvidenceID(existingID), Created: false}, nil
	case err != nil:
		return SaveResult{}, fmt.Errorf("evidence: insert: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO evidence_outbox (id, evidence_id, event_type, payload, occurred_at)
		VALUES ($1,$2,$3,$4,$5)
	`, uuid.NewString(), insertedID, eventTypeEvidenceRegistered, string(payload), event.OccurredAt); err != nil {
		return SaveResult{}, fmt.Errorf("evidence: outbox insert: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return SaveResult{}, err
	}
	return SaveResult{ID: domain.EvidenceID(insertedID), Created: true}, nil
}

// GetByID loads the whole Evidence aggregate by its id.
func (s *Store) GetByID(ctx context.Context, id domain.EvidenceID) (domain.Evidence, error) {
	var (
		kind, fingerprint, releaseID string
		provSource, provDigest, trust string
		invJSON                       []byte
		filedAt                       time.Time
	)
	err := s.pool.QueryRow(ctx, `
		SELECT kind, fingerprint, subject_release_id, provenance_source, provenance_image_digest,
			trust_status, canonical_inventory, filed_at
		FROM evidence WHERE id = $1
	`, string(id)).Scan(&kind, &fingerprint, &releaseID, &provSource, &provDigest, &trust, &invJSON, &filedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Evidence{}, ErrNotFound
	}
	if err != nil {
		return domain.Evidence{}, err
	}
	fp, err := value.ParseContentFingerprint(fingerprint)
	if err != nil {
		return domain.Evidence{}, err
	}
	inv, err := unmarshalInventory(invJSON)
	if err != nil {
		return domain.Evidence{}, err
	}
	return domain.NewEvidence(id, domain.Kind(kind), fp, domain.SubjectRef{ReleaseID: releaseID},
		domain.Provenance{Source: provSource, ImageDigest: provDigest}, domain.TrustStatus(trust), inv, filedAt)
}

// GetInventory returns just the canonical component inventory for an Evidence id —
// the read path downstream contexts use after EvidenceRegistered (D6).
func (s *Store) GetInventory(ctx context.Context, id domain.EvidenceID) (domain.Inventory, error) {
	var invJSON []byte
	err := s.pool.QueryRow(ctx, `SELECT canonical_inventory FROM evidence WHERE id = $1`, string(id)).Scan(&invJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Inventory{}, ErrNotFound
	}
	if err != nil {
		return domain.Inventory{}, err
	}
	return unmarshalInventory(invJSON)
}

// Purge deletes all Evidence and outbox rows. It is a DEV/TEST-ONLY affordance for
// resetting data (EDR-EVIDENCE-01 D8) and must be gated off in production — the
// production Evidence contract has no delete (CON-0007 immutability).
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, "TRUNCATE evidence_outbox, evidence RESTART IDENTITY CASCADE")
	return err
}

// Summary is a list-view row for evidence filed against a release.
type Summary struct {
	ID          domain.EvidenceID
	Kind        domain.Kind
	Fingerprint string
	FiledAt     time.Time
}

// ListByRelease returns evidence summaries for a release, newest first.
func (s *Store) ListByRelease(ctx context.Context, releaseID string) ([]Summary, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, fingerprint, filed_at FROM evidence
		WHERE subject_release_id = $1 ORDER BY filed_at DESC, id
	`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Summary
	for rows.Next() {
		var id, kind string
		var sum Summary
		if err := rows.Scan(&id, &kind, &sum.Fingerprint, &sum.FiledAt); err != nil {
			return nil, err
		}
		sum.ID = domain.EvidenceID(id)
		sum.Kind = domain.Kind(kind)
		out = append(out, sum)
	}
	return out, rows.Err()
}

// --- JSON codecs -----------------------------------------------------------

type eventPayload struct {
	EvidenceID       string    `json:"evidence_id"`
	Kind             string    `json:"kind"`
	SubjectReleaseID string    `json:"subject_release_id"`
	Fingerprint      string    `json:"fingerprint"`
	OccurredAt       time.Time `json:"occurred_at"`
}

func newEventPayload(e domain.EvidenceRegistered) eventPayload {
	return eventPayload{
		EvidenceID:       string(e.EvidenceID),
		Kind:             string(e.Kind),
		SubjectReleaseID: e.SubjectReleaseID,
		Fingerprint:      e.Fingerprint,
		OccurredAt:       e.OccurredAt,
	}
}

type inventoryJSON struct {
	Components   []componentJSON `json:"components"`
	Dependencies []edgeJSON      `json:"dependencies"`
}

type componentJSON struct {
	PURL      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type edgeJSON struct {
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"`
}

func marshalInventory(inv domain.Inventory) ([]byte, error) {
	dto := inventoryJSON{}
	for _, c := range inv.Components() {
		dto.Components = append(dto.Components, componentJSON{PURL: c.PURL.String(), Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem})
	}
	for _, e := range inv.Dependencies() {
		dto.Dependencies = append(dto.Dependencies, edgeJSON{From: e.From.String(), To: e.To.String(), Relationship: e.Relationship})
	}
	return json.Marshal(dto)
}

func unmarshalInventory(data []byte) (domain.Inventory, error) {
	if len(data) == 0 {
		return domain.NewInventory(nil, nil), nil
	}
	var dto inventoryJSON
	if err := json.Unmarshal(data, &dto); err != nil {
		return domain.Inventory{}, fmt.Errorf("inventory: %w", err)
	}
	comps := make([]domain.Component, 0, len(dto.Components))
	for _, c := range dto.Components {
		purl, err := value.NewPURL(c.PURL)
		if err != nil {
			return domain.Inventory{}, fmt.Errorf("inventory component: %w", err)
		}
		comps = append(comps, domain.Component{PURL: purl, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem})
	}
	edges := make([]domain.DependencyEdge, 0, len(dto.Dependencies))
	for _, e := range dto.Dependencies {
		from, err := value.NewPURL(e.From)
		if err != nil {
			return domain.Inventory{}, fmt.Errorf("inventory edge from: %w", err)
		}
		to, err := value.NewPURL(e.To)
		if err != nil {
			return domain.Inventory{}, fmt.Errorf("inventory edge to: %w", err)
		}
		edges = append(edges, domain.DependencyEdge{From: from, To: to, Relationship: e.Relationship})
	}
	return domain.NewInventory(comps, edges), nil
}
