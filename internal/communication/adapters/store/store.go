// Package store is the Communication context's Postgres persistence adapter: it owns the
// publications / communication_outbox / publishable_positions tables and implements the
// application Repository port as an aggregate-root store. Publication content is immutable;
// only the delivery outcome and the superseded-by link mutate, guarded by optimistic
// concurrency (D9). A terminal audit event is written in the same transaction as the
// aggregate mutation (transactional outbox). jsonb columns receive string(...); the bytea
// payload column receives []byte directly.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// ErrNotFound is returned by GetByID when no Publication exists.
var ErrNotFound = errors.New("communication: publication not found")

// Store is the Communication Publication aggregate repository.
type Store struct {
	pool *pgxpool.Pool
}

// New builds a Store over the given pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const pubColumns = `id, artifact_type, stance, title, summary, rationale, position_version,
	release_id, finding_id, faultline_id, cve, format, audience, channel, payload,
	delivery_status, delivery_attempts, delivery_last_error, delivered_at,
	supersedes_id, superseded_by_id, version, created_at`

// CurrentPublication returns the latest non-superseded Publication for the identity tuple
// (Release, Faultline, artifact-type, audience) — the one a re-publish supersedes (D5).
func (s *Store) CurrentPublication(ctx context.Context, releaseID, faultlineID string, typ domain.ArtifactType, audience string) (domain.Publication, bool, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+pubColumns+`
		FROM publications
		WHERE release_id=$1 AND faultline_id=$2 AND artifact_type=$3 AND audience=$4 AND superseded_by_id=''
		ORDER BY created_at DESC, id DESC LIMIT 1`,
		releaseID, faultlineID, string(typ), audience)
	pub, err := scanPublication(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Publication{}, false, nil
	}
	if err != nil {
		return domain.Publication{}, false, err
	}
	return pub, true, nil
}

// GetByID loads a Publication by its identity.
func (s *Store) GetByID(ctx context.Context, id domain.PublicationID) (domain.Publication, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+pubColumns+` FROM publications WHERE id=$1`, string(id))
	pub, err := scanPublication(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Publication{}, ErrNotFound
	}
	if err != nil {
		return domain.Publication{}, err
	}
	return pub, nil
}

// row abstracts *pgx.Row / pgx.Rows for the shared scanner.
type row interface {
	Scan(dest ...any) error
}

func scanPublication(r row) (domain.Publication, error) {
	var (
		id, artifactType, stance, title, summary, rationale            string
		positionVersion                                                int
		releaseID, findingID, faultlineID, cve, format, audience, chnl string
		payload                                                        []byte
		deliveryStatus, deliveryLastError                              string
		deliveryAttempts                                               int
		deliveredAt                                                    *time.Time
		supersedesID, supersededByID                                   string
		version                                                        int
		createdAt                                                      time.Time
	)
	if err := r.Scan(&id, &artifactType, &stance, &title, &summary, &rationale, &positionVersion,
		&releaseID, &findingID, &faultlineID, &cve, &format, &audience, &chnl, &payload,
		&deliveryStatus, &deliveryAttempts, &deliveryLastError, &deliveredAt,
		&supersedesID, &supersededByID, &version, &createdAt); err != nil {
		return domain.Publication{}, err
	}

	art := domain.Artifact{
		Type: domain.ArtifactType(artifactType), Stance: domain.Stance(stance),
		Title: title, Summary: summary, Rationale: rationale, PositionVersion: positionVersion,
		Lineage: domain.Lineage{ReleaseID: releaseID, FindingID: findingID, FaultlineID: faultlineID, CVE: cve},
	}
	delivery := domain.DeliveryOutcome{
		Status: domain.DeliveryStatus(deliveryStatus), Attempts: deliveryAttempts, LastError: deliveryLastError,
	}
	if deliveredAt != nil {
		delivery.DeliveredAt = *deliveredAt
	}
	return domain.ReconstitutePublication(domain.PublicationID(id), art, format, audience, chnl,
		payload, delivery, domain.PublicationID(supersedesID), domain.PublicationID(supersededByID), version, createdAt), nil
}

// Save records the new Publication, optionally supersedes a prior one (version-guarded), and
// writes the outbox notes — all atomically (D6/D9). A prior-version mismatch (a concurrent
// re-publish superseded it first) returns app.ErrConcurrent.
func (s *Store) Save(ctx context.Context, pub domain.Publication, prior *domain.Publication, priorPrevVersion int, notes []app.OutboxNote) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := insertPublication(ctx, tx, pub); err != nil {
		return err
	}
	if prior != nil {
		ct, err := tx.Exec(ctx,
			`UPDATE publications SET superseded_by_id=$1, version=$2 WHERE id=$3 AND version=$4`,
			string(prior.SupersededBy()), prior.Version(), string(prior.ID()), priorPrevVersion)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return app.ErrConcurrent
		}
	}
	if err := s.saveNotes(ctx, tx, notes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func insertPublication(ctx context.Context, tx pgx.Tx, pub domain.Publication) error {
	art := pub.Artifact()
	l := pub.Lineage()
	d := pub.Delivery()
	var deliveredAt *time.Time
	if !d.DeliveredAt.IsZero() {
		t := d.DeliveredAt
		deliveredAt = &t
	}
	var payload any
	if !pub.PayloadPruned() {
		payload = pub.Payload()
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO publications (`+pubColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
		string(pub.ID()), string(art.Type), string(pub.Stance()), art.Title, art.Summary, art.Rationale, art.PositionVersion,
		l.ReleaseID, l.FindingID, l.FaultlineID, l.CVE, pub.Format(), pub.Audience(), pub.Channel(), payload,
		string(d.Status), d.Attempts, d.LastError, deliveredAt,
		string(pub.Supersedes()), string(pub.SupersededBy()), pub.Version(), pub.CreatedAt())
	return err
}

func (s *Store) saveNotes(ctx context.Context, tx pgx.Tx, notes []app.OutboxNote) error {
	for _, n := range notes {
		payload, err := json.Marshal(n.Event)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO communication_outbox (id, publication_id, event_type, payload, occurred_at)
			VALUES ($1,$2,$3,$4,$5)`,
			uuid.NewString(), publicationIDOf(n.Event), n.EventType, string(payload), n.OccurredAt); err != nil {
			return err
		}
	}
	return nil
}

// publicationIDOf extracts the publication id from a terminal event for the outbox row's
// foreign reference; unknown shapes fall back to empty.
func publicationIDOf(event any) string {
	switch e := event.(type) {
	case domain.PublicationCreated:
		return string(e.PublicationID)
	case domain.PublicationDelivered:
		return string(e.PublicationID)
	case domain.PublicationSuperseded:
		return string(e.PublicationID)
	default:
		return ""
	}
}

// UndeliveredPublications returns Publications awaiting delivery (pending or failed) — the
// durable delivery queue (D6) — up to limit, oldest first.
func (s *Store) UndeliveredPublications(ctx context.Context, limit int) ([]domain.Publication, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pubColumns+`
		FROM publications WHERE delivery_status IN ('pending','failed')
		ORDER BY created_at, id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Publication
	for rows.Next() {
		pub, err := scanPublication(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, rows.Err()
}

// UpdateDelivery persists a delivery-status change (version-guarded) + outbox notes,
// atomically. A version mismatch returns app.ErrConcurrent.
func (s *Store) UpdateDelivery(ctx context.Context, pub domain.Publication, prevVersion int, notes []app.OutboxNote) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	d := pub.Delivery()
	var deliveredAt *time.Time
	if !d.DeliveredAt.IsZero() {
		t := d.DeliveredAt
		deliveredAt = &t
	}
	ct, err := tx.Exec(ctx, `
		UPDATE publications
		SET delivery_status=$1, delivery_attempts=$2, delivery_last_error=$3, delivered_at=$4, version=$5
		WHERE id=$6 AND version=$7`,
		string(d.Status), d.Attempts, d.LastError, deliveredAt, pub.Version(), string(pub.ID()), prevVersion)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return app.ErrConcurrent
	}
	if err := s.saveNotes(ctx, tx, notes); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListByRelease returns all Publications for a Release, newest first (D10).
func (s *Store) ListByRelease(ctx context.Context, releaseID string) ([]domain.Publication, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+pubColumns+`
		FROM publications WHERE release_id=$1 ORDER BY created_at DESC, id DESC`, releaseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.Publication
	for rows.Next() {
		pub, err := scanPublication(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, pub)
	}
	return out, rows.Err()
}

// PublishableQueue returns the analyst worklist projection (D4/D10), most-recent first.
func (s *Store) PublishableQueue(ctx context.Context) ([]app.QueueEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT finding_id, release_id, faultline_id, cve, version, stance, stale
		FROM publishable_positions ORDER BY updated_at DESC, finding_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []app.QueueEntry
	for rows.Next() {
		var e app.QueueEntry
		var stance string
		if err := rows.Scan(&e.FindingID, &e.ReleaseID, &e.FaultlineID, &e.CVE, &e.Version, &stance, &e.Stale); err != nil {
			return nil, err
		}
		e.Stance = domain.Stance(stance)
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkPublishable upserts the publishable-positions worklist projection (D4).
func (s *Store) MarkPublishable(ctx context.Context, e app.QueueEntry) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO publishable_positions (finding_id, release_id, faultline_id, cve, version, stance, stale, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now())
		ON CONFLICT (finding_id) DO UPDATE SET
			release_id=EXCLUDED.release_id, faultline_id=EXCLUDED.faultline_id, cve=EXCLUDED.cve,
			version=EXCLUDED.version, stance=EXCLUDED.stance, stale=EXCLUDED.stale, updated_at=now()`,
		e.FindingID, e.ReleaseID, e.FaultlineID, e.CVE, e.Version, string(e.Stance), e.Stale)
	return err
}

// PrunePayloads drops the rendered payload bytes of delivered Publications recorded before
// the cutoff (the retention cap — D1); the metadata is kept and the payload stays
// regenerable. Returns how many were pruned.
func (s *Store) PrunePayloads(ctx context.Context, before time.Time) (int, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE publications SET payload = NULL, version = version + 1
		WHERE delivery_status = 'delivered' AND payload IS NOT NULL AND created_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return int(ct.RowsAffected()), nil
}

// Purge removes all Communication rows (dev/test only).
func (s *Store) Purge(ctx context.Context) error {
	_, err := s.pool.Exec(ctx,
		`TRUNCATE publishable_positions, communication_outbox, publications RESTART IDENTITY CASCADE`)
	return err
}
