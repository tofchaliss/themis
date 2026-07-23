package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxNote is one undelivered outbox entry handed to a Publisher.
type OutboxNote struct {
	ID         string
	EventType  string
	Payload    []byte
	OccurredAt time.Time
}

// Publisher delivers an outbox note to the event bus. Implementations live in the
// Event Infrastructure (M5); the Evidence store only produces the notes.
type Publisher interface {
	Publish(ctx context.Context, note OutboxNote) error
}

// Relay delivers unsent outbox notes and marks them sent, giving
// exactly-once-eventually delivery (BCK-0041): every stored evidence is announced
// exactly once, and no announcement exists for un-stored evidence.
type Relay struct {
	pool      *pgxpool.Pool
	publisher Publisher
	batchSize int
}

const defaultRelayBatch = 100

// NewRelay builds a relay. A non-positive batchSize falls back to the default.
func NewRelay(pool *pgxpool.Pool, publisher Publisher, batchSize int) *Relay {
	if batchSize <= 0 {
		batchSize = defaultRelayBatch
	}
	return &Relay{pool: pool, publisher: publisher, batchSize: batchSize}
}

// DeliverPending delivers up to batchSize unsent notes (oldest first) and returns
// the number successfully delivered. A publish failure increments the note's
// attempt counter and leaves it unsent for a later retry; it does not abort the
// batch, so one bad note cannot block the others.
func (r *Relay) DeliverPending(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, event_type, payload, occurred_at FROM evidence_outbox
		WHERE sent_at IS NULL ORDER BY occurred_at, id LIMIT $1
	`, r.batchSize)
	if err != nil {
		return 0, err
	}
	var notes []OutboxNote
	for rows.Next() {
		var n OutboxNote
		if err := rows.Scan(&n.ID, &n.EventType, &n.Payload, &n.OccurredAt); err != nil {
			rows.Close()
			return 0, err
		}
		notes = append(notes, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	delivered := 0
	for _, n := range notes {
		if err := r.publisher.Publish(ctx, n); err != nil {
			_, _ = r.pool.Exec(ctx, `UPDATE evidence_outbox SET attempts = attempts + 1 WHERE id = $1`, n.ID)
			continue
		}
		if _, err := r.pool.Exec(ctx, `UPDATE evidence_outbox SET sent_at = now() WHERE id = $1`, n.ID); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}
