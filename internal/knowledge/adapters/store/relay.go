package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// OutboxNote is an un-delivered outbox row handed to the Publisher.
type OutboxNote struct {
	ID          string
	FaultlineID string
	EventType   string
	Payload     []byte
	OccurredAt  time.Time
}

// Publisher delivers an outbox note to the event bus. A logging stand-in is used until
// Event Infrastructure (M5) lands.
type Publisher interface {
	Publish(ctx context.Context, n OutboxNote) error
}

// Relay delivers pending Knowledge outbox notes exactly-once-eventually (BCK-0041): it
// publishes each un-sent note and marks it sent on success, or bumps its attempt count
// on failure so it is retried on the next pass.
type Relay struct {
	pool  *pgxpool.Pool
	pub   Publisher
	batch int
}

// NewRelay builds a Relay delivering up to batch notes per pass.
func NewRelay(pool *pgxpool.Pool, pub Publisher, batch int) *Relay {
	if batch <= 0 {
		batch = 100
	}
	return &Relay{pool: pool, pub: pub, batch: batch}
}

// DeliverPending delivers up to one batch of un-sent notes and returns how many were
// delivered.
func (r *Relay) DeliverPending(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, faultline_id, event_type, payload, occurred_at
		FROM knowledge_outbox WHERE sent_at IS NULL
		ORDER BY occurred_at LIMIT $1`, r.batch)
	if err != nil {
		return 0, err
	}
	var notes []OutboxNote
	for rows.Next() {
		var n OutboxNote
		if err := rows.Scan(&n.ID, &n.FaultlineID, &n.EventType, &n.Payload, &n.OccurredAt); err != nil {
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
		if err := r.pub.Publish(ctx, n); err != nil {
			if _, uerr := r.pool.Exec(ctx, `UPDATE knowledge_outbox SET attempts = attempts + 1 WHERE id = $1`, n.ID); uerr != nil {
				return delivered, uerr
			}
			continue
		}
		if _, err := r.pool.Exec(ctx, `UPDATE knowledge_outbox SET sent_at = now() WHERE id = $1`, n.ID); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}
