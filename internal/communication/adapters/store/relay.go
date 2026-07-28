package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
)

// Publisher delivers a terminal audit-event Envelope to the event bus / audit sink. A
// logging stand-in is used until Event Infrastructure (M5) wires the real platform
// Publisher (EB-04); the Envelope is the kernel's stable integration-event contract (D9).
type Publisher interface {
	Publish(ctx context.Context, env event.Envelope) error
}

// Relay delivers pending Communication terminal audit events exactly-once-eventually
// (BCK-0041 / D8): it publishes each un-sent note and marks it sent on success, or bumps its
// attempt count on failure so it is retried on the next pass. These events are terminal —
// consumed only by audit / metrics, never fed upstream (D8).
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
		SELECT id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at
		FROM communication_outbox WHERE sent_at IS NULL
		ORDER BY occurred_at LIMIT $1`, r.batch)
	if err != nil {
		return 0, err
	}
	var envs []event.Envelope
	for rows.Next() {
		var e event.Envelope
		if err := rows.Scan(&e.ID, &e.SourceContext, &e.Subject, &e.Type, &e.SchemaRef, &e.CorrelationID, &e.Payload, &e.OccurredAt); err != nil {
			rows.Close()
			return 0, err
		}
		envs = append(envs, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	delivered := 0
	for _, env := range envs {
		if err := r.pub.Publish(ctx, env); err != nil {
			if _, uerr := r.pool.Exec(ctx, `UPDATE communication_outbox SET attempts = attempts + 1 WHERE id = $1`, env.ID); uerr != nil {
				return delivered, uerr
			}
			continue
		}
		if _, err := r.pool.Exec(ctx, `UPDATE communication_outbox SET sent_at = now() WHERE id = $1`, env.ID); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}
