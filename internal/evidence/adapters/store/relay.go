package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/event"
)

// Publisher delivers a completed-fact Envelope to the event bus. A logging stand-in is
// used until Event Infrastructure (M5) wires the real platform Publisher (EB-04); the
// Envelope is the kernel's stable integration-event contract (D9).
type Publisher interface {
	Publish(ctx context.Context, env event.Envelope) error
}

// Relay delivers unsent outbox rows and marks them sent, giving
// exactly-once-eventually delivery (BCK-0041): every stored evidence is announced
// exactly once, and no announcement exists for un-stored evidence. Each row is read as
// a full kernel Envelope (the row id is the Envelope id).
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

// DeliverPending delivers up to batchSize unsent envelopes (oldest first) and returns
// the number successfully delivered. A publish failure increments the row's attempt
// counter and leaves it unsent for a later retry; it does not abort the batch, so one
// bad envelope cannot block the others. The relay trusts its own outbox, so it scans
// each row straight into an Envelope without re-validation.
func (r *Relay) DeliverPending(ctx context.Context) (int, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, source_context, subject, event_type, schema_ref, correlation_id, payload, occurred_at
		FROM evidence_outbox WHERE sent_at IS NULL ORDER BY occurred_at, id LIMIT $1
	`, r.batchSize)
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
		if err := r.publisher.Publish(ctx, env); err != nil {
			_, _ = r.pool.Exec(ctx, `UPDATE evidence_outbox SET attempts = attempts + 1 WHERE id = $1`, env.ID)
			continue
		}
		if _, err := r.pool.Exec(ctx, `UPDATE evidence_outbox SET sent_at = now() WHERE id = $1`, env.ID); err != nil {
			return delivered, err
		}
		delivered++
	}
	return delivered, nil
}
